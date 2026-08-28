#!/usr/bin/env python3
"""Build per-platform nodary wheels around prebuilt Go binaries.

Every channel ships the same binary; the wheel is a delivery mechanism, not a
different build (docs/adr/0004-release-artifacts-and-channels.md). A wheel is a
zip with a prescribed layout, so it is written directly here rather than
through a build backend — there is no Python source to compile and no
dependency worth adding to do it.

    python3 packaging/pypi/build_wheels.py --version 0.0.1 --dist dist/

`--dist` holds binaries named `nodary-<version>-<os>-<arch>`, which is what
goreleaser produces.

Platform tags matter: they are what makes `pip install nodary` say "no matching
distribution" on an unsupported platform instead of installing something that
cannot run.
"""

from __future__ import annotations

import argparse
import base64
import csv
import hashlib
import io
import pathlib
import sys
import zipfile

# (goos, goarch) -> wheel platform tags.
#
# A CGO-free Go binary runs against both glibc and musl, so each Linux target
# gets both tags. Without the musllinux wheel, Alpine users fall through to an
# sdist that does not exist and get a confusing build error.
PLATFORM_TAGS: dict[tuple[str, str], list[str]] = {
    ("linux", "amd64"): ["manylinux2014_x86_64", "musllinux_1_2_x86_64"],
    ("linux", "arm64"): ["manylinux2014_aarch64", "musllinux_1_2_aarch64"],
    ("darwin", "amd64"): ["macosx_10_12_x86_64"],
    ("darwin", "arm64"): ["macosx_11_0_arm64"],
}

SUMMARY = "Accountable GPU inference: one control plane, audited operations."

DESCRIPTION = """\
# nodary

nodary manages LLM serving across independently controlled machines from one
central control point, with controls and logging over users, usage and models.

This package ships the prebuilt `nodary` binary for your platform. It is the
same artifact served by <https://nodary.net/install.sh>; only the delivery
differs.

```sh
pip install nodary
nodary version
nodary server install      # control plane (Linux, systemd)
nodary node install …      # GPU node   (Linux, systemd)
```

The server and agent require Linux with systemd. macOS wheels provide the
operator CLI.

Documentation: <https://github.com/nodary/nodary>
"""

# `python -m nodary`. The console script is the binary itself, so this exists
# only for the module-invocation path.
DUNDER_MAIN = '''\
"""Run the bundled nodary binary."""

import os
import sys

from . import binary_path


def main() -> "int":
    exe = binary_path()
    if exe is None:
        sys.stderr.write(
            "nodary: the platform binary is missing from this installation.\\n"
            "Reinstall with `pip install --force-reinstall nodary`.\\n"
        )
        return 1
    os.execv(exe, [exe, *sys.argv[1:]])


if __name__ == "__main__":
    raise SystemExit(main())
'''

INIT = '''\
"""nodary — accountable GPU inference.

This package is a thin wrapper around a prebuilt binary. The console script
installed as `nodary` is that binary directly, with no Python in the path at
run time.
"""

import os
import sysconfig

__version__ = "{version}"

__all__ = ["binary_path", "__version__"]


def binary_path() -> "str | None":
    """Absolute path to the installed nodary binary, or None if absent."""
    name = "nodary.exe" if os.name == "nt" else "nodary"
    for key in ("scripts", "purelib"):
        base = sysconfig.get_path(key)
        if not base:
            continue
        candidate = os.path.join(base, name)
        if os.path.isfile(candidate):
            return candidate
    return None
'''


def urlsafe_b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


class Wheel:
    """Accumulates files and writes a valid wheel with its RECORD."""

    def __init__(self, path: pathlib.Path, distinfo: str):
        self.distinfo = distinfo
        self.records: list[tuple[str, str, int]] = []
        self.zf = zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED)

    def add(self, arcname: str, data: bytes, mode: int = 0o644) -> None:
        # A fixed timestamp keeps wheels byte-reproducible across builds.
        info = zipfile.ZipInfo(arcname, date_time=(1980, 1, 1, 0, 0, 0))
        info.external_attr = (mode | 0o100000) << 16
        info.compress_type = zipfile.ZIP_DEFLATED
        self.zf.writestr(info, data)
        digest = urlsafe_b64(hashlib.sha256(data).digest())
        self.records.append((arcname, f"sha256={digest}", len(data)))

    def close(self) -> None:
        record_name = f"{self.distinfo}/RECORD"
        buf = io.StringIO()
        writer = csv.writer(buf, lineterminator="\n")
        for row in self.records:
            writer.writerow(row)
        writer.writerow([record_name, "", ""])
        info = zipfile.ZipInfo(record_name, date_time=(1980, 1, 1, 0, 0, 0))
        info.external_attr = (0o644 | 0o100000) << 16
        self.zf.writestr(info, buf.getvalue())
        self.zf.close()


def build_wheel(version: str, binary: pathlib.Path, tag: str, outdir: pathlib.Path) -> pathlib.Path:
    distinfo = f"nodary-{version}.dist-info"
    datadir = f"nodary-{version}.data"
    filename = f"nodary-{version}-py3-none-{tag}.whl"
    out = outdir / filename

    w = Wheel(out, distinfo)

    w.add("nodary/__init__.py", INIT.format(version=version).encode())
    w.add("nodary/__main__.py", DUNDER_MAIN.encode())

    # Installing the binary as a script puts it straight on PATH with the
    # executable bit set, so `nodary` runs with no Python indirection.
    w.add(f"{datadir}/scripts/nodary", binary.read_bytes(), mode=0o755)

    w.add(f"{distinfo}/WHEEL", (
        "Wheel-Version: 1.0\n"
        "Generator: nodary-build-wheels\n"
        "Root-Is-Purelib: false\n"
        f"Tag: py3-none-{tag}\n"
    ).encode())

    w.add(f"{distinfo}/METADATA", (
        "Metadata-Version: 2.1\n"
        "Name: nodary\n"
        f"Version: {version}\n"
        f"Summary: {SUMMARY}\n"
        "Author: nodary contributors\n"
        "License: Apache-2.0\n"
        "Project-URL: Homepage, https://github.com/nodary/nodary\n"
        "Project-URL: Source, https://github.com/nodary/nodary\n"
        "Classifier: License :: OSI Approved :: Apache Software License\n"
        "Classifier: Operating System :: POSIX :: Linux\n"
        "Classifier: Operating System :: MacOS\n"
        "Classifier: Programming Language :: Go\n"
        "Classifier: Topic :: System :: Systems Administration\n"
        "Requires-Python: >=3.8\n"
        "Description-Content-Type: text/markdown\n"
        "\n"
        f"{DESCRIPTION}"
    ).encode())

    # No entry_points: the console script is the binary itself, installed via
    # the .data/scripts path above. A Python shim in front of it would add
    # interpreter startup to every invocation for nothing.
    w.close()
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--version", required=True)
    ap.add_argument("--dist", default="dist", type=pathlib.Path,
                    help="directory holding nodary-<version>-<os>-<arch> binaries")
    ap.add_argument("--out", default=None, type=pathlib.Path,
                    help="output directory (default: <dist>/wheels)")
    args = ap.parse_args()

    outdir = args.out or (args.dist / "wheels")
    outdir.mkdir(parents=True, exist_ok=True)

    built = 0
    missing = []
    for (goos, goarch), tags in PLATFORM_TAGS.items():
        binary = args.dist / f"nodary-{args.version}-{goos}-{goarch}"
        if not binary.is_file():
            missing.append(binary.name)
            continue
        for tag in tags:
            out = build_wheel(args.version, binary, tag, outdir)
            print(f"  ✔ {out.name}", file=sys.stderr)
            built += 1

    if missing:
        print(f"\nmissing binaries: {', '.join(missing)}", file=sys.stderr)
        return 1
    if not built:
        print("no wheels built", file=sys.stderr)
        return 1

    print(f"\n{built} wheels in {outdir}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
