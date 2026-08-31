#!/usr/bin/env python3
"""Assemble the nodary npm packages around prebuilt Go binaries.

Publishing nodary to npm means publishing five packages: the entry package and
one per platform, referenced through optionalDependencies. This is the esbuild
layout, chosen because it needs no postinstall script — nothing downloads at
install time, so an air-gapped or locked-down npm install behaves the same as
any other (docs/adr/0004-release-artifacts-and-channels.md).

    python3 packaging/npm/build_packages.py --version 0.0.1 --dist dist/

Then, in dependency order:

    npm publish dist/npm/nodary-linux-x64      # and the other platforms
    npm publish dist/npm/nodary                # entry package last

The entry package goes last because its optionalDependencies must already
resolve, or the first person to install it gets a broken tree.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import shutil
import sys

REPO = "https://github.com/nodarynet/nodary"

# (goos, goarch) -> (npm platform, npm cpu)
TARGETS = {
    ("linux", "amd64"): ("linux", "x64"),
    ("linux", "arm64"): ("linux", "arm64"),
    ("darwin", "amd64"): ("darwin", "x64"),
    ("darwin", "arm64"): ("darwin", "arm64"),
}

DESCRIPTION = (
    "Accountable GPU inference: one control plane, audited operations."
)


def common(version: str) -> dict:
    return {
        "version": version,
        "license": "Apache-2.0",
        "homepage": REPO,
        "repository": {"type": "git", "url": f"git+{REPO}.git"},
        "engines": {"node": ">=16"},
    }


def platform_package(version: str, binary: pathlib.Path, npm_os: str, npm_cpu: str,
                     outdir: pathlib.Path) -> pathlib.Path:
    name = f"nodary-{npm_os}-{npm_cpu}"
    pkgdir = outdir / name
    (pkgdir / "bin").mkdir(parents=True, exist_ok=True)

    target = pkgdir / "bin" / "nodary"
    shutil.copy2(binary, target)
    target.chmod(0o755)

    manifest = {
        "name": name,
        "description": f"{DESCRIPTION} ({npm_os} {npm_cpu} binary)",
        # `os` and `cpu` are the guard: npm refuses to install this package on
        # a platform it does not match, rather than installing a binary that
        # cannot run.
        "os": [npm_os],
        "cpu": [npm_cpu],
        "files": ["bin/"],
        **common(version),
    }
    (pkgdir / "package.json").write_text(json.dumps(manifest, indent=2) + "\n")
    (pkgdir / "README.md").write_text(
        f"# {name}\n\nPlatform binary for [nodary]({REPO}).\n"
        f"Install `nodary` instead; this package is a dependency of it.\n"
    )
    return pkgdir


def entry_package(version: str, platforms: list[str], outdir: pathlib.Path,
                  shim_src: pathlib.Path) -> pathlib.Path:
    pkgdir = outdir / "nodary"
    (pkgdir / "bin").mkdir(parents=True, exist_ok=True)

    shutil.copy2(shim_src, pkgdir / "bin" / "nodary.js")
    (pkgdir / "bin" / "nodary.js").chmod(0o755)

    manifest = {
        "name": "nodary",
        "description": DESCRIPTION,
        "bin": {"nodary": "bin/nodary.js"},
        "files": ["bin/"],
        "keywords": ["llm", "inference", "gpu", "vllm", "sglang", "control-plane"],
        # optionalDependencies rather than dependencies: npm installs only the
        # one matching this platform and skips the rest without failing.
        "optionalDependencies": {p: version for p in sorted(platforms)},
        **common(version),
    }
    (pkgdir / "package.json").write_text(json.dumps(manifest, indent=2) + "\n")

    (pkgdir / "README.md").write_text(f"""\
# nodary

{DESCRIPTION}

```sh
npm install -g nodary
nodary version
nodary server install      # control plane (Linux, systemd)
nodary node install …      # GPU node   (Linux, systemd)
```

This package ships the prebuilt `nodary` binary for your platform — the same
artifact served by <https://nodary.net/install.sh>. The server and agent require
Linux with systemd; macOS builds provide the operator CLI.

Documentation: <{REPO}>
""")
    return pkgdir


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--version", required=True)
    ap.add_argument("--dist", default="dist", type=pathlib.Path,
                    help="directory holding nodary-<version>-<os>-<arch> binaries")
    ap.add_argument("--out", default=None, type=pathlib.Path)
    args = ap.parse_args()

    here = pathlib.Path(__file__).resolve().parent
    shim = here / "nodary" / "bin" / "nodary.js"
    if not shim.is_file():
        print(f"missing shim: {shim}", file=sys.stderr)
        return 1

    outdir = args.out or (args.dist / "npm")
    if outdir.exists():
        shutil.rmtree(outdir)
    outdir.mkdir(parents=True)

    names, missing = [], []
    for (goos, goarch), (npm_os, npm_cpu) in TARGETS.items():
        binary = args.dist / f"nodary-{args.version}-{goos}-{goarch}"
        if not binary.is_file():
            missing.append(binary.name)
            continue
        pkgdir = platform_package(args.version, binary, npm_os, npm_cpu, outdir)
        names.append(pkgdir.name)
        print(f"  ✔ {pkgdir.name}", file=sys.stderr)

    if missing:
        print(f"\nmissing binaries: {', '.join(missing)}", file=sys.stderr)
        return 1

    entry = entry_package(args.version, names, outdir, shim)
    print(f"  ✔ {entry.name} (optionalDependencies: {', '.join(sorted(names))})",
          file=sys.stderr)

    print(f"\npublish platform packages first, then {entry.name}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
