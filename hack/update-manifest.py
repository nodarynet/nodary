#!/usr/bin/env python3
"""Regenerate internal/components/components.json from upstream releases.

Digests are never hand-written. This script fetches the checksum files that
upstream projects publish alongside their release assets, and resolves
container images to an index digest through the registry API, so every entry in
the manifest is pinned to something a third party asserted.

    python3 hack/update-manifest.py [--check]

--check exits non-zero if the regenerated manifest differs from the file on
disk, which is what CI runs.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import sys
import urllib.error
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parent.parent
OUT = ROOT / "internal" / "components" / "components.json"

NODARY_VERSION = (ROOT / "VERSION").read_text().strip()
PLATFORMS = ["linux/amd64", "linux/arm64"]
ARCH = {"linux/amd64": "amd64", "linux/arm64": "arm64"}

GH = "https://github.com"


def get(url: str, headers: dict[str, str] | None = None, timeout: int = 30) -> bytes:
    req = urllib.request.Request(url, headers=headers or {})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read()


def latest_tag(repo: str) -> str:
    data = json.loads(get(f"https://api.github.com/repos/{repo}/releases/latest"))
    return data["tag_name"]


def sums(url: str) -> dict[str, str]:
    """Parse a `sha256  filename` checksum file into {filename: digest}."""
    out: dict[str, str] = {}
    for line in get(url).decode().splitlines():
        parts = line.split()
        if len(parts) >= 2 and len(parts[0]) == 64:
            out[parts[-1].lstrip("*")] = parts[0]
    return out


# --- container image digests -------------------------------------------------

REGISTRY_AUTH = {
    "docker.io": ("https://auth.docker.io/token?service=registry.docker.io&scope=repository:{repo}:pull",
                  "https://registry-1.docker.io"),
    "ghcr.io": ("https://ghcr.io/token?scope=repository:{repo}:pull", "https://ghcr.io"),
    "nvcr.io": ("https://nvcr.io/proxy_auth?scope=repository:{repo}:pull", "https://nvcr.io"),
}

ACCEPT = ", ".join([
    "application/vnd.oci.image.index.v1+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.docker.distribution.manifest.v2+json",
])


def image_digest(ref: str) -> tuple[str, list[str]]:
    """Resolve `registry/repo:tag` to (`registry/repo@sha256:...`, platforms).

    The platform list comes from the image index rather than being assumed: a
    manifest that claims linux/arm64 for an amd64-only image installs fine and
    then fails at pull time on the one host that cannot afford a surprise.
    """
    host, _, rest = ref.partition("/")
    if "." not in host:  # bare Docker Hub reference
        host, rest = "docker.io", ref
    repo, _, tag = rest.rpartition(":")
    if host == "docker.io" and "/" not in repo:
        repo = "library/" + repo

    auth_tmpl, base = REGISTRY_AUTH[host]
    token = json.loads(get(auth_tmpl.format(repo=repo)))
    token = token.get("token") or token["access_token"]

    req = urllib.request.Request(
        f"{base}/v2/{repo}/manifests/{tag}",
        headers={"Authorization": f"Bearer {token}", "Accept": ACCEPT},
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        digest = resp.headers["Docker-Content-Digest"]
        body = json.loads(resp.read())

    if not digest:
        raise RuntimeError(f"no digest header for {ref}")

    plats = []
    for m in body.get("manifests", []):
        pl = m.get("platform", {})
        os_, arch = pl.get("os"), pl.get("architecture")
        if os_ == "unknown" or arch == "unknown":
            continue  # attestation manifests, not runnable images
        if os_ and arch:
            key = f"{os_}/{arch}"
            if key in PLATFORMS and key not in plats:
                plats.append(key)
    if not plats:
        # A single (non-index) manifest describes one platform; images built
        # this way are amd64 in practice.
        plats = ["linux/amd64"]

    display = f"{host}/{repo}" if host != "docker.io" else repo
    return f"{display}@{digest}", sorted(plats)


# --- component builders ------------------------------------------------------


def containerd() -> dict:
    tag = latest_tag("containerd/containerd")
    v = tag.lstrip("v")
    plats = {}
    for p in PLATFORMS:
        name = f"containerd-{v}-linux-{ARCH[p]}.tar.gz"
        url = f"{GH}/containerd/containerd/releases/download/{tag}/{name}"
        plats[p] = {"url": url, "sha256": sums(url + ".sha256sum")[name]}
    return {
        "name": "containerd", "version": v, "kind": "archive",
        "roles": ["node"], "group": "runtime", "platforms": plats,
    }


def runc() -> dict:
    tag = latest_tag("opencontainers/runc")
    table = sums(f"{GH}/opencontainers/runc/releases/download/{tag}/runc.sha256sum")
    plats = {}
    for p in PLATFORMS:
        name = f"runc.{ARCH[p]}"
        plats[p] = {
            "url": f"{GH}/opencontainers/runc/releases/download/{tag}/{name}",
            "sha256": table[name],
        }
    return {
        "name": "runc", "version": tag.lstrip("v"), "kind": "binary",
        "roles": ["node"], "group": "runtime", "platforms": plats,
    }


def cni_plugins() -> dict:
    tag = latest_tag("containernetworking/plugins")
    plats = {}
    for p in PLATFORMS:
        name = f"cni-plugins-linux-{ARCH[p]}-{tag}.tgz"
        url = f"{GH}/containernetworking/plugins/releases/download/{tag}/{name}"
        plats[p] = {"url": url, "sha256": sums(url + ".sha256")[name]}
    return {
        "name": "cni-plugins", "version": tag.lstrip("v"), "kind": "archive",
        "roles": ["node"], "group": "runtime",
        "notes": "provides the bridge plugin backing nodary-isolated",
        "platforms": plats,
    }


def nerdctl() -> dict:
    tag = latest_tag("containerd/nerdctl")
    v = tag.lstrip("v")
    table = sums(f"{GH}/containerd/nerdctl/releases/download/{tag}/SHA256SUMS")
    plats = {}
    for p in PLATFORMS:
        name = f"nerdctl-{v}-linux-{ARCH[p]}.tar.gz"
        plats[p] = {
            "url": f"{GH}/containerd/nerdctl/releases/download/{tag}/{name}",
            "sha256": table[name],
        }
    return {
        "name": "nerdctl", "version": v, "kind": "archive",
        "roles": ["node"], "group": "runtime", "platforms": plats,
    }


# Image tags are pinned to concrete versions, never to a moving tag such as
# `latest` or `main-stable`. The digest resolved below is what actually pins the
# artifact, but a moving tag makes the `version` field a lie and makes a manifest
# diff unreadable, which defeats the point of reviewing one.
IMAGES = [
    ("litellm", "ghcr.io/berriai/litellm:v1.98.0", ["server"], "core",
     "OpenAI-compatible data plane; runs stateless (ADR 0003)"),
    ("prometheus", "prom/prometheus:v3.14.0", ["server"], "observability", ""),
    ("grafana", "grafana/grafana:13.1.4", ["server"], "observability", ""),
    ("dcgm-exporter", "nvcr.io/nvidia/k8s/dcgm-exporter:4.4.1-4.5.2-ubuntu22.04",
     ["node"], "observability", "GPU telemetry"),

    # Model-server images. Pinned here so the control plane can mirror them and
    # a node never needs registry access (docs/specs/01-install.md §3). They are
    # selected by `--backends`, not `--components`: which one a site needs
    # depends on the models it enables, and each is several gigabytes.
    ("vllm", "vllm/vllm-openai:v0.28.0", ["node"], "backend",
     "backend descriptor: vllm"),
    ("sglang", "lmsysorg/sglang:v0.5.18", ["node"], "backend",
     "backend descriptor: sglang"),
    ("llama-cpp", "ghcr.io/ggml-org/llama.cpp:server-cuda-b4738", ["node"], "backend",
     "backend descriptor: llama-cpp"),
]


def images() -> list[dict]:
    out = []
    for name, ref, roles, group, notes in IMAGES:
        try:
            pinned, plats = image_digest(ref)
        except Exception as e:  # noqa: BLE001 - report and continue
            print(f"  ! {name}: could not resolve digest ({e})", file=sys.stderr)
            continue
        tag = ref.rpartition(":")[2]
        entry = {
            "name": name, "version": tag, "kind": "image",
            "roles": roles, "group": group,
            "platforms": {p: {"image": pinned} for p in plats},
        }
        if notes:
            entry["notes"] = notes
        out.append(entry)
        print(f"  ✔ {name:16} {','.join(a.split('/')[1] for a in plats):11} {pinned}",
              file=sys.stderr)
    return out


def build() -> dict:
    comps = []
    for fn in (containerd, runc, cni_plugins, nerdctl):
        c = fn()
        print(f"  ✔ {c['name']:16} {c['version']}", file=sys.stderr)
        comps.append(c)
    comps.extend(images())
    comps.sort(key=lambda c: c["name"])
    return {"schema": 1, "nodary_version": NODARY_VERSION, "components": comps}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true",
                    help="fail if the file on disk is out of date")
    args = ap.parse_args()

    print("resolving upstream components:", file=sys.stderr)
    text = json.dumps(build(), indent=2) + "\n"

    if args.check:
        current = OUT.read_text() if OUT.exists() else ""
        if current != text:
            print("components.json is out of date; run hack/update-manifest.py", file=sys.stderr)
            return 1
        print("components.json is up to date", file=sys.stderr)
        return 0

    OUT.write_text(text)
    print(f"wrote {OUT}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
