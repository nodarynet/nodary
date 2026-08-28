# ADR 0004 — Release artifacts and install channels

**Status:** Accepted · **Date:** 2026-08-28

## Context

[ADR 0002](0002-go-with-package-manager-wrappers.md) chose a single static Go binary,
redistributed through `curl … | sh`, PyPI, npm and Homebrew. It left one word ambiguous.

"The bundle" named two objects at once: a ~20 MB artifact in ADR 0002, and in
[01](../specs/01-install.md) a tarball additionally carrying containerd, runc, CNI plugins,
the NVIDIA container toolkit and the Prometheus, Grafana and DCGM container images. Those
differ by two orders of magnitude, and the ambiguity decides real things:

- whether a PyPI wheel can carry the artifact at all — the default per-file limit is 100 MB;
- whether `pip install nodary` is a complete install path or a degraded one;
- what `install.sh` downloads, and what it verifies;
- whether an air-gapped site receives a fixed tarball or composes one for its own hardware.

## Decision

**One shipped artifact: the `nodary` binary. Third-party components are fetched at install
time against a digest-pinned manifest embedded in that binary, or supplied offline as a bundle
nodary generates itself.**

Three objects, named distinctly, never again used interchangeably:

| Object | Contents | Size | Produced by |
| :--- | :--- | :--- | :--- |
| **Binary** | `nodary` — server, agent and CLI | ~20–40 MB | Release build |
| **Component manifest** | Name, version, per-platform URL and SHA-256 for every third-party dependency | Embedded in the binary | Release build |
| **Offline bundle** | Binary plus a chosen subset of components, resolved from the manifest | GB | `nodary bundle create` |

### Channels carry the binary and nothing else

| Channel | Mechanism |
| :--- | :--- |
| `nodary.net/install.sh` | Fetch, verify and place the binary, then `exec` it |
| PyPI | Per-platform wheels; the entry point `execv`s the binary |
| npm | Per-platform packages under `optionalDependencies`, guarded by `os`/`cpu` |
| Homebrew | Tap with a bottle per platform |

Because every channel ships the same object, they converge on the same state. `pip install
nodary && nodary server install` and `curl -fsSL https://nodary.net/install.sh | sh -s --
server` differ only in how the binary arrived.

### Installation is interactive; components come after

`install.sh` obtains the binary and `exec`s `nodary server install` or `nodary node install`,
which reopen `/dev/tty` and prompt for what to install. Every prompt has a flag equivalent, so
nothing is reachable only through an interactive session.

### The control plane is a mirror

`nodary server install` resolves components once into `/var/lib/nodary/dist/` and serves that
cache to nodes. Only the control-plane host contacts an upstream source. This preserves the
property from [01](../specs/01-install.md#3-bootstrap-order) — a GPU host bootstraps with no
internet access and no container-registry access — while reaching it by caching rather than by
shipping everything up front.

### Offline is generated, not shipped

`nodary bundle create` runs on a connected machine and emits a bundle containing exactly the
components that site needs. It resolves against the same embedded manifest the online path
uses, so both verify identically.

## Rationale

**The 100 MB wall is the forcing function.** A wheel cannot carry containerd and three
container images. Either the package-manager channels become degraded stubs — undermining
ADR 0002's argument that wrappers make the package names real — or the heavy components stop
being part of the shipped artifact. The second is better in every other respect too.

**Composed bundles beat shipped ones.** A fixed tarball carries TensorRT-LLM images to a site
running llama.cpp, and is stale the moment any component releases. A bundle generated per site
carries what that site chose, at the versions its binary pins.

**Verification improves.** `install.sh` now signature-checks exactly one file. Everything after
that is fetched and digest-checked by Go code against the embedded manifest, rather than by
shell against a tarball. The trust decision moves out of the least verifiable part of the
system.

## Consequences

**Gained.** One artifact per platform across four channels. A complete `pip install` path. Per-
site offline bundles. A single verification story shared by the online and offline paths.

**Lost.** The one-file install ceases to be literally true for networked installs: the control
plane contacts upstream sources on first install. Air-gapped sites use `bundle create` and are
unaffected.

**Cost.** The component manifest is now a maintained release artifact — every dependency bump
is a digest update, and a stale URL is a broken install. `nodary components verify` exists to
catch that in CI rather than at a customer.

**Reconsider if** upstream component hosting proves unreliable enough that mirroring
everything ourselves is cheaper than pinning it, or if a channel appears that can carry
gigabyte artifacts and becomes the dominant install path.
