# ADR 0002 — Go, redistributed through package-manager wrappers

**Status:** Accepted · **Date:** 2026-08-28 · **Amended by**
[ADR 0004](0004-release-artifacts-and-channels.md), which resolves what "bundle" means here:
the shipped artifact is the binary alone, and the heavy components named below are fetched
against an embedded manifest or supplied as a generated offline bundle.

## Context

The primary install path is `curl … | sh` on hosts that may be air-gapped and may have no
usable language runtime. Two questions are entangled: what to write nodary in, and how to
distribute it.

Python is the default choice in this problem domain. It answers the first question well and
the second badly: every Python answer to *"how does this install on a host with no
interpreter"* is a workaround — a vendored runtime, a relocatable build, or a container the
installer must already be able to run. Removing the orchestrator
([ADR 0001](0001-no-orchestrator.md)) also removes the work a dynamic language is best at
here — manifest rendering and driving external CLIs — and leaves state management, an HTTP
surface, and process supervision.

## Decision

**Write nodary in Go as a single static binary. Redistribute that binary through PyPI and npm
wrappers.**

The binary contains server, agent and CLI, selected by subcommand. Cross-compilation covers
`linux/amd64`, `linux/arm64`, `darwin/amd64`, `darwin/arm64`.

Distribution:

| Channel | Mechanism | Prior art |
| :--- | :--- | :--- |
| `curl \| sh` | Signed bundle containing the binary | primary path |
| PyPI | Per-platform wheels carrying the prebuilt binary; entry point `execv`s it | `ruff`, `uv` |
| npm | Per-platform packages under `optionalDependencies` — no `postinstall` fetch | `esbuild` |
| Homebrew | Tap with a bottle per platform | — |

## Rationale

**Single static binary.** No interpreter, no virtualenv, no host runtime to conflict with. The
bundle drops from roughly 80 MB to roughly 20. This is the property that makes appliances of
this shape pleasant to install, and it is the friction the project exists to remove.

**Native to the ecosystem.** containerd, nerdctl, CNI and Prometheus are Go; NVIDIA publishes
official `go-nvml` bindings for GPU inventory and topology. First-party libraries replace
subprocess calls.

**Wrappers make the package names real.** PyPI and npm registrations become genuine install
paths rather than defensive stubs, which is a better reason to hold a name than squatting.

## Consequences

**Lost.** `huggingface_hub`. Resumable weight downloads become nodary's code — a few hundred
lines against HF's HTTP API. Manifest verification and atomic rename were always going to be
ours regardless.

**Cost.** A Go toolchain, and a team that writes Go. This is the only surviving argument
against the decision, and it is about people rather than architecture.

**Reconsider if** the team cannot sustain Go. The fallback is Python with a relocatable
interpreter (`python-build-standalone`) in the bundle, which recovers most of the
single-artifact property at the cost of bundle size and startup time.
