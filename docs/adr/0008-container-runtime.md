# ADR 0008 — containerd, not podman

**Status:** Accepted · **Date:** 2026-09-07 ·
**Settles the reconsider-if in:** [ADR 0001](0001-no-orchestrator.md)

## Context

[ADR 0001](0001-no-orchestrator.md) chose systemd and containerd, and the component manifest
has pinned `containerd`, `runc`, `cni-plugins` and `nerdctl` since
[R0](../tasks/R0-release.md). [The spike](../spike-fips-and-manifest.md) then found something
that made the choice worth re-opening: docker's isolation primitive silently destroys ingress,
and [03 §5](../specs/03-agent.md#5-egress-isolation)'s warning that `IPAddressDeny=` filters
the launcher rather than the workload is a consequence of containerd's shim parenting the
container elsewhere.

Podman is daemonless. If its container process lands inside the launching unit's cgroup, that
systemd filter would actually enforce, turning 03 §5's "the obvious approach does not work"
into a mechanism rather than a trap. That was worth measuring before
[R4-26](../tasks/R4-agent.md) is built rather than after.

Evaluated on two criteria: **security** and **ease of deployment**.

## Decision

**containerd stays.** The security difference is unproven and, at its best, improves
defence-in-depth rather than the control. The deployment difference is measured and severe.

### Ease of deployment: containerd, and it is not close

**Podman publishes no official static Linux engine binary.** Measured against
`containers/podman` v6.1.1: of nine release assets, the only Linux ones are
`podman-remote-static-linux_{amd64,arm64}.tar.gz` — the *client* that talks to a podman
service, not the engine. Upstream ships source and leaves the engine to distributions.

That is disqualifying for this product specifically, because
[ADR 0004](0004-release-artifacts-and-channels.md) fetches every component by URL and SHA-256
from an upstream release and pins the digest. Adopting podman means one of three things, and
each is worse than the problem it solves:

| | |
| :--- | :--- |
| A third-party rebuild | The best-maintained one is an individual's repository. It would be the container runtime, inside the boundary [ADR 0006](0006-cui-boundary-and-fips.md) exists to defend, pinned to a build nobody in the containers organisation makes |
| Distribution packages | Contradicts `allow.package_install = false` ([12](../specs/12-node-guardrails.md)) and [R5-11](../tasks/R5-install.md)'s record of what nodary placed. Ubuntu 24.04's `podman` has nine `Depends`, five of them shared libraries, plus `uidmap`, `passt` and `slirp4netns` as `Recommends` |
| Build it ourselves | Makes nodary a distributor of a container engine, and every CVE in it ours to rebuild for |

By contrast `containerd`, `nerdctl` and `cni-plugins` publish official static tarballs and
`runc` publishes `runc.amd64` — the four artifacts the manifest already pins, all still
resolving.

**Rootless podman also needs a bootstrap nodary cannot provide.** Measured on this host: with
`/etc/subuid` and `/etc/subgid` ranges present and user namespaces available, podman still
refuses with `command required for rootless mode with multiple IDs: exec: "newuidmap":
executable file not found`. Those are setuid helpers from a distribution package. A node
installer that must ask for a setuid binary from apt before it can start a container is not
the one-command install [01](../specs/01-install.md) promises.

### Security: closer than it looks, and the advantage is not the control

**The load-bearing control is runtime-independent.** [03 §5](../specs/03-agent.md#5-egress-isolation)
is a network namespace with no route off-box, and the spike measured that mechanism working:
no default route, DNS failing, external TCP failing, the bridge gateway unreachable — with a
port published on `127.0.0.1` still serving. Nothing in that depends on which runtime creates
the namespace.

**Podman's advantage was not measured, and is not claimed here.** Whether conmon lands in the
launching system unit's cgroup needs root and a system unit; this evaluation had neither, so
it remains a hypothesis. Said plainly rather than assumed, because assuming is what this
project keeps being wrong about.

Even granting it, what it buys is that `IPAddressDeny=` stops being documented-as-inert and
starts enforcing — an improvement to defence in depth, not to the control. There is also a
second reason it would not enforce that podman cannot fix: a user-session manager is delegated
`cpu memory pids` and no network controller at all, measured, so the filter has nothing to
attach to outside a system unit either way.

**Two things cut the other way.** Rootless podman's networking is `pasta`/`slirp4netns`, a
different isolation model that would need its own `verify-egress` and its own proof — the work
03 §5 already has against a bridge. And rootless depends on setuid helpers, which are attack
surface in exchange for removing a daemon.

GPU access is a wash: both reach it through the NVIDIA toolkit and CDI.

## Consequences

**Gained.** The install path stays four digest-pinned artifacts from the projects that build
them, and 03 §5's mechanism stays the one that was measured working.

**Lost.** `IPAddressDeny=` remains defence in depth that constrains the launcher, and
[R4-28](../tasks/R4-agent.md) keeps documenting it as such. The rootless story stays
unavailable; nodary's agent runs as root on a node it also installs systemd units on, which is
consistent with what it already is.

**Cost.** A daemon to supervise, and the shim parenting that makes the systemd filter useless.
Both were already true.

**Reconsider if** podman ships official static Linux engine binaries, which would remove the
whole of the deployment argument at a stroke — or if the CNI half of `nodary-isolated` proves
as awkward as docker's `--internal` did, in which case measure the cgroup question properly
before deciding, with root and a system unit.
