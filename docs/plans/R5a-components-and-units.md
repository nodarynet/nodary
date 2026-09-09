# R5a — Components, the mirror, and the units

**Slice of:** [R5](../tasks/R5-install.md) ·
**Tasks:** R5-06, R5-07, R5-11 · **Status:** complete

The slice that closes the sentence the README has carried since R4c: *containerd is not
installed, so a unit reaches `start` and fails there*. Everything else in
[S7](mvp.md#4-the-route) — preflight, `doctor`, the setup URL, the FIPS job — is worth having
and unblocks nothing. This is the part that does.

## 1. The mirror is the whole architecture, not an optimization

**Decided.** The control plane resolves components once into `/var/lib/nodary/dist/` and serves
that directory to nodes. A node fetches from its control plane and contacts nothing else.

**Why.** [01 §3](../specs/01-install.md#3-bootstrap-order) states the consequence as the point:
*only the control-plane host ever contacts an upstream source*, and GPU hosts bootstrap with
no internet and no registry access. That is not a convenience — it is the same property
[R4d](R4d-egress-isolation.md) spends its whole effort asserting at runtime, applied to install
time. A node that curls GitHub to install containerd is a node with egress, on the day it is
least supervised.

It also means one digest check protects the fleet: the control plane verifies against the
embedded manifest, and a node verifies against the same manifest again. Neither trusts the
other's word.

**Rejected — each node resolves from upstream, with the manifest as the check.** Simpler, no
mirror to serve, and the digest check still holds. It requires every GPU host to reach GitHub
and a container registry, which is exactly the network position a defense subcontractor's
GPU host is not in, and which the product's own isolation story says it should not be in.

## 2. A fetch verifies before it places, and is idempotent by digest

**Decided.** Every artifact is downloaded to a temporary file in the destination directory,
hashed, and only then renamed into place. An artifact already present whose digest matches is
skipped without a network call.

**Why.** [01 §4](../specs/01-install.md#4-server-install)'s step 3 says "digest-checked against
the embedded manifest. Skip anything already present and correct", and each half is doing work.
Verify-then-rename means a killed install leaves a temporary file rather than a half-written
binary that looks complete — the same rule [05 §3](../specs/05-catalog.md#3-staging) already
applies to weights, and the same reason: a partial artifact that is indistinguishable from a
whole one is how a corrupt install becomes a permanent mystery.

Skipping by digest rather than by presence is what makes the step idempotent in the sense
[01 §4](../specs/01-install.md#4-server-install) means: re-running the install re-verifies
rather than re-downloads, and a tampered cache is caught on the next run rather than trusted
because the file exists.

## 3. Ownership is recorded at install, never inferred at uninstall

**Decided.** `/etc/nodary/components.json` records what nodary placed, where, and with which
digest — written as each artifact lands.

**Why.** R5-11 says so, and its `done:` says why: *ownership is recorded, never inferred*. A
host may already have containerd, installed by the operator, in use by something else. An
uninstall that removed `/usr/local/bin/containerd` because it is in nodary's manifest would
take down whatever else was using it — and it would do so on a machine
[12](../specs/12-node-guardrails.md) opens by pointing out is rarely only a nodary node.

So the record distinguishes *placed by nodary* from *found already present and acceptable*,
and only the first is ever removed.

## 4. What this slice can prove here, and what it cannot

Stated up front. This machine has **no passwordless root**, so nothing here can write to
`/usr/local/bin`, `/etc/systemd/system` or create a system user.

| | |
| :--- | :--- |
| Fetching and digest-verifying the real pinned artifacts | **proved** — real downloads |
| A tampered artifact being refused | **proved** |
| Re-running skipping by digest, and catching a tampered cache | **proved** |
| Extracting the archives and finding the expected binaries | **proved** |
| Recording ownership, and distinguishing placed from found | **proved** |
| The mirror serving a node over mTLS | **proved** |
| Placing binaries in `/usr/local/bin` and units in `/etc/systemd/system` | **not proved** — needs root |

The last row is the one a first install exercises immediately, and it is marked in the tracker
rather than claimed.

## 5. The shape

| | |
| :--- | :--- |
| `internal/components/fetch.go` | Resolve, verify, place; the ownership record |
| `internal/components/archive.go` | Extracting a tarball safely |
| `internal/api/dist.go` | `GET /api/v1/agent/dist/{name}` — the mirror |
| `internal/cli/components.go` | `nodary components fetch` |

## 6. Steps

- [x] Fetch: verify-then-rename, skip by digest, refuse a mismatch
- [x] Extract an archive without letting it escape its directory
- [x] The ownership record, distinguishing placed from found
- [x] The mirror endpoint, behind the same mTLS the agent protocol uses
- [x] `nodary components fetch`, and the node fetching from its control plane

## 7. What was run

Against a real control plane on this machine, not only in tests:

```
nodary components fetch --role node          # 108 MB from upstream, digests verified
nodary components fetch --role node --mirror # the same, through the control plane over mTLS
```

The first resolved containerd, `nerdctl`, the CNI plugins and runc into the control plane's
cache and wrote the ownership record. The second fetched them again as an enrolled node,
presenting its client certificate and pinning the control plane by fingerprint — reaching no
upstream at all. An unenrolled host is refused with a message naming `nodary node enroll`.

**A bug this found in itself.** `--from` originally took a URL and used a bare HTTP client,
which cannot reach a mirror behind mTLS. It failed on the first real run with a certificate
error. The flag is now `--mirror` with no URL, because everything it needs — the server, the
pin, the certificate — is already in `agent.toml`, and a control plane a node had to be told
about separately would be one nobody pinned.

## 8. Open items

- Preflight (R5-01, R5-02, R5-04), `doctor` (R5-18), the setup URL (R5-08), `--with-node`
  (R5-12) and the FIPS job (R5-25) are the rest of [S7](mvp.md#4-the-route) and land next.
- [mvp §4](mvp.md#4-the-route)'s S7 row lists neither R5-06 nor R5-07, which is an omission:
  [01 §4](../specs/01-install.md#4-server-install)'s step 3 *is* component resolution, so
  R5-05 cannot be done without them.
