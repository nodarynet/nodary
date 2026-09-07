# ADR 0007 — The component manifest as an independent artifact

**Status:** Accepted · **Date:** 2026-09-06 ·
**Amends:** [ADR 0004](0004-release-artifacts-and-channels.md)

## Context

[ADR 0004](0004-release-artifacts-and-channels.md) makes the component manifest one of three
release objects and embeds it in the binary. It names the maintenance burden that follows —
"every dependency bump is a digest update" — and accepts it, because the manifest's integrity
then comes for free: the binary is signed, `install.sh` verifies it, and a manifest inside a
verified binary needs no verification of its own.

[The pivot to CMMC](../plans/pivot-cmmc.md#adr-0007--the-component-manifest-becomes-an-independent-artifact)
turns that from a burden into a defect. containerd ships a fix; the customer cannot take it
until we cut a release. **We would have coupled every customer's patch timeline to our release
cadence, and their assessor holds them to a window we do not control.** 800-171 asks that
flaws be corrected in a timely manner, and "our vendor has not tagged yet" is not an answer
an assessor accepts from a company that could have shipped a manifest.

The pull is against a property worth keeping. Every component is digest-pinned precisely so
that nothing changes without an explicit human act, and the answer is not to weaken that.

## Decision

**The component manifest becomes separately versioned and separately signed. The binary's
embedded copy remains as a floor; a signed manifest revision with a higher revision number
supersedes it.**

| | |
| :--- | :--- |
| **Revision** | A monotonic integer in the manifest, independent of `nodary_version` |
| **Signature** | Detached, over the manifest bytes, against a key embedded in the binary |
| **Floor** | The embedded manifest. A revision at or below it is ignored, not an error |
| **Delivery** | Online from the control plane's upstream, or inside a `nodary bundle create` output for offline sites |
| **Failure** | Any verification failure falls back to the floor and is reported. A manifest is never partially applied |

Applying a revision is a mutation and lands in the audit chain, so *which* manifest an
install is running is an attributable fact rather than an inference from a version string.

### The signature is Ed25519 in the minisign format, non-prehashed

Verification happens in Go, in the binary, against an embedded public key. Two constraints
came out of [the spike](../spike-fips-and-manifest.md#3-the-manifest-can-be-verified-independently--the-reuse-claim-cannot)
and both are load-bearing:

**It is new code, not reused code.** [`internal/components/verify.go`](../../internal/components/verify.go)
verifies SHA-256 digests over HTTP and contains no signature verification of any kind; every
signature check in the project today is shell calling `openssl` or `minisign`. This ADR adds
the first signature verifier written in Go. It is roughly eighty lines against the standard
library and no new dependency — small, but it is not nothing, and describing it as reuse
would have hidden it.

**The prehashed minisign variant is refused.** Minisign's `ED` algorithm signs a BLAKE2b-512
digest. BLAKE2b is not in the standard library and is not FIPS-approved, so a prehashed
signature would place a non-approved hash on the path that verifies what a node installs —
inside the boundary [ADR 0006](0006-cui-boundary-and-fips.md) exists to defend. The legacy
`Ed` algorithm signs the message directly with Ed25519, which is approved and passes under
`GODEBUG=fips140=only`. **The release pipeline must produce `Ed` signatures**, and the
verifier rejects `ED` rather than growing a dependency to accommodate it.

The trusted comment is covered by the global signature and carries the revision number, so a
signature cannot be lifted from one revision onto another.

## Rationale

**Every property ADR 0004 argued for survives; only the embedding goes.** Components stay
pinned by digest, stay signed, and stay verified by Go code rather than by shell against a
tarball. ADR 0004's "the trust decision moves out of the least verifiable part of the system"
is unchanged — the manifest simply carries its own signature now instead of borrowing the
binary's.

**A floor is what makes this safe to add.** An install with no network, no bundle and no
revision behaves exactly as it does today. The embedded manifest is not a fallback for a
failure path; it is the normal state, and a revision is an improvement on it. That is also
why an older revision is ignored rather than rejected: an offline site replaying a stale
bundle should keep working, not fail closed on something that is not an attack.

**The failure modes were exercised before this was written.** A throwaway verifier resolved a
signed revision against a floor across five cases — valid, body tampered, wrong key, older
than the floor, trusted comment rewritten — and each behaved as specified. ADR 0007 was
[named load-bearing and unproven](../plans/pivot-cmmc.md#10-the-spike); it is no longer
unproven.

## Consequences

**Gained.** A customer can take a component fix on their own timeline. The advisory feed
([ADR 0005](0005-editions-and-the-advisory-feed.md)) has something to point at: an advisory
naming a digest is actionable only if the digest can be moved without a release.

**Lost.** The manifest stops being free. It is now a signed release artifact with its own
revision counter, its own publication step, and its own key to protect.

**Cost.** A second signing key in the release pipeline, and a Go verifier to maintain. The
same verifier serves [ADR 0005](0005-editions-and-the-advisory-feed.md)'s licence key and the
advisory feed, so it is written once and used three times — which is the argument for writing
it properly rather than inline.

**ADR 0004 stays Accepted.** Its reasoning holds; only the embedding is amended, and it gains
a pointer here.

**Reconsider if** manifest revisions turn out to be published so rarely that the machinery
outlives its purpose — in which case the honest fix is a faster release cadence, not a
revision channel nobody uses.
