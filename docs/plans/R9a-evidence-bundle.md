# R9a — The evidence bundle

**Slice of:** [R9](../tasks/R9-evidence-remediation.md) · **Tasks:** R9-01 – R9-13 ·
**Status:** complete

The first commercial slice, and [the MVP route](mvp.md#51-evidence-export-lands-before-the-control-plane)
pulls it ahead of R2 on purpose: the bundle's only input that exists today is the chain, the
chain is finished, and the format is the one thing in the product that cannot be changed once
a customer holds one.

## Scope

R9-01 – R9-09 and R9-12 in full. R9-10, R9-11 and R9-13 ship as stubs with their structure and
no claims — [MVP §3](mvp.md#3-stub-discipline). R9-14 onwards is not in this slice.

## What is already built

Almost all of the chain half.
[`audit.VerifyFile(path, *Anchor)`](../../internal/audit/verify.go) already verifies a
fragment against the record it claims to follow, and `Result.Anchored` already means "this
fragment proves as much as a whole chain from the anchor onwards". That *is* R9-08, built in
[R1b](R1b-audit-chain.md) for `audit export --from-seq` and reusable here unchanged.

`ExportJSONL` already emits bytes identical to what a sink delivered, which is what lets
`chain.jsonl` be diffed against a copy shipped off-box.

## Decisions

### The bundle is signed by a key belonging to the install

**Decided.** Each install generates an Ed25519 signing key on first export. The private half is
sealed with the existing at-rest key; the public half is recorded in the chain when it is
created, and travels inside the bundle.

**Why.** [13 §3](../specs/13-evidence.md#3-the-bundle-verifies-without-nodary-installed) requires
that an assessor verify a tarball with no nodary and no network. Digests alone cannot do that:
anyone who edits a member can recompute `manifest.sha256`. A signature is what makes the
manifest worth checking, so there has to be a private key at export time — and the only machine
that has one is the customer's.

The chain is what makes the key trustworthy rather than merely present. The record of its
creation is inside the evidence the key later signs, so a substituted key is a key with no
creation record, which is exactly the kind of gap the chain exists to expose.

**Rejected — sign with nodary's release key.** One key to explain, and the strongest possible
provenance. Impossible: we do not hold a private key on a customer's box, and shipping one
would make every install able to forge every other install's evidence.

**Rejected — digests only, no signature.** Simplest, and honest about what it proves. It proves
that a bundle is internally consistent, which is a property a forger can also arrange. It also
contradicts 13 §2, and a member list that anyone can regenerate is not evidence.

**Rejected — sign with the at-rest key.** It exists, it is already sealed, and no new key
management appears. It is a symmetric key: anything that can verify can also forge, so the
assessor would need the customer's secret to check the bundle. That is the opposite of the
property being sold.

### The verifier is stdlib, and refuses minisign's prehashed variant

**Decided.** `internal/minisign` — Apache, core, no dependency — verifying the legacy `Ed`
algorithm and refusing `ED`.

**Why.** [ADR 0007](../adr/0007-independent-component-manifest.md) settled this: the prehashed
variant signs a BLAKE2b-512 digest, and BLAKE2b is neither in the standard library nor
FIPS-approved, so it would put a non-approved hash on the path that verifies a licence — inside
the boundary [ADR 0006](../adr/0006-cui-boundary-and-fips.md) exists to defend. The same
verifier serves the licence here, the manifest in [R5-27](../tasks/R5-install.md) and the feed
in R9-14, which is why it is written properly rather than inline.

It is **core, not `ee/`**: [ADR 0005](../adr/0005-editions-and-the-advisory-feed.md) keeps every
mechanism Apache, and a community install verifies manifest revisions with this same code.

### An unlicensed install exports nothing, and says exactly what it would have exported

**Decided.** `nodary evidence export` without a licence lists every member, says what each one
is for, and exits 5 without writing a file.

**Why.** [ADR 0005](../adr/0005-editions-and-the-advisory-feed.md)'s first non-negotiable. A
hidden verb is discovered by a customer only after they have chosen something else.

**Rejected — a watermarked or truncated bundle.** It demonstrates the artifact rather than
describing it, which is a better sales tool. A half-bundle in an assessor's hands is worse than
no bundle, and the first time one is mistaken for the real thing is a support incident that
costs more than the trial was worth.

### Every member is present, and an empty one says so in its own schema

**Decided.** `revisions.jsonl`, `nodes.json` and `remediation.jsonl` have no producer until R2,
R4 and R9's remediation half. They ship as valid, empty documents carrying a `status` that
names why.

**Why.** 13 §2 already requires it. The reason it is worth restating: an assessor who sees a
file with a header and no rows learns that nodary knows about the category and this install has
nothing in it. An assessor who sees a missing file has to ask, and the answer costs a meeting.

## Steps

- [x] `internal/minisign` — verify `Ed`, refuse `ED`
- [x] The install's signing key, sealed, its creation audited
- [x] `ee/` — the licence file, `nodary license apply|show`
- [x] `ee/evidence` — the bundle, every member
- [x] `nodary evidence export`, and the unlicensed path
- [x] The verify-without-nodary procedure, tested by running it
