# R1d — Policy profiles

**Slice of:** [R1](../tasks/R1-core-audit-identity.md) · **Tasks:** R1-25 – R1-28 ·
**Status:** complete

The fourth of five slices of R1.

```
R1a foundation --> R1b audit chain --+--> R1c identity --+
                                     +--> R1d policy   --+--> R1e attestation
```

R1d comes before [R1e](../tasks/R1-core-audit-identity.md) because three of R1e's five tasks
name R1-25 as a dependency: justification length, TOTP re-entry and unattended-token grants
are all *ceremony the active profile decides*. Building attestation first would mean building
it against a profile that does not exist and then threading one through.

## Scope

| Task | |
| :--- | :--- |
| **R1-25** | Parse and validate a profile from TOML; unknown keys rejected |
| **R1-26** | Embed `default` and `regulated`; `default` active on a fresh install |
| **R1-27** | Enforce the invariants no profile can turn off |
| **R1-28** | `nodary policy show\|apply\|diff` |

## Decisions

### TOML comes from a dependency, not from us

**Decided.** Add `github.com/BurntSushi/toml`.

**Why.** R1-25's `done:` is *unknown keys are rejected rather than ignored*, and that is the
whole point of a profile being a reviewable object — a silently dropped key defeats it.
BurntSushi exposes `MetaData.Undecoded()`, which is precisely that check; a hand-rolled parser
would have to reimplement it along with the rest of the grammar.

TOML is not incidental here. [12](../specs/12-node-guardrails.md) specifies `node.toml`,
[04](../specs/04-backends.md) makes backend descriptors TOML files, and
[R2-35](../tasks/R2-control-plane.md) adds `server.toml`. The dependency is paid once and used
by four subsystems. It is pure Go with no transitive dependencies, so
[ADR 0002](../adr/0002-go-with-package-manager-wrappers.md)'s static-binary property is
untouched.

**Rejected — hand-roll a subset parser.** The profile is a flat table of scalars and string
arrays, so a subset is perhaps 150 lines and adds nothing to `go.mod`. It is *more* code than
it saves, and it fails in the worst available direction: a subset parser accepts documents
real TOML rejects and rejects documents real TOML accepts, so the file an operator reviews and
the file nodary reads stop being the same document. Being approximately right about a security
posture's syntax is not a saving.

**Rejected — JSON, reusing the encoder R1a already has.** Zero new dependencies and the
canonical encoder is already here. The specification says TOML, operators edit this file by
hand, and JSON has no comments — and every line of the shipped profiles in
[07 §4](../specs/07-identity-audit.md#4-policy-profiles) is commented, because the comment is
what explains *why* a constraint is set where it is.

### The active profile is stored as its source text

**Decided.** One singleton row holding the profile's TOML bytes, its name, and when it was
applied. `show` and `diff` re-parse it rather than reading columns.

**This contradicted [08 §1](../specs/08-data-model.md#1-schema)**, which specified
`policy(name PK, body_toml, active, applied_by, applied_at)`. Per
[the rules](README.md#the-rules) that should have been recorded here as an open item when the
slice landed and was not — the omission is noted rather than quietly repaired. The spec has
since been corrected to the singleton, with the reasoning in 08 §1: `applied_by` duplicates
the audit record, `name PK` plus `active` admits having no active profile or two, and storing
inactive profiles serves no verb.

**Why.** [07 §4](../specs/07-identity-audit.md#4-policy-profiles) calls a profile "a single
reviewable object", worth as much to an assessor as to a maintainer. Storing the source keeps
it one object; storing sixteen columns turns it into sixteen facts that can disagree with the
document they came from. Re-parsing on read also means `show` cannot drift from `apply` — they
run the same code over the same bytes.

**Rejected — a column per setting.** Queryable, and the obvious shape for R2's API. It makes
the reviewable object a rendering rather than a record, and every new setting becomes a
migration. R2 can add a projection over the source when something actually needs to query it.

**Rejected — a file at `/etc/nodary/policy.toml`.** Matches how operators think about
configuration, and needs no schema at all. It puts the posture outside the database and
therefore outside `backup create`, outside the chain's transaction, and reachable by anything
that can write the filesystem. Applying a profile is a mutation; mutations live in the
database and commit with their audit record.

### History lives in the chain, so the row is a singleton

Every `policy apply` is an audited mutation carrying the applied source in its detail. Asking
"what was the posture on the 3rd of March" is a chain query, not a table scan, and that is
the same answer [13](../specs/13-evidence.md) gives for every other historical question.

## What R1-27 can actually enforce

The five invariants in [07 §4](../specs/07-identity-audit.md#what-a-profile-cannot-turn-off)
divide in two, and conflating them would produce a check that cannot fail.

**Three are not expressible.** The audit chain, `intent_hash` binding and digest-pinned
components have no key in either shipped profile. A profile that tries to disable them is
already rejected by R1-25 as an unknown key — but *"unknown key `audit_chain`"* is a poor
answer to somebody who just tried to turn off the audit chain. These get named rejections that
say the property is not a setting and why, rather than falling through to the generic message.

**Two are expressible, and are the real check.** `require_signed_artifacts = false` and
`egress_default = "allow"` are valid TOML against valid keys, and both must be refused at
parse and at apply. They are the ones a plausible profile could contain by accident.

## Steps

- [x] `internal/policy` — `Profile`, `Parse`, the invariants, the two embedded profiles
- [x] Migration `0004_policy.sql` — the singleton row
- [x] `Active` and `Apply`, the latter through `audit.Mutation`
- [x] `Diff`, naming which constraints loosen
- [x] `nodary policy show|apply|diff`
