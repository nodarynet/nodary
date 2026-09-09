# R1e — Attestation

**Slice of:** [R1](../tasks/R1-core-audit-identity.md) · **Tasks:** R1-13 – R1-17, R1-29 – R1-31 ·
**Status:** complete

The last of five slices of R1.

```
R1a foundation --> R1b audit chain --+--> R1c identity --+
                                     +--> R1d policy   --+--> R1e attestation
```

[R1b](R1b-audit-chain.md) built the seam every mutation passes through and
[R1d](R1d-policy.md) built the object that decides how much ceremony a mutation costs. R1e is
what happens between them: the preview an operator approves, the hash that binds it, and the
proof that a person was present.

## Scope

| Task | |
| :--- | :--- |
| **R1-13** | Render a preview and hash it into `intent_hash`; `--dry-run` applies nothing |
| **R1-14** | Re-render and re-hash at apply; refuse on mismatch, exit 4 |
| **R1-15** | `--justify`, with `min_justification_length` from the active profile |
| **R1-16** | TOTP re-entry when `require_totp` is set, per act rather than per session |
| **R1-17** | `--allow-unattended` tokens: an audited grant, refused under `regulated` |
| **R1-29** | Exit codes 0–6 through every R1 verb |
| **R1-30** | Output discipline through every R1 verb |
| **R1-31** | `--yes` skips confirmation and skips neither justification nor TOTP |

## Design

### The preview is a function, not a value

`intent_hash` binds "what the operator approved" to "what was applied"
([07 §3](../specs/07-identity-audit.md#intent_hash)). Binding a *value* computed once would
bind nothing: it would still match after the world moved, because it was never recomputed.

So a verb supplies a **render**, run twice:

```go
type Render func(context.Context, *sql.Tx) (any, error)
```

Once against a read snapshot, to show the operator and hash into `intent_hash`; again inside
the mutation's own transaction, hashed and compared. A mismatch refuses with exit 4 and
applies nothing. `canonical.HashHex` does the hashing, which is [R1-01](../tasks/R1-core-audit-identity.md)'s
whole purpose — a hash is reproducible only because the encoding is.

**What each verb renders is what it actually depends on**, not a restatement of its arguments.
`user suspend` renders the state it is moving *from*; `policy apply` renders the diff. Both
change underneath an operator who walked away, which is the window
[07 §3](../specs/07-identity-audit.md#intent_hash) exists to close. A render that echoed only
the command line would hash something that cannot move and would be ceremony rather than a
gate.

### Ceremony is checked in a core package, prompted in the CLI

`internal/attest` holds the rules and no I/O: given a profile and what the caller supplied, it
says whether the act may proceed. The CLI prompts and reads a terminal;
[R2-20](../tasks/R2-control-plane.md) will read `X-Nodary-Justify` and `X-Nodary-TOTP` headers
and call the same function. This is the
[cross-cutting constraint](../tasks/README.md#cross-cutting-constraints) — one core, two
front ends — applied before there is a second front end to disagree with.

### What an unattended token substitutes for

[07 §2](../specs/07-identity-audit.md#2-attestation) requires re-authentication "when the
active policy requires it", and says non-interactive use requires a token minted
`--allow-unattended`. Read together, the rule is:

| `require_totp` | credential | outcome |
| :--- | :--- | :--- |
| false | any | no code |
| true | ordinary, interactive | prompt, and spend the code |
| true | ordinary, non-interactive | **refused** — there is nobody to attest |
| true | `--allow-unattended` | no code; the grant is the attestation, and it is in the chain |

The grant is what makes this honest. A cron job cannot prove a person was present, so it does
not get to claim it did — instead somebody stood behind it once, in an audited act, and that
record is what an assessor reads. Under `regulated`, `allow_unattended_tokens = false` closes
the route entirely.

**A wrong code and an absent code exit differently.** A code that fails to verify is an
authentication failure, exit 3. A code that policy required and nobody supplied is the policy
refusing the operation, exit 5 — the operator did not fail to authenticate, they were never
allowed to try.

### `--yes` and `--dry-run` are opposite ends of the same gate

`--dry-run` runs the render, prints the change and its hash, and stops before ceremony is even
checked: there is nothing to justify because nothing will happen.

`--yes` skips only the interactive confirmation, and
[10 §2](../specs/10-cli.md#2-global-flags) is explicit that it skips neither justification nor
TOTP. It is the flag most likely to be reached for by somebody trying to make a refusal go
away, so the test for it asserts the refusal still happens.

## Decisions

### The preview goes to stderr, the result to stdout

**Decided.** Previews, confirmations, prompts and the loosening report are diagnostics.

**Why.** [10 §4](../specs/10-cli.md#4-output-discipline) requires `--format json` to emit a
stable schema to stdout *and nothing else*. A preview on stdout would corrupt every scripted
caller, and `--dry-run --format json` still has to be parseable — so the preview's own JSON
form goes to stdout only when nothing else will.

**Rejected — preview on stdout, result on stderr.** Reads better interactively, since the
preview is the thing a human is there to read. It inverts the rule for every other verb and
breaks piping.

### TOTP is verified inside the mutation, not before it

**Decided.** `identity.VerifyTOTP` already takes an `audit.Mutation`, and R1e keeps it there.

**Why.** Spending the step is itself a write, and it must commit with the act it authorizes.
Verifying first and acting second gives a window where the code is spent and the act did not
happen — the operator's next attempt then fails on a replayed code they never got to use.

**The cost, stated:** the ceremony check therefore runs in two halves. Whether a code is
*required* is decided before the transaction, so an operator is prompted before anything
starts; whether it is *valid* is decided inside. A refusal for a wrong code is a rolled-back
transaction with a `failure` record, which is the correct outcome and worth the split.

## Steps

- [x] `internal/attest` — `Intent`, `Render`, `Ceremony`, `Require`
- [x] `session.act` — one gate every mutating verb passes through
- [x] Renders for `user`, `token` and `policy`, and `--dry-run`
- [x] R1-17 — `--allow-unattended` at mint, refused by profile
- [x] Exit codes and output discipline, asserted per verb
