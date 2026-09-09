# R2c — The shared core and the HTTP layer

**Slice of:** [R2](../tasks/R2-control-plane.md) ·
**Tasks:** R2-15 – R2-20, R2-24, R2-34, R2-42 · **Status:** complete

The slice where the CLI stops being the only front end, and therefore the slice where
[R2-34](../tasks/R2-control-plane.md) has to become structure rather than intent.

## The constraint this slice exists to satisfy

> **The CLI and the HTTP API call the same core functions.** Neither holds business logic.
> This is what keeps them behaviorally identical without duplicated effort, and it is a
> constraint on the implementation, not an aspiration.
> · [tasks README](../tasks/README.md#cross-cutting-constraints)

Until now there was one front end, so the constraint could not be violated and could not be
tested either. Adding the second is what makes it real.

**Today the CLI holds business logic.** `session.attested` in
[`internal/cli/attest.go`](../../internal/cli/attest.go) orchestrates the whole of
[07 §2](../specs/07-identity-audit.md#2-attestation): render the preview, hash it, check
ceremony against the active profile, verify TOTP inside the act, re-render and bind, apply.
An HTTP handler that reimplemented that would be a second implementation of attestation, and
the first divergence between them would be an API call that mutated with less ceremony than
the CLI demands. That is the failure this constraint exists to prevent, and it would not be
noticed until an assessor found it.

## Decision: the orchestration moves to `internal/core`, and prompting stays in the CLI

**Decided.** `core.Act` performs the sequence. `internal/cli` and `internal/api` supply a
principal, a ceremony and a change, and each renders the outcome its own way.

The split runs exactly along what a front end knows that the core cannot:

| Front end | Core |
| :--- | :--- |
| Where the credential came from — a file, a bearer token, a cookie | What that principal is allowed to do |
| How to ask a human for a TOTP code, or that there is no human | Whether a code is required, and whether it verifies |
| Whether to confirm interactively | That `--yes` never skips justification or TOTP |
| Text, JSON, or an HTTP status | What happened |

**Prompting cannot move into the core**, and that is the seam's real test. `core.Act` returns
`attest.ErrTOTPRequired`; the CLI catches it, prompts, and calls again, while the API turns it
into a `428`-shaped policy refusal. Neither invents a rule — they answer a question the core
asked.

**Rejected — a shared middleware the HTTP layer calls and the CLI imitates.** Natural for the
API and the smaller diff today. "Imitates" is the whole problem: it leaves two orchestrations
that agree by review rather than by construction.

**Rejected — make the CLI an HTTP client of its own server.** One implementation by
definition, and several products do it. It makes every local verb require a running server,
which contradicts [R1](../tasks/R1-core-audit-identity.md)'s premise that the CLI operates on
the database directly, and it puts recovery — the case where the server will not start —
behind the server.

## The HTTP layer

**Errors are one envelope with a stable `code`** ([09 §3](../specs/09-api.md#3-errors)), built
from the same error values the CLI maps to exit codes. Exit code 5 and HTTP 403 must come from
one `errors.Is` chain, or the two front ends disagree about what a policy refusal is.

**`?dry_run=true`, `X-Nodary-Intent`, `X-Nodary-Justify` and `X-Nodary-TOTP` are the CLI's
`--dry-run`, `--justify` and `--totp` arriving by another road.** They are parsed into the
same `attest.Ceremony` the CLI builds and handed to the same `core.Act`.

**Request IDs are minted at the edge and travel into the audit record**
([R2-24](../tasks/R2-control-plane.md)), so a user reporting one bad request resolves to one
row without guesswork.

### What this slice does not do

Pagination ([R2-21](../tasks/R2-control-plane.md)), `If-Match` (R2-22) and `Idempotency-Key`
(R2-23) are deferred by [the MVP route](mvp.md#4-the-route). Each is a real property and none
changes the shape of a handler enough that adding it later is a rewrite.

## R2-42 lands here because login is what needs it

PBKDF2-SHA256 with a salt of at least 128 bits — Go's FIPS module refuses shorter, so it is a
correctness requirement rather than a preference
([ADR 0006](../adr/0006-cui-boundary-and-fips.md)). The parameters travel with each hash so
raising the cost does not invalidate existing ones, and a hash under old parameters is
replaced on the next successful verification.

It arrives now because `POST /auth/login` is its first and only consumer, which is exactly the
argument [R1c](R1c-identity.md) made for deferring it.

## What moving the CLI onto the core changed

One thing, and it is an improvement rather than a regression. The confirmation and the TOTP
prompt swapped order: an operator now sees the change, confirms it, and *then* re-authenticates.
Before, the code was asked for first — proving presence for something not yet shown, which is
the wrong way round for a factor whose whole purpose is to attest to *this act*.

## Steps

- [x] `internal/core` — `Act`, and the CLI moved onto it with no behavior change
- [x] R2-42 — PBKDF2 password hashing, migration, `user passwd`
- [x] `internal/api` — server, router, the error envelope, request IDs
- [x] Auth: bearer tokens and session cookies honouring `session_ttl_minutes`
- [x] The mutating-handler gate: `dry_run`, intent, justify, TOTP
- [x] A test that the two front ends refuse the same things for the same reasons
