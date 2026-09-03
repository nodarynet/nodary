# Implementation plans

**How.** [`docs/specs/`](../specs/) says what, [`docs/adr/`](../adr/) says why,
[`docs/tasks/`](../tasks/) says what is done. A plan says how one slice of a
milestone gets built, and records the decisions taken along the way.

## What a plan is for

A milestone is too large to design in one pass. [R1](../tasks/R1-core-audit-identity.md)
is 31 tasks whose dependencies are forced rather than chosen, so it is split into slices
that are designed and built in order. One file per slice.

A plan carries three things the tracker cannot:

1. **The design** — packages, interfaces, and how the pieces fit.
2. **The decisions** — what was chosen, and what was rejected and why. This is the part
   that outlives the work. A decision recorded only in a commit message is a decision
   nobody can find.
3. **The steps** — the in-flight record. A tracker checkbox is binary; a plan is where
   partially-finished work lives.

## The rules

- **The plan is the in-flight record.** A checkbox in [`docs/tasks/`](../tasks/) flips
  only when the task's `done:` criteria actually pass. Progress before that point lives
  in the plan's steps.
- **The specs stay authoritative.** A plan never restates a decision a spec already
  made, and never contradicts one. Where a plan finds a spec wrong, the spec is
  corrected — the plan records it as an open item until it is.
- **A decision without its rejected alternatives is half-recorded.** The reasoning is
  the point; the outcome alone is already visible in the code.
- **Plans are disposable.** Like the tracker, they are derived. Once a slice lands, its
  plan is history rather than a maintained document.

## Slices

| Plan | Milestone | Tasks | Status |
| :--- | :--- | :--- | :--- |
| [R1a — Storage foundation](R1a-storage-foundation.md) | [R1](../tasks/R1-core-audit-identity.md) | R1-01 – R1-04 | complete |
| [R1b — Audit chain](R1b-audit-chain.md) | [R1](../tasks/R1-core-audit-identity.md) | R1-05 – R1-12 | complete |
| [R1c — Identity](R1c-identity.md) | [R1](../tasks/R1-core-audit-identity.md) | R1-18 – R1-24, R1-36 | complete |

## Not a slice

One file here is not a slice of a milestone.
[Pivot — SMB CMMC as the primary market](pivot-cmmc.md) re-aims the product at a buyer
and records what the specifications owe as a result. It is the one plan that changes what
the authoritative documents say rather than describing how to build what they already
said, and it is finished when [§7](pivot-cmmc.md#7-spec-corrections-this-plan-owes) is
empty.
