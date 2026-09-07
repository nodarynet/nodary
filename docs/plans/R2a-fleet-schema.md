# R2a — The fleet schema

**Slice of:** [R2](../tasks/R2-control-plane.md) · **Tasks:** R2-01, R2-04 – R2-10 ·
**Status:** complete

The first slice of R2, and the one [S4 of the MVP route](mvp.md#4-the-route) starts with.
It turns the fleet objects into state: nodes, models, staging, deployments, routes, limits,
usage and join tokens become rows, with the constraints that keep them honest.

Nothing here talks to a node or serves inference. Nothing here creates a row either — the
writers arrive with the endpoints in the next slice and with [R4](../tasks/R4-agent.md). What
this slice owes is the shape, because [R2-11](../tasks/R2-control-plane.md)'s revision
snapshots every one of these tables and cannot be written against a schema that does not exist.

## Scope

| Task | |
| :--- | :--- |
| **R2-01** | `node` — inventory, offer, constraints, `reboot_policy`, and its states |
| **R2-04** | `model` and `staging`, keyed `(model_id, node_name)` |
| **R2-05** | `deployment` and its states |
| **R2-06** | `route` and `route_member` |
| **R2-07** | `limits` keyed `(subject_kind, subject_id)` |
| **R2-08** | `usage` and `usage_daily` |
| **R2-09** | `join_token` — the `policy` half landed in [R1d](R1d-policy.md) |
| **R2-10** | No two deployments on a node may claim the same GPU index |

**Not in this slice.** [R2-02](../tasks/R2-control-plane.md) (`refusal`) and R2-03 (`backend`,
`derived_image`) belong to node guardrails and to [R6](../tasks/R6-backends.md), both of which
the MVP defers. `deployment.backend` and `model.backend` are therefore plain text with no
foreign key: naming a backend the catalog does not yet hold is a state this milestone cannot
reach, and a constraint against a table that does not exist is not a constraint.

## Decisions

### Constraints go in the schema, not only in the write path

**Decided.** Every state machine is a `CHECK`, every relationship a foreign key, and R2-10 is
a partial unique index.

**Why.** [R1a](R1a-storage-foundation.md) established this and 08 §1 argues it for the audit
chain specifically: `prev_hash UNIQUE` puts "two records cannot claim the same predecessor" in
the schema "rather than only in the write path — it then holds against a writer that never
goes through the audit layer." The same reasoning covers the fleet. The control plane is about
to grow an HTTP surface and an agent protocol, and a rule enforced in one handler is a rule
the other handler does not have.

### R2-10 is an index, not a check at apply time

**Decided.** An unconditional unique index over `(node_name, gpu_index)`, populated from a
`deployment_gpu` table rather than from `gpus_json`. A deployment holds its claim for as long
as it exists.

**Why.** [11 §2](../specs/11-failure-modes.md#2-models-and-deployments) makes "two deployments
claim one GPU" a failure mode with a named owner, and
[R4-23](../tasks/R4-agent.md) double-checks it on the node. The control plane's half has to be
a constraint the database enforces, because the two writers that will race are an HTTP handler
and an agent reconcile, and neither can see the other's transaction.

That needs the GPU index as a row, not an element inside a JSON array: SQLite cannot make a
unique index over the contents of `gpus_json`. So a deployment's GPUs are a child table, and
`gpus_json` in [08 §1](../specs/08-data-model.md#1-schema) becomes the rendering rather than
the storage.

**The claim was going to expire with the deployment's liveness, and cannot.** The first
version indexed only deployments in a live state, which needs the deployment's state in the
index's `WHERE` clause — and **SQLite prohibits subqueries in a partial index predicate**,
measured, not assumed. Reaching that state from here would mean copying it into
`deployment_gpu` and keeping the copy in step, which is the write-path discipline this index
exists to replace.

Holding the claim through `stopped` and `failed` turns out to be the better rule anyway. A
failed deployment on GPU 0 is one to fix and restart, not one to quietly build over; freeing
the GPU means deleting the deployment, which is an explicit act by somebody and recorded —
which is what this product does everywhere else.

**Rejected — validate in the handler.** No schema change, and the error message is nicer. Two
handlers and an agent all have to remember, and the first one that forgets produces exactly the
failure 11 §2 names, on a machine nobody is watching.

**Rejected — a unique index over `gpus_json` text.** Cheap. It makes `[0,1]` and `[1,0]`
different values and `[0]` compatible with `[0,1]`, so it forbids the wrong things.

### Usage is a separate chain from audit and never joins it

R2-08's `done:` says it and it is worth stating in the schema too: `usage` has no `prev_hash`
and no `hash`. It is telemetry, written per request at a volume the audit chain would choke
on, and pruned on a schedule the audit chain must never be pruned on
([08 §3](../specs/08-data-model.md#3-retention)). Conflating them would either make throttling
events tamper-evident at enormous cost or make administrative acts disposable.

## Steps

- [x] Migration `0006_fleet.sql` — every table, every state machine as a CHECK
- [x] `deployment_gpu` and the unique index that makes R2-10 structural
- [x] Tests that each constraint refuses what it should, and permits what it should

**Moved out of this slice:** the row types and the reads a revision snapshot needs. They have
no caller until [R2-11](../tasks/R2-control-plane.md) exists, and types written against no
caller are types written against a guess. They land with revisions.

**`join_token` was already built.** [R1c](R1c-identity.md) created it for `nodary token join`,
so R2-09 is complete rather than partly done — both halves landed early, in the slices that
needed them.
