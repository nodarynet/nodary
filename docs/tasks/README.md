# Implementation tasks

**Status:** derived from the specifications as of 2026-08-29

## What this is

A tracker, derived from [`docs/specs/`](../specs/) and disposable. It exists to
say what is done, what is next, and where each piece of work comes from.

**The specs are authoritative.** Nothing here restates a decision; every task
points at the text that made it. Where a task and its spec disagree, the spec
wins and the task is wrong — fix the task. A change of intent is a change to a
spec, and the tasks follow.

## Milestones

R0 is the ground the milestones stand on rather than one of them. R1–R5 deliver
the whole stated goal with no frontend; R6 makes pluggability real; stopping
after R6 is a complete outcome, and R7–R8 are polish.
· [00 §8](../specs/00-overview.md#8-milestones)

| | Milestone | Proves | Depth | Open |
| :--- | :--- | :--- | :--- | ---: |
| **[R0](R0-release.md)** | Release pipeline | The distribution path works while the stakes are zero | task | 5 of 25 |
| **[R1](R1-core-audit-identity.md)** | Core, audit, identity | Accountability, before any rearchitecture | task | 31 |
| **[R2](R2-control-plane.md)** | Control plane | State has one owner | task | 40 |
| **[R3](R3-gateway.md)** | Gateway | Tokens and usage | deliverable | 14 |
| **[R4](R4-agent.md)** | Agent | Nodes run without an orchestrator | deliverable | 37 |
| **[R5](R5-install.md)** | Installation | One-command install — the goal is met | deliverable | 21 |
| **[R6](R6-backends.md)** | Backends | Pluggability is real, not theoretical | deliverable | 12 |
| **[R7](R7-ui-readonly.md)** | Read-only UI | Zero mutation, zero risk | deliverable | 8 |
| **[R8](R8-ui-mutating.md)** | Mutating UI | Parity with the CLI | deliverable | 6 |

R0–R2 are broken to task level because they are what you would start now.
R3–R8 are deliverable level deliberately: writing 150 detailed tasks against
decisions R1 and R2 have not yet tested produces detail that has to be unwritten.
Break a milestone down when you reach it.

R0 has 20 items delivered and 5 outstanding; the 5 are gaps between what a
document promises and what the tree does, and they block a first real release.
Three of them — the signing key, the fingerprints and the hosting — need
material only the release owner holds.

## Task format

```markdown
- [ ] **R1-07** Chain audit records by `prev_hash` · [07 §3](../specs/07-identity-audit.md#3-the-audit-chain)
  - *done:* mutating record k in a chain of N makes `audit verify` report the first break at seq k
  - *deps:* R1-05, R1-06
```

- **IDs are permanent.** They are what a commit subject cites — `[feat] R1-07 chain audit records by prev_hash`. A dropped task is struck through, never deleted and never renumbered; the number is not reused.
- **The spec link is the requirement.** It is anchored, so a task always resolves to the text it came from. A task with no spec link is a task nobody agreed to.
- **`done:` is a condition, not a restatement.** It says how you would know, and is omitted where the spec section is unambiguous on its own.
- **`deps:` lists only hard ordering** — work that cannot start until the named task lands. Not "related to".

## Cross-cutting constraints

Three properties every milestone must respect and none can complete. They are
review criteria, not work items — a checkbox would be the wrong shape, because
nothing ever finishes them.

1. **The CLI and the HTTP API call the same core functions.** Neither holds business logic. This is what keeps them behaviourally identical without duplicated effort, and it is a constraint on the implementation, not an aspiration. · [10 §1](../specs/10-cli.md#1-verbs)
2. **Every mutating call passes through the audit layer.** Not by convention — structurally, so that a mutating path which writes no record cannot be reached. · [07 §3](../specs/07-identity-audit.md#3-the-audit-chain)
3. **Nothing site-specific lives in code.** No internal hostnames, no node names, no particular model IDs, no assumption of FIPS or a specific certificate authority. A regulated posture is a policy profile, never compiled-in behaviour. · [00 §1](../specs/00-overview.md#tool-versus-deployment)

## Failure-mode coverage

[11 — Failure modes](../specs/11-failure-modes.md) states that every row of its
tables is a test case. Its 40 rows are not tracked separately, because they span
every milestone; each is an acceptance criterion inside the milestone that owns
the behaviour. This table exists so none is lost.

### [§1 Control plane and agent](../specs/11-failure-modes.md#1-control-plane-and-agent)

| Failure | Owned by |
| :--- | :--- |
| Control plane down | R4-12 |
| Agent down | R4-09 |
| Agent certificate expired | R4-05 |
| Protocol version unsupported | R4-11 |
| Network partition | R4-12 |
| Clock skew > 60s | R5-02, R5-18 |
| Agent event queue overflows | R4-10 |

### [§2 Models and deployments](../specs/11-failure-modes.md#2-models-and-deployments)

| Failure | Owned by |
| :--- | :--- |
| Weights corrupt | R4-35 |
| Staging interrupted | R4-33 |
| Disk full during staging | R4-33 |
| `prepare` fails or times out | R6-06 |
| Derived-image build fails | R6-10 |
| Derived-image build reaches outside its index | R6-09 |
| A derive's base image moves | R6-10 |
| Deployment crash-loops | R4-21 |
| Deployment never becomes ready | R4-21 |
| Two deployments claim one GPU | R2-10, R4-23 |
| GPU falls off the bus | R4-25 |
| WSL2 host rebooted, no logon task | R4-09, R5-04 |
| NVIDIA driver installed inside WSL2 | R5-03 |
| Model origin becomes policy-denied | R4-32 |
| Node guardrail refuses an action | R4-15 |
| A guardrail narrows under a running deployment | R4-16 |
| `nodary node leave` run on a node | R4-06 |

### [§3 Security controls](../specs/11-failure-modes.md#3-security-controls)

| Failure | Owned by |
| :--- | :--- |
| Egress verification fails | R4-29 |
| Audit chain broken | R1-09 |
| `intent_hash` mismatch at apply | R1-14, R2-19 |
| Bundle signature invalid | R5-14 |
| Join token replayed | R4-03 |
| Unapproved node requests work | R4-04 |

### [§4 Gateway](../specs/11-failure-modes.md#4-gateway)

| Failure | Owned by |
| :--- | :--- |
| No ready deployment on a route | R3-11 |
| LiteLLM unreachable | R3-11 |
| Stream terminates early | R3-07 |
| Token revoked mid-stream | R3-11 |
| Quota exceeded | R3-09 |

### [§5 Recovery](../specs/11-failure-modes.md#5-recovery)

| Situation | Owned by |
| :--- | :--- |
| Control plane host lost | R2-37 |
| `secret.key` lost | R1-04, R2-37 |
| Database corrupt | R1-08, R2-37 |
| Bad upgrade | R5-15 |
| Node unrecoverable | R4-06, R4-34 |
