# R4c — The reconcile loop, units, and the daemon

**Slice of:** [R4](../tasks/R4-agent.md) ·
**Tasks:** R4-12, R4-18 – R4-20 · **Status:** complete

The acting half. [R4b](R4b-backends-and-the-plan.md) made the agent able to say exactly what
it would do; this makes it do it. Egress isolation is R4d and lands next, which means nothing
built here may assume a deployment is unreachable — the network name is in the plan and the
network itself is not yet created.

## 1. Side effects are two function fields, not an interface

**Decided.** `Host` carries `Run` (execute a command) and `Probe` (make one HTTP request).
Everything else — reading and writing files — happens directly, with paths that the plan
already renders and a test can point at a temporary directory.

**Why.** Those two are the entire boundary between decidable and undecidable.
[R4b](R4b-backends-and-the-plan.md) put everything decidable in `Build`, so what is left is
`systemctl` and a health endpoint, and both have exactly one real implementation plus one test
double. A `Host` interface with a method per operation would be an abstraction over a boundary
that has two functions in it.

Injecting the filesystem too was considered and rejected. `Unit.EnvPath` is rendered by the
plan, so `PlanOptions.ConfigDir` already lets a test put it under `t.TempDir()` — a second
mechanism for the same thing would be one to keep in step.

**Rejected — shell out through a single `exec` helper with no injection, and test against real
systemd only.** Simplest code. It makes every test require a systemd user manager, which CI
may not have, and it makes the failure paths — a unit that will not start, a `systemctl` that
is not installed — untestable, which is most of what this slice has to get right.

## 2. The env file is compared before it is written

**Decided.** Reconcile reads the file on disk, compares it to what the plan renders, and
writes only on a difference. A unit is restarted only when its env file actually changed or it
is not running.

**Why.** [03 §3](../specs/03-agent.md#3-reconcile-loop) requires the loop to be idempotent and
convergent, and the failure mode of getting it wrong is not a wasted write — it is a model
server restarting every fifteen seconds forever, dropping in-flight requests each time.
[R4b](R4b-backends-and-the-plan.md) already made the rendering byte-stable for this reason;
this is the other half of the same guarantee, and the two are tested together.

## 3. The agent owns `nodary-model@*` and nothing else

**Decided.** Reconcile stops units matching `nodary-model@*` that the plan does not name, and
never touches any other unit.

**Why.** A node is rarely only a nodary node —
[12](../specs/12-node-guardrails.md) opens with exactly that, a box that drives a display and
hosts something else at 3pm on a Tuesday. An agent that stopped "anything it did not
recognize" on a machine somebody else also uses is the single most destructive thing this
codebase could do, and the blast radius is bounded by naming what it owns rather than by
listing what it must not touch.

## 4. Health is reported, not acted on

**Decided.** The agent polls, counts three consecutive failures, and reports `unhealthy`. It
does not remove anything from a route.

**Why.** [03 §7](../specs/03-agent.md#7-gpu-assignment-health-restart-reboot) assigns the two
halves to different sides: the agent marks it, "the control plane removes it from its route,
and `Restart=always` handles recovery". A route is fleet state — another node may hold the
last ready replica — and a node that withdrew itself would be making a decision on
information it does not have.

**Rejected — let the agent stop an unhealthy deployment.** It looks like fixing the problem.
`Restart=always` is already systemd's job ([03 §6](../specs/03-agent.md#6-unit-template) is
explicit that the agent holds no supervision logic), and an agent that stops things would race
the restart it is supposed to be observing.

## 5. The daemon reconciles forward and never replays

**Decided.** `nodary agent run` long-polls, plans, reconciles, heartbeats, and repeats. On
reconnect after a gap it acts on whatever the current document says and never walks the
revisions it missed.

**Why.** [11 §1](../specs/11-failure-modes.md#1-control-plane-and-agent) says so directly, and
the reason is in the shape of the protocol:
[03 §2](../specs/03-agent.md#2-desired-state-document) makes the document a complete end
state with no imperative commands in it, so there is nothing in an intermediate revision that
converging on the latest one would miss. Replaying would mean starting a deployment that was
created and withdrawn while the node was offline.

R4-12's backoff comes with it. A daemon that retries a down control plane in a tight loop is a
node that turns one outage into two, and the jitter is what stops a fleet retrying in lockstep.

## 6. The unit template is written by the agent, and rewritten if it drifts

**Decided.** The agent writes `nodary-model@.service` if it is absent or differs from the
template this build carries, and runs `daemon-reload` when it does.

**Why.** [03 §6](../specs/03-agent.md#6-unit-template) fixes the template's contents and
[01 §5](../specs/01-install.md#5-node-install) has `node install` place it — but `node install`
is R5, and until it exists nothing would. Writing it from the agent also makes the drift case
correct rather than undefined: the template and the env-file variable names are one contract,
and a template edited by hand that no longer reads `NODARY_ARGS` produces a deployment that
starts with no arguments at all.

**Rejected — refuse to run if the template is missing, and let R5 place it.** Cleaner
ownership. It makes this slice untestable end to end and leaves a version of the agent that
cannot start a model on a correctly enrolled node.

## 7. The shape

| | |
| :--- | :--- |
| `internal/agent/unit.go` | The unit template, and writing it |
| `internal/agent/reconcile.go` | `Host`, `Reconcile`, observing systemd |
| `internal/agent/health.go` | The probe and the three-strike counter |
| `internal/agent/run.go` | The daemon: poll, plan, reconcile, report |
| `internal/cli/agent.go` | `nodary agent run` |

## 8. Steps

- [x] The unit template, matching 03 §6 exactly
- [x] `Reconcile`: observe, write, start, stop, report
- [x] Health polling and the three-strike rule
- [x] The daemon loop with backoff and jitter
- [x] `nodary agent run`
- [x] A real systemd run on this machine, not only a fake

## 9. What this slice changed outside itself

- **[03 §6](../specs/03-agent.md#6-unit-template)'s unit template was wrong.** It expanded the
  argument list as `${NODARY_ARGS}`, and systemd passes a braced variable as a *single*
  argument — only the bare `$FOO` splits at whitespace. A model server would have received its
  whole argv as one string and exited on an unrecognized argument, which surfaces on a GPU host
  as a container that will not start, a long way from its cause.

  Found by writing the assertion instead of trusting the template, and measured on systemd 255
  in both directions: `$NODARY_ARGS` produced three arguments, `${NODARY_ARGS}` produced one
  and the job failed. The spec now carries the correction and the reason; the test asserts both
  forms, so the braces cannot come back quietly.

  It is also the measured basis for something that was previously an assumption:
  [R4b](R4b-backends-and-the-plan.md) refuses an `extra_args` entry containing whitespace, and
  the reason is exactly this expansion — no quoting convention applied on our side survives it.

- The template now reads `${NODARY_NETWORK}` rather than hardcoding `nodary-isolated`, because
  [03 §2](../specs/03-agent.md#2-desired-state-document)'s document carries `network` per
  deployment and a hardcoded template would make that field a lie.
- [10 §1](../specs/10-cli.md#1-verbs) gains `agent run`.

## 10. What was run, and what it proved

Against a live control plane on this machine, not only against the fake host: enrol, approve,
`config apply`, then `nodary agent run`. The node polled its desired state over mTLS, verified
real weights against a real `sha256sum` manifest, wrote the environment file, wrote and loaded
the unit template, and started the instance — which failed with
`Unit containerd.service not found`, reported as `failed` carrying systemd's own message.

That is the correct outcome on a host without a container runtime, and it is every host until
R5-04. The heartbeat then delivered the real inventory (an RTX 5090 on driver 610.88), the
staging verdict `staged`, and the health probe's actual connection error — so
[R4a](R4a-agent-protocol.md)'s observed-state path was exercised with real data rather than a
fixture.

## 11. Open items

- R4d takes egress isolation (R4-26, R4-27, R4-29), which
  [mvp §5.3](mvp.md#53-egress-isolation-is-built-node-guardrails-are-not) makes non-optional.
- Nothing here fetches containerd or `nerdctl`. That is R5-04, and until it lands a unit will
  fail to start on a host without them — reported as `failed` with the log tail, which is the
  correct behavior for a missing runtime either way.
