# 00 — Overview

**Status:** Draft for implementation · **Date:** 2026-08-28

nodary manages LLM serving across the GPU machines you own, from one central control point,
with controls and logging over users, usage and models. A control plane owns all state; node
agents reconcile toward it.

The distinction from an orchestrator is the shape of the problem. Kubernetes, Ray and
comparable systems assume a cluster: a scheduler making placement decisions, a control loop,
and someone to operate them. nodary assumes a handful of machines on fixed hardware where
placement is a decision you make once, and the work is remembering what was done and by whom.

The target is a homelab or a small business with direct control of its hardware. A site with
security obligations — up to and including CMMC 2.0 — turns on stricter attestation and
retention through a policy profile ([07](07-identity-audit.md#4-policy-profiles)); it is not
the default posture.

## 1. Scope

A control plane plus a node agent. The control plane is the sole entry point for enabling
models, directing nodes, issuing tokens, and metering usage. Nodes run containers under
systemd, honour a small set of local guardrails ([12](12-node-guardrails.md)), and report
status.

### Non-goals

- **Not a scheduler.** Placement is explicit: a deployment names its node and its GPU indices. No bin-packing, no autoscaling, no preemption.
- **Not multi-tenant isolation.** Users are distinguished for attribution and quota, not sandboxed from one another.
- **Not highly available.** One control plane. It is restartable and its state is a single file; that is the recovery story.
- **Not a general workload runner.** nodary runs inference backends, not arbitrary jobs.

### Tool versus deployment

nodary is a general tool. **Nothing site-specific may live in code** — no internal hostnames,
no node names, no particular model IDs, no assumption of FIPS or a specific certificate
authority. Those are deployment configuration and policy.

| Layer | Lives in | Example |
| :--- | :--- | :--- |
| Tool | Code | "a deployment binds to GPU indices" |
| Deployment | `/etc/nodary/server.toml` | bind address, TLS cert paths, data dir |
| Configuration | Control-plane database | nodes, models, deployments, users |
| Policy | Control-plane database, as a profile | origin denylist, require re-auth, deny egress |

A regulated posture — CMMC, FedRAMP, or an internal standard — is expressed as a **policy
profile** ([07](07-identity-audit.md#4-policy-profiles)), never as compiled-in behaviour. The
profile a fresh install runs is `default`, which suits a homelab; `regulated` is opt-in.

## 2. Topology

```
                          ┌──────────────────────── control plane host ──┐
   IDE / CLI ──HTTPS──►   │  nodary-gateway  auth, quota, metering       │
                          │        │                                     │
                          │        ▼                                     │
                          │  LiteLLM         OpenAI-compat, routing      │
                          │        │                                     │
                          │  nodary-server   state, API, UI, enrollment  │
                          │  prometheus + grafana                        │
                          │  /var/lib/nodary/nodary.db                   │
                          └────────┬─────────────────────────────────────┘
                                   │ mTLS, agent-initiated (outbound only)
              ┌────────────────────┼────────────────────┐
              ▼                    ▼                    ▼
       ┌─── node ─────┐     ┌─── node ─────┐     ┌─── node ─────┐
       │ nodary-agent │     │ nodary-agent │     │ nodary-agent │
       │ containerd   │     │ containerd   │     │ containerd   │
       │ model units  │     │ model units  │     │ model units  │
       │ dcgm-exporter│     │ dcgm-exporter│     │ dcgm-exporter│
       └──────────────┘     └──────────────┘     └──────────────┘
```

Traffic to nodes is **agent-initiated only**. Nodes need no inbound firewall rules and no
listening SSH for nodary to function; the control plane never dials a node. A single-box
deployment uses `--with-node`.

Operator access is SSH: an administrator connects to a host and runs `nodary` verbs there.
The agent/control-plane relationship handles *workload* direction; SSH is the human's path to
*lifecycle* operations on a machine.

## 3. Object model

```
Node        a host running nodary-agent           pending → approved → ready → draining → departed
Backend     a model server descriptor             built-in | registered
Model       a catalog entry (weights + metadata)  registered → staged (per node) → available
Deployment  a model bound to (node, gpu_set)      defined → staging → preparing → starting → ready → stopped | failed
Route       a public model name → deployments     round-robins across ready members
User        a person                              active → suspended → deleted
Token       a credential belonging to a User      active → revoked | expired
Revision    an immutable config snapshot          append-only, hash-chained
AuditRecord an administrative action              append-only, hash-chained
UsageRecord one inference request                 high-volume, rolled up
```

Two chains, deliberately separate: **audit** is low-volume administrative actions kept for the
full retention period; **usage** is high-volume telemetry kept raw for 90 days and rolled up
to daily aggregates. Conflating them makes both worse.

## 4. State and change control

The control plane owns state in a single SQLite file. There is no declarative manifest and no
GitOps flow. Change control is preserved by other means:

- Every configuration change writes an immutable **revision**: monotonic sequence, full snapshot, author, justification, timestamp, hash-chained to its predecessor.
- `nodary config diff`, `nodary config rollback`, `nodary config show` operate on revisions.
- `nodary config export` emits canonical TOML and `nodary config apply -f` reads it back, for provisioning and disaster recovery — but the database, not the file, is authoritative.
- `nodary backup create` / `restore` handle recovery. The file is the artifact.

This is the API-first model used by Grafana, Vault and Tailscale: declarative provisioning is
retained, declarative *ownership* is not.

## 5. Trust boundaries

| Boundary | Control |
| :--- | :--- |
| Installer → host | Signed binary, digest verified before placement; components digest-pinned by an embedded manifest ([01](01-install.md)) |
| Node → control plane | Join token, then mTLS client certificate; admin approval before workload ([02](02-enrollment.md)) |
| Control plane → node | Local guardrails the agent enforces — offered GPUs, deployment ceiling, maintenance window ([12](12-node-guardrails.md)) |
| Deployment → network | Isolated namespace with no route off-box; continuously asserted ([03](03-agent.md#5-egress-isolation)) |
| Client → gateway | Bearer token resolved to a person; quota and model allowlist enforced ([06](06-gateway.md)) |
| Operator → mutation | Preview, justification, re-authentication, hash-bound apply ([07](07-identity-audit.md)) |

## 6. Component inventory

| Unit | Role | Host |
| :--- | :--- | :--- |
| `nodary-server` | State, HTTP API, enrollment, reconciliation, web UI | control plane |
| `nodary-gateway` | Client auth, quota, metering, proxy | control plane |
| `litellm` | OpenAI compatibility, routing, retries, fallbacks | control plane |
| `nodary-agent` | Enroll, long-poll, reconcile, report | every node |
| `nodary-model@<id>` | One model server instance | every node |
| `nodary-stage@<id>` | Transient weight-staging unit | every node |
| `dcgm-exporter` | GPU telemetry | every node |
| `prometheus`, `grafana` | Metrics and dashboards | control plane |

## 7. Why LiteLLM stays

nodary owns identity, quota, metering and audit. LiteLLM owns OpenAI compatibility, routing,
retries and fallbacks. Reimplementing the second set — streaming, tool calls, per-model token
accounting, error mapping — is where projects of this shape fail.

Because identity lives in nodary, LiteLLM runs **stateless behind a single master key** never
exposed to clients, and needs no database of its own.

## 8. Milestones

Each is independently useful and shippable.

| | Deliverable | Proves |
| :--- | :--- | :--- |
| **R1** | `core` + `audit` + `identity`: chain, attestation, roles, policy profiles, `audit verify/export` | Accountability, before any rearchitecture |
| **R2** | Control plane: SQLite state, HTTP API, revisions, CLI against it | State has one owner |
| **R3** | Gateway: auth, metering, throttling, LiteLLM stateless behind it | Tokens and usage |
| **R4** | Agent: enroll, long-poll, reconcile, systemd units, egress isolation, staging | Nodes run without an orchestrator |
| **R5** | `install.sh`, component manifest, PyPI/npm/Homebrew channels, `bundle create`, `upgrade`, `uninstall`, `doctor` | One-command install; the goal is met |
| **R6** | Backend descriptors beyond vLLM: SGLang, llama.cpp, TensorRT-LLM | Pluggability is real, not theoretical |
| **R7** | Read-only web UI: nodes, models, staging, usage, audit browser | Zero mutation, zero risk |
| **R8** | Mutating UI with attestation | Parity with the CLI |

Node guardrails ([12](12-node-guardrails.md)) are not a milestone of their own: the agent
checks the desired state against `node.toml` before reconciling, so the check lands in R4 with
the reconcile loop. Adding it afterwards would mean threading a refusal path through code
written to assume it never refuses.

R1–R5 deliver the whole stated goal with no frontend. R7 and R8 are polish; stopping after R6
is a complete outcome.
