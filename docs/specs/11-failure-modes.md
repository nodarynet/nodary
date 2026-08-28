# 11 — Failure modes

Behaviour under failure is specified, not left to discovery. Every row below is a test case.

## 1. Control plane and agent

| Failure | Behaviour |
| :--- | :--- |
| Control plane down | Nodes keep serving. Agents retry with exponential backoff and jitter. The gateway is down, so inference stops — accepted, and the reason `--with-node` exists for single-box installs |
| Agent down | Deployments keep running; systemd owns them. Node marked `stale` after 60s without a heartbeat |
| Agent certificate expired | Agent stops reconciling, keeps units running, reports `expired`. Requires an administrator to re-enroll |
| Protocol version unsupported | Agent stops reconciling, keeps units running, reports `incompatible`. It does not guess ([03](03-agent.md#4-version-skew)) |
| Network partition | Agent continues serving from last known desired state. On reconnect it reconciles forward; it never "catches up" by replaying intermediate revisions |
| Clock skew > 60s | mTLS and audit ordering break. `doctor` reports it as a hard failure |
| Agent event queue overflows | Oldest events spill to disk; if the disk buffer fills, the drop is itself recorded as an audit event |

## 2. Models and deployments

| Failure | Behaviour |
| :--- | :--- |
| Weights corrupt | Deployment refuses to start; state `corrupt`; explicit `restage` required. Nothing auto-repairs |
| Staging interrupted | Resumes from partial on reconnect. Temporary directory is never renamed into place unverified |
| Disk full during staging | Staging fails cleanly, the partial is removed, an alert is raised |
| `prepare` fails or times out | Deployment marked `failed` with the build log tail. Weights remain staged; the artifact is not cached |
| Derived-image build fails | No image is produced and none is replaced. The failure is audited with the log tail; deployments on the previous digest keep serving ([04](04-backends.md#5-derived-images)) |
| Derived-image build reaches outside its index | Build fails. An unexpected dependency is a failure, not a surprise to discover later |
| A derive's base image moves | The derive is marked `stale`. Nothing rebuilds automatically — silently changing what is serving is what the chain exists to prevent |
| Deployment crash-loops | systemd backs off; marked `failed` after N restarts in a window; removed from its route; last 100 log lines captured |
| Deployment never becomes ready | Marked `failed` at the backend's `ready_timeout_s` |
| Two deployments claim one GPU | Rejected at the control plane; the agent double-checks and refuses, reporting a conflict |
| GPU falls off the bus | Agent reports; affected deployments marked `failed`; node flagged. **Never auto-rebooted** |
| WSL2 host rebooted, no logon task | The distribution never starts, so the node goes `stale` like any unreachable host. Preflight warned about this at install |
| NVIDIA driver installed inside WSL2 | CUDA passthrough breaks and `nvidia-smi` enumerates nothing. Preflight fails on it rather than letting deployments fail at start |
| Model origin becomes policy-denied | Existing deployments flagged, not stopped. Disabling is an explicit, audited decision |
| Node guardrail refuses an action | Recorded as a `refusal`, surfaced against the node, **not retried** — a limit being hit repeatedly is for an operator to see ([12](12-node-guardrails.md)) |
| A guardrail narrows under a running deployment | Reported `out_of_policy`; the deployment keeps running until withdrawn or the next maintenance window. Editing a config file never kills a model |
| `nodary node leave` run on a node | Deployments drain if reachable, then stop. Control plane marks it `departed` and removes it from every route |

## 3. Security controls

| Failure | Behaviour |
| :--- | :--- |
| **Egress verification fails** | Deployment marked non-compliant, removed from its route, critical alert. It is not silently left serving |
| Audit chain broken | `audit verify` reports the first bad sequence. The server keeps running and raises a critical alert — it does not stop serving, and it does not repair the chain |
| `intent_hash` mismatch at apply | Operation refused with `412`. The operator re-reads the current diff and re-attests |
| Bundle signature invalid | Install aborts. There is no override flag |
| Join token replayed | Rejected — tokens are single-use by default and burned on success |
| Unapproved node requests work | Receives an empty desired state. It can heartbeat; it cannot serve |

## 4. Gateway

| Failure | Behaviour |
| :--- | :--- |
| No ready deployment on a route | `503` with `Retry-After`; alert raised |
| LiteLLM unreachable | `502`. The gateway does not fall back to proxying deployments directly — that path would bypass routing and fallback logic |
| Stream terminates early | Metered from tokens observed, flagged `partial` ([06](06-gateway.md#3-metering)) |
| Token revoked mid-stream | Stream completes; the next request is rejected |
| Quota exceeded | `429` naming the limit, current usage, and reset time |

## 5. Recovery

| Situation | Procedure |
| :--- | :--- |
| Control plane host lost | Reinstall, `nodary backup restore`. Agents reconnect using existing certificates provided the CA key was in the backup ([08](08-data-model.md#4-secrets-at-rest)) |
| `secret.key` lost | Unrecoverable for encrypted material. Every agent must re-enroll and every TOTP enrollment must be redone. The audit chain remains readable and verifiable |
| Database corrupt | Restore from backup. The JSONL audit mirror is independent and survives database loss |
| Bad upgrade | Restore the pre-upgrade backup named in `nodary upgrade` output. Schema migrations are forward-only ([08](08-data-model.md#5-migrations)) |
| Node unrecoverable | `nodary node revoke`, reinstall, re-enroll. Staged weights on surviving disks can be adopted without restaging |
