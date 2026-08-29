# R4 — Agent

**Deliverable:** enroll, long-poll, reconcile, systemd units, egress isolation, staging.
**Proves:** nodes run without an orchestrator.
· [00 §8](../specs/00-overview.md#8-milestones)

Deliverable level. Break these into tasks when R4 starts.

Node guardrails ([12](../specs/12-node-guardrails.md)) are not a milestone of
their own and land here: the agent checks the desired state against `node.toml`
before reconciling, so the check belongs with the reconcile loop. Adding it
afterwards would mean threading a refusal path through code written to assume it
never refuses. · [00 §8](../specs/00-overview.md#8-milestones)

## Enrollment and trust

- [ ] **R4-01** `POST /api/v1/enroll` — CSR plus join token returns a 90-day client certificate; the only unauthenticated agent endpoint · [02 §1](../specs/02-enrollment.md#1-flow)
- [ ] **R4-02** CA fingerprint pinning: the agent fetches the CA certificate on first contact and refuses it unless the fingerprint matches; `--ca-fingerprint` is required for a network install · [02 §1](../specs/02-enrollment.md#1-flow)
- [ ] **R4-03** Join tokens: `nodary token join --ttl --uses`, single-use by default, burned on success, minting audited · [02 §4](../specs/02-enrollment.md#4-token-types)
  - *done:* a replayed token is rejected · [11 §3](../specs/11-failure-modes.md#3-security-controls)
- [ ] **R4-04** Approval as a separate step: a `pending` node receives an empty desired state — it can heartbeat, it cannot serve · [02 §2](../specs/02-enrollment.md#2-why-approval-is-a-separate-step)
  - *done:* the approval record names the administrator, carries their justification, and records the node's advertised offer and constraints in the same record. Neither side can later claim terms the other did not see
- [ ] **R4-05** Certificate lifecycle: renewal at two-thirds of lifetime over the existing mTLS channel; a node offline past expiry must re-enroll · [02 §3](../specs/02-enrollment.md#3-certificate-lifecycle)
- [ ] **R4-06** `nodary node revoke` and node-side `nodary node leave` · [12 §5](../specs/12-node-guardrails.md#5-decommissioning)
  - *done:* `leave` works without the control plane being reachable — the common case is precisely that something has gone wrong

## Protocol

- [ ] **R4-07** `GET /api/v1/agent/desired?rev=N` long-poll, blocking up to 60s · [03 §1](../specs/03-agent.md#1-transport)
- [ ] **R4-08** The desired-state document: a complete end state, with no imperative commands anywhere in the protocol · [03 §2](../specs/03-agent.md#2-desired-state-document)
- [ ] **R4-09** `POST /api/v1/agent/status` every 15s — inventory, unit states, staging progress; node marked `stale` after 60s of silence · [11 §1](../specs/11-failure-modes.md#1-control-plane-and-agent)
- [ ] **R4-10** `POST /api/v1/agent/events` with a bounded queue that spills to disk; an overflow is itself recorded · [07 §3](../specs/07-identity-audit.md#3-the-audit-chain)
- [ ] **R4-11** Protocol version handling: an agent outside the server's supported range stops reconciling, keeps running what is already up, and reports `incompatible` · [03 §4](../specs/03-agent.md#4-version-skew)
  - *done:* it does not guess
- [ ] **R4-12** Reconnect behaviour: exponential backoff with jitter; on reconnect the agent reconciles forward and never replays intermediate revisions · [11 §1](../specs/11-failure-modes.md#1-control-plane-and-agent)

## Guardrails

- [ ] **R4-13** `/etc/nodary/node.toml` parsing; every field optional, an absent `[limits]` offering the whole machine · [12 §2](../specs/12-node-guardrails.md#2-the-file)
- [ ] **R4-14** `evaluate` runs before any side effect · [03 §3](../specs/03-agent.md#3-reconcile-loop)
  - *done:* an agent never partially applies a document it is going to refuse — a half-applied change is worse than a rejected one
- [ ] **R4-15** Refusals are recorded, surfaced against the node, and **not** retried · [12 §1](../specs/12-node-guardrails.md#1-where-they-apply)
  - *done:* a limit being hit repeatedly is something an operator sees, not something the system grinds against
- [ ] **R4-16** A guardrail narrowing under a running deployment reports `out_of_policy` and does not kill it · [12 §3](../specs/12-node-guardrails.md#3-editing-a-live-node)
  - *done:* editing a config file never terminates a serving model. A guardrail nobody dares touch is not a guardrail
- [ ] **R4-17** Reported inventory is the offer, not the machine: a four-GPU host offering three appears as a three-GPU node · [12 §4](../specs/12-node-guardrails.md#4-reported-inventory)

## Reconcile and runtime

- [ ] **R4-18** The reconcile loop: idempotent, convergent, observing actual state rather than assuming it caused it · [03 §3](../specs/03-agent.md#3-reconcile-loop)
  - *done:* the fixed ordering holds — weights before prepare, prepare before start, stop before weight removal, GPU released before reassignment
- [ ] **R4-19** `nodary-model@.service` template and `/etc/nodary/deployments/<id>.env`; the agent writes the env file and calls `systemctl` and holds no supervision logic of its own · [03 §6](../specs/03-agent.md#6-unit-template)
- [ ] **R4-20** Health polling every 10s; three consecutive failures mark `unhealthy` and remove the deployment from its route · [03 §7](../specs/03-agent.md#7-gpu-assignment-health-restart-reboot)
- [ ] **R4-21** Failure handling: crash-loop backoff, `failed` after N restarts in a window, last 100 log lines captured, `ready_timeout_s` enforced · [11 §2](../specs/11-failure-modes.md#2-models-and-deployments)
- [ ] **R4-22** Rolling restart that never drops the last ready replica; fewer than two replicas requires `--allow-downtime` · [03 §7](../specs/03-agent.md#7-gpu-assignment-health-restart-reboot)
- [ ] **R4-23** GPU assignment double-checked on the node before start; a conflict is refused and reported · [03 §7](../specs/03-agent.md#7-gpu-assignment-health-restart-reboot)
- [ ] **R4-24** `reboot_policy` detection and enforcement — `manual-console` for an encrypted root with no network unlock, `host-managed` on WSL2; the agent never initiates a reboot on either · [03 §7](../specs/03-agent.md#reboot-safety)
- [ ] **R4-25** A GPU falling off the bus marks affected deployments `failed` and flags the node, and **never** triggers an automatic reboot · [11 §2](../specs/11-failure-modes.md#2-models-and-deployments)

## Egress isolation

The mechanism matters more than the intent here: the obvious approach —
`IPAddressDeny=any` on the model unit — filters `nerdctl` rather than the model,
looks correct, reviews clean, and enforces nothing.
· [03 §5](../specs/03-agent.md#5-egress-isolation)

- [ ] **R4-26** Create the `nodary-isolated` CNI bridge network at install: host-local address, **no default route**, IP forwarding disabled, nftables dropping forwarded traffic from its subnet
- [ ] **R4-27** Publish deployment ports on `127.0.0.1` only
- [ ] **R4-28** `IPAddressDeny=any` retained on the unit as defence in depth, documented in place as constraining the launcher and not being the control
- [ ] **R4-29** `nodary node verify-egress` runs a probe inside a live deployment's namespace, asserting that a route off-box, a DNS lookup and a connection to a known-external address all fail
  - *done:* it runs after every deployment start and on demand; a failure marks the deployment non-compliant, removes it from its route and raises a critical alert. Given how easy this mechanism is to get subtly wrong, an assertion that runs continuously is worth more than any amount of configuration review
- [ ] **R4-30** Staging runs as a transient host unit with a narrow `IPAddressAllow=` list, outside the isolated namespace, exiting before the model unit starts · [03 §5](../specs/03-agent.md#staging-is-separate)
  - *done:* the systemd filter genuinely applies here, because the download is a direct child of the unit

## Catalog and staging

- [ ] **R4-31** `nodary model register` with provenance, licence, artifact kind and manifest · [05 §1](../specs/05-catalog.md#1-the-catalog)
- [ ] **R4-32** Origin checked against the active profile's allowlist and denylist, rejected at registration, rejection audited with actor and attempted origin · [05 §2](../specs/05-catalog.md#2-provenance-as-a-control)
  - *done:* a model whose origin later becomes denied flags existing deployments rather than stopping them; disabling is an explicit, audited decision
- [ ] **R4-33** `source: remote` staging — download to a temporary directory, verify against the manifest, atomically rename into place, resumable across agent restarts · [05 §3](../specs/05-catalog.md#3-staging)
  - *done:* a temporary directory is never renamed into place unverified; disk-full fails cleanly and removes the partial
- [ ] **R4-34** `source: local` staging — the air-gapped path, verified from the manifest and marked staged, as a first-class path rather than a workaround · [05 §3](../specs/05-catalog.md#3-staging)
- [ ] **R4-35** `corrupt` is terminal and requires explicit `nodary model restage`
  - *done:* nothing auto-repairs a failed verification, because a silent re-download is how a corrupt artifact becomes a permanent mystery
- [ ] **R4-36** `nodary model enable|disable|restart|stage|unstage|restage` and `nodary route list|show|set` · [05 §4](../specs/05-catalog.md#4-enable-and-disable)
  - *done:* `disable` leaves weights in place; removing them is the separate verb `unstage`, because the two have very different costs to undo
- [ ] **R4-37** Staging progress reported as bytes completed against total, and surfaced as a resumable, reportable task rather than something an operator watches over SSH
