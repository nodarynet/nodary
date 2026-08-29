# R8 — Mutating web UI

**Deliverable:** mutating UI with attestation.
**Proves:** parity with the CLI.
· [00 §8](../specs/00-overview.md#8-milestones)

Deliverable level. Break these into tasks when R8 starts.

R8 adds no new capability. Every mutation it offers already exists as a core
function with an audit record, a preview and an `intent_hash`; R8 is a third
caller of the same seam ([R2-34](R2-control-plane.md)). If a task here needs a
new core function, that is a signal the seam was drawn wrong, not that the UI
needs an exception.

- [ ] **R8-01** The preview → `intent_hash` → apply flow in the browser, using the same `?dry_run=true` endpoints an API client uses · [09 §2](../specs/09-api.md#2-conventions)
  - *done:* a stale preview is refused with `412` and the operator re-reads the current diff and re-attests, exactly as on the CLI · [11 §3](../specs/11-failure-modes.md#3-security-controls)
- [ ] **R8-02** Justification capture, with `min_justification_length` enforced by the active profile · [07 §2](../specs/07-identity-audit.md#2-attestation)
- [ ] **R8-03** TOTP re-entry when `require_totp` is set
  - *done:* a live session does not satisfy it. A cookie proves someone logged in at some point; a re-entered code proves a person was present for this specific act
- [ ] **R8-04** Verb parity with the CLI across nodes, models, deployments, routes, users, tokens, limits and policy · [10 §1](../specs/10-cli.md#1-verbs)
- [ ] **R8-05** Destructive operations name their cost before asking · [05 §4](../specs/05-catalog.md#4-enable-and-disable)
  - *done:* `unstage` states the restaging cost; a rolling restart with fewer than two ready replicas requires the same explicit `--allow-downtime` decision the CLI requires · [03 §7](../specs/03-agent.md#7-gpu-assignment-health-restart-reboot)
- [ ] **R8-06** `If-Match` surfaced as a real conflict, not a silent overwrite, when two administrators act at once · [09 §2](../specs/09-api.md#2-conventions)
