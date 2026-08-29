# R7 — Read-only web UI

**Deliverable:** nodes, models, staging, usage, audit browser.
**Proves:** zero mutation, zero risk.
· [00 §8](../specs/00-overview.md#8-milestones)

Deliverable level. Break these into tasks when R7 starts.

R7 and R8 are polish. Stopping after [R6](R6-backends.md) is a complete outcome,
and nothing in R1–R6 depends on a frontend existing.

- [ ] **R7-01** Static asset serving from the binary, behind session authentication · [07 §1](../specs/07-identity-audit.md#1-users-and-roles)
- [ ] **R7-02** Fleet view: nodes with state, offer, constraints, `reboot_policy`, last seen, and refusals surfaced against the node · [12 §1](../specs/12-node-guardrails.md#1-where-they-apply)
  - *done:* `manual-console` and `host-managed` reboot policies are displayed prominently, and a WSL2 node shows whether a logon task exists to bring it back · [03 §7](../specs/03-agent.md#reboot-safety)
- [ ] **R7-03** Deployments and their health, with GPU topology from `nvidia-smi topo -m` shown so an operator can see which index sets are sensible · [03 §7](../specs/03-agent.md#7-gpu-assignment-health-restart-reboot)
- [ ] **R7-04** Catalog and staging progress — bytes completed against total, resumable state, `corrupt` visible and terminal · [05 §3](../specs/05-catalog.md#3-staging)
- [ ] **R7-05** Usage views over `usage` and `usage_daily`, by user, model and node · [06 §3](../specs/06-gateway.md#3-metering)
- [ ] **R7-06** Audit browser with filters matching `audit list`, and the chain's verification status shown rather than assumed · [07 §3](../specs/07-identity-audit.md#3-the-audit-chain)
- [ ] **R7-07** The active policy profile displayed on every relevant screen · [07 §4](../specs/07-identity-audit.md#4-policy-profiles)
- [ ] **R7-08** Non-compliant deployments and `out_of_policy` states shown as first-class status, not buried · [03 §5](../specs/03-agent.md#5-egress-isolation)
