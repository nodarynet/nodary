# R2 — Control plane

**Deliverable:** SQLite state, HTTP API, revisions, CLI against it.
**Proves:** state has one owner.
· [00 §8](../specs/00-overview.md#8-milestones)

R2 turns R1's local database into the control plane: the full schema, an HTTP API
over it, and configuration revisions. The fleet objects are created here as
*state* — nodes, models, deployments and routes become rows and endpoints. Nothing
in R2 talks to a node or serves inference; that is [R4](R4-agent.md) and
[R3](R3-gateway.md).

The load-bearing constraint is R2-34: the CLI and the API must call the same core
functions. Every endpoint added here is a chance to grow a second implementation
by accident.

## Schema

Each task is the migration plus the type, its state machine where it has one, and
the constraints that keep it honest. · [08 §1](../specs/08-data-model.md#1-schema)

- [ ] **R2-01** `node` — inventory, offer, constraints, `reboot_policy`, states `pending → approved → ready → draining → departed` · [00 §3](../specs/00-overview.md#3-object-model)
- [ ] **R2-02** `refusal` — a node's rejection of a desired-state document, against node and revision · [12 §1](../specs/12-node-guardrails.md#1-where-they-apply)
- [ ] **R2-03** `backend` and `derived_image` · [04 §9](../specs/04-backends.md#9-registering-a-backend)
- [ ] **R2-04** `model` and `staging`, keyed `(model_id, node_name)`, states `absent → staging → verifying → staged | corrupt` · [05 §3](../specs/05-catalog.md#3-staging)
- [ ] **R2-05** `deployment`, states `defined → staging → preparing → starting → ready → stopped | failed`
- [ ] **R2-06** `route` and `route_member`
- [ ] **R2-07** `limits` keyed `(subject_kind, subject_id)` · [06 §4](../specs/06-gateway.md#4-throttling)
- [ ] **R2-08** `usage` and `usage_daily`
  - *done:* usage is a separate chain from audit and is never conflated with it — different volumes, different retention · [00 §3](../specs/00-overview.md#3-object-model)
- [ ] **R2-09** `policy` and `join_token`
- [ ] **R2-10** No two deployments on a node may claim the same GPU index
  - *done:* rejected at the control plane with `409` · [11 §2](../specs/11-failure-modes.md#2-models-and-deployments)
  - *deps:* R2-01, R2-05

## Revisions

- [ ] **R2-11** `revision`: monotonic sequence, full snapshot, author, justification, hash-chained to its predecessor · [08 §2](../specs/08-data-model.md#2-revisions-replace-version-control)
  - *done:* every configuration change writes one; the chain verifies the same way the audit chain does
  - *deps:* R1-06, R2-01
- [ ] **R2-12** `nodary config show|diff|rollback|export|apply` · [10 §1](../specs/10-cli.md#1-verbs)
  - *done:* `export` emits canonical TOML that `apply -f` reads back; the database stays authoritative and the file is a convenience
  - *deps:* R2-11
- [ ] **R2-13** A rollback is itself a new revision
  - *done:* history is append-only; nothing is ever rewritten
  - *deps:* R2-12
- [ ] **R2-14** Retention and pruning as a periodic task · [08 §3](../specs/08-data-model.md#3-retention)
  - *done:* pruning writes an audit record naming the range removed, and refuses to prune `audit` below the active profile's floor. A retention job that silently deletes evidence is indistinguishable from tampering
  - *deps:* R1-26, R2-08, R2-11

## HTTP layer

- [ ] **R2-15** HTTP server, TLS from `/etc/nodary/server.toml`, routes under `/api/v1` · [09](../specs/09-api.md)
- [ ] **R2-16** Authentication: session cookie or `Authorization: Bearer nodary_pt_…`
  - *done:* short-lived signed session cookies honour `session_ttl_minutes`
  - *deps:* R1-21, R1-26
- [ ] **R2-17** The uniform error envelope and the full status-code table · [09 §3](../specs/09-api.md#3-errors)
  - *done:* `code` is stable and machine-readable; a route outside the caller's allowlist returns `403`, not `404`
- [ ] **R2-18** `?dry_run=true` returns the rendered change and its `intent_hash` without applying · [09 §2](../specs/09-api.md#2-conventions)
  - *done:* attestation is available to API clients, not only the CLI
  - *deps:* R1-13
- [ ] **R2-19** `X-Nodary-Intent` enforcement — refuse with `412` when the re-rendered change no longer matches
  - *deps:* R1-14, R2-18
- [ ] **R2-20** `X-Nodary-Justify` and `X-Nodary-TOTP` on mutating requests · [09](../specs/09-api.md)
  - *deps:* R1-15, R1-16
- [ ] **R2-21** Pagination: `limit` (default 50, max 500), `cursor`, `next_cursor` · [09 §2](../specs/09-api.md#2-conventions)
- [ ] **R2-22** `If-Match` on versioned objects, `409` on mismatch
  - *done:* two administrators cannot silently overwrite one another
- [ ] **R2-23** `Idempotency-Key`: a repeat within 24h returns the original response rather than acting twice
- [ ] **R2-24** Request IDs threaded from request through audit and usage records · [06 §6](../specs/06-gateway.md#6-error-envelope)
  - *done:* a user's report of one bad request resolves to one row without guesswork

## Endpoints

Grouped as [09 §1](../specs/09-api.md#1-surface) groups them. Each depends on
R2-34 rather than reimplementing behaviour.

- [ ] **R2-25** Auth — `POST /auth/login`, `POST /auth/logout`, `GET /auth/whoami`
- [ ] **R2-26** Nodes — list, show, `approve`, `drain`, `revoke`, `verify-egress`
  - *note:* `verify-egress` returns the stored result in R2; the probe itself lands in [R4](R4-agent.md)
- [ ] **R2-27** Backends — list, show, create, delete, `build`, build status
- [ ] **R2-28** Models — list, register, show, `enable`, `disable`, `restart`, `stage`, `unstage`, delete
- [ ] **R2-29** Deployments — list, show, `logs`
- [ ] **R2-30** Routes — list, show, `PUT /routes/{name}`
- [ ] **R2-31** Users, tokens and limits — including `POST /tokens/join`
  - *deps:* R1-23, R1-24
- [ ] **R2-32** Usage — `GET /usage?from&to&user&model&group_by`
  - *deps:* R2-08
- [ ] **R2-33** Audit, policy and config — listing, `verify`, `export`, `apply`, `diff`, revisions, rollback
  - *deps:* R1-09, R1-11, R1-28, R2-12

## The shared core

- [ ] **R2-34** One set of core functions behind both the CLI and the API · [10 §1](../specs/10-cli.md#1-verbs)
  - *done:* a behavioural difference between `nodary model enable …` and `POST /models/{id}/enable` is impossible by construction, because neither holds business logic. This is a constraint on the implementation, not an aspiration — and it is cheapest to satisfy now, while there are two callers rather than three
  - *deps:* R1-12

## Server lifecycle

- [ ] **R2-35** `/etc/nodary/server.toml` — bind address, TLS certificate paths, data directory · [01 §12](../specs/01-install.md#12-filesystem-layout)
- [ ] **R2-36** `nodary server install|start|stop|status` · [10 §1](../specs/10-cli.md#1-verbs)
  - *note:* R2 covers the lifecycle verbs against an already-provisioned host; the full interactive install with preflight and component resolution is [R5](R5-install.md)
- [ ] **R2-37** `nodary backup create|restore` · [08 §4](../specs/08-data-model.md#4-secrets-at-rest)
  - *done:* `secret.key` is captured by default, the command refuses a world-readable destination, and the output states plainly that a database backup without the key is useless. The inverse is the real risk — an operator who backs up only the database discovers at restore time that every agent must re-enroll
  - *deps:* R1-04
- [ ] **R2-38** `nodary status` and `nodary restart` · [10 §1](../specs/10-cli.md#1-verbs)
- [ ] **R2-39** Self-signed certificate generation with the fingerprint printed · [01 §5](../specs/01-install.md#self-signed-control-planes)
  - *done:* the printed form includes the `--pinnedpubkey` variant of the node install command
- [ ] **R2-40** The internal CA that signs agent certificates, unrelated to the server's public TLS certificate · [01 §4](../specs/01-install.md#4-server-install)
  - *done:* the CA private key is encrypted at rest under `secret.key`
  - *deps:* R1-04
- [ ] **R2-41** A network audit sink — Elastic, Splunk HEC, or a generic NDJSON endpoint · [07 §3](../specs/07-identity-audit.md#3-the-audit-chain)
  - *done:* an implementation of R1-08's `Sink` and nothing else changes; the endpoint, credentials and TLS settings come from `server.toml` with the credential sealed under `secret.key`, and a destination that fell behind is re-synced with `audit export --from-seq` rather than by replaying from a queue
  - *note:* deferred out of [R1b](../plans/R1b-audit-chain.md) deliberately. Shipping records to a SIEM with WORM retention is what a CMMC deployment needs and no MVP install does, and its configuration has nowhere to live until R2-35. The seam, the per-record `install` id and the `v` field that lets the record shape grow all land in R1-08 so this stays additive
  - *deps:* R1-08, R2-35, R1-04
