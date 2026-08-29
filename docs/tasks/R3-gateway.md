# R3 — Gateway

**Deliverable:** auth, metering, throttling, LiteLLM stateless behind it.
**Proves:** tokens and usage.
· [00 §8](../specs/00-overview.md#8-milestones)

Deliverable level. Break these into tasks when R3 starts — R2 will have moved
some of the ground underneath.

nodary owns identity, quota, metering and audit; LiteLLM owns OpenAI
compatibility, routing, retries and fallbacks. Because identity lives in nodary,
LiteLLM runs stateless behind a single master key never exposed to clients, and
needs no database of its own. · [00 §7](../specs/00-overview.md#7-why-litellm-stays)

- [ ] **R3-01** `nodary-gateway` process serving the OpenAI surface: `/v1/chat/completions`, `/v1/completions`, `/v1/embeddings`, `/v1/models` · [06 §1](../specs/06-gateway.md#1-request-path)
- [ ] **R3-02** Bearer authentication resolving `nodary_sk_…` to a person; `401` for revoked, expired and suspended-user tokens; `last_used_at` recorded · [06 §2](../specs/06-gateway.md#2-authentication)
- [ ] **R3-03** Per-user model allowlist; a route outside it returns `403`, and `/v1/models` returns only permitted routes rather than the full fleet · [06 §2](../specs/06-gateway.md#2-authentication)
- [ ] **R3-04** LiteLLM deployed stateless behind a master key, its configuration generated from routes and deployments · [06 §1](../specs/06-gateway.md#1-request-path)
- [ ] **R3-05** Metering: user, token, route, resolved model, deployment, prompt and completion tokens, latency, status, streamed, partial · [06 §3](../specs/06-gateway.md#3-metering)
- [ ] **R3-06** Streaming usage: inject `stream_options.include_usage`, read the final usage chunk, pass the stream through otherwise untouched · [06 §3](../specs/06-gateway.md#3-metering)
- [ ] **R3-07** A stream that terminates early is metered from tokens observed and flagged `partial`
  - *done:* usage is never silently dropped on disconnect. If disconnection erased usage, metering would be trivially avoidable and the quota system decorative
- [ ] **R3-08** Token-bucket throttling on `rpm`, `tpm`, `daily_tokens` and `max_concurrent`, per user, per role and globally · [06 §4](../specs/06-gateway.md#4-throttling)
- [ ] **R3-09** `429` carries `Retry-After` and a body naming which limit was hit, current usage and reset time
  - *done:* a bare 429 tells a user nothing actionable
- [ ] **R3-10** Throttle events are usage records; changing a limit is an audit record · [06 §4](../specs/06-gateway.md#4-throttling)
  - *done:* the two are never written to the same place — one is telemetry, the other an administrative act with an accountable author
- [ ] **R3-11** Gateway failure behaviour · [06 §5](../specs/06-gateway.md#5-failure-behaviour) · [11 §4](../specs/11-failure-modes.md#4-gateway)
  - *done:* no ready deployment → `503` + `Retry-After` + alert; LiteLLM unreachable → `502` with no direct-to-deployment fallback, because that path would bypass routing and fallback logic; token revoked mid-stream → the stream completes and the next request is rejected
- [ ] **R3-12** `nodary limits show|set` and `nodary usage show` with `--user`, `--model`, `--node`, `--group_by`, `--from`, `--to`, `--format` · [10 §1](../specs/10-cli.md#1-verbs)
- [ ] **R3-13** Roll `usage` into `usage_daily` past `usage_retention_days` · [08 §3](../specs/08-data-model.md#3-retention)
- [ ] **R3-14** Route round-robin across ready members, with health-driven membership changes honoured live · [05 §5](../specs/05-catalog.md#5-routes)
