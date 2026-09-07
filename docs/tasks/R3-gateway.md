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

- [x] **R3-01** `nodary-gateway` process serving the OpenAI surface: `/v1/chat/completions`, `/v1/completions`, `/v1/embeddings`, `/v1/models` · [06 §1](../specs/06-gateway.md#1-request-path)
- [x] **R3-02** Bearer authentication resolving `nodary_sk_…` to a person; `401` for revoked, expired and suspended-user tokens; `last_used_at` recorded · [06 §2](../specs/06-gateway.md#2-authentication)
  - the **kind** is enforced, not just the credential: a personal token is refused here. [02 §4](../specs/02-enrollment.md#4-token-types) gives each prefix one purpose, and accepting a `pt` would make the credential on an operator's workstation — which can mutate the control plane — the same one any application holding an inference key uses
  - `last_used_at` goes through `internal/observed`, because an inference request authorises no act and so has no audited mutation for the touch to ride along with
- [x] **R3-03** Per-user model allowlist; a route outside it returns `403`, and `/v1/models` returns only permitted routes rather than the full fleet · [06 §2](../specs/06-gateway.md#2-authentication)
  - **a user with no grants may call nothing.** [07 §5](../specs/07-identity-audit.md#5-control-mapping) maps this to AC-3 and AC-6 with the words "least privilege by default", and an empty allowlist meaning *every* route would make that sentence false — it would leave the role grant as the only real control and the allowlist as a restriction somebody has to remember to opt into
  - the grant is in the configuration snapshot, so it is a revision like every other administrative decision, and it is keyed by user **name** so an export survives a rebuild where the same people have different ids
- [x] **R3-04** LiteLLM deployed stateless behind a master key, its configuration generated from routes and deployments · [06 §1](../specs/06-gateway.md#1-request-path)
  - proved against **the pinned image from `components.json`**, not a schema read from documentation: the real LiteLLM starts on the generated configuration, loads the route, and refuses `/v1/models` without the master key. R3-04's real risk was that the configuration is rejected, and nothing would have known until an install
  - the client's own `Authorization` never reaches LiteLLM. It identifies a person to nodary and means nothing upstream, and forwarding a credential past the component that consumed it is how a stateless proxy acquires an identity it should not have
- [x] **R3-05** Metering: user, token, route, resolved model, deployment, prompt and completion tokens, latency, status, streamed, partial · [06 §3](../specs/06-gateway.md#3-metering)
- [x] **R3-06** Streaming usage: inject `stream_options.include_usage`, read the final usage chunk, pass the stream through otherwise untouched · [06 §3](../specs/06-gateway.md#3-metering)
  - a client cannot opt out. Opting out of usage reporting would be opting out of nodary's accounting, which makes metering advisory — and the cost is stated: a client that set `include_usage: false` now receives a usage chunk it did not ask for
  - chunks are **scanned and forwarded, never re-serialised**, and the scanner carries a partial line across writes. Asserted against a stream delivered one byte at a time, which is the case that finds an accumulator that resets per write
- [ ] **R3-07** A stream that terminates early is metered from tokens observed and flagged `partial`
  - *done:* usage is never silently dropped on disconnect. If disconnection erased usage, metering would be trivially avoidable and the quota system decorative
  - *partial:* the **flag** lands with R3a — a stream that produced no usage chunk records `partial = 1` rather than a silent zero, so incomplete accounting says so. What remains is counting the tokens actually observed, which needs a tokenizer the gateway does not have
- [ ] **R3-08** Token-bucket throttling on `rpm`, `tpm`, `daily_tokens` and `max_concurrent`, per user, per role and globally · [06 §4](../specs/06-gateway.md#4-throttling)
- [ ] **R3-09** `429` carries `Retry-After` and a body naming which limit was hit, current usage and reset time
  - *done:* a bare 429 tells a user nothing actionable
- [ ] **R3-10** Throttle events are usage records; changing a limit is an audit record · [06 §4](../specs/06-gateway.md#4-throttling)
  - *done:* the two are never written to the same place — one is telemetry, the other an administrative act with an accountable author
- [ ] **R3-11** Gateway failure behaviour · [06 §5](../specs/06-gateway.md#5-failure-behaviour) · [11 §4](../specs/11-failure-modes.md#4-gateway)
  - *done:* no ready deployment → `503` + `Retry-After` + alert; LiteLLM unreachable → `502` with no direct-to-deployment fallback, because that path would bypass routing and fallback logic; token revoked mid-stream → the stream completes and the next request is rejected
- [x] **R3-12** `nodary limits show|set` and `nodary usage show` with `--user`, `--model`, `--node`, `--group_by`, `--from`, `--to`, `--format` · [10 §1](../specs/10-cli.md#1-verbs)
- [ ] **R3-13** Roll `usage` into `usage_daily` past `usage_retention_days` · [08 §3](../specs/08-data-model.md#3-retention)
- [ ] **R3-14** Route round-robin across ready members, with health-driven membership changes honoured live · [05 §5](../specs/05-catalog.md#5-routes)
- [x] **R3-15** The metering record schema is closed — no free-text body field exists to write into · [pivot §3](../plans/pivot-cmmc.md#the-guarantee-is-structural-not-documentary)
  - *done:* a test fails if request or completion content reaches the database or a log. "nodary records that a request happened, never what it said" is a structural guarantee, made unreachable in the same way as [the audit seam](README.md#cross-cutting-constraints) rather than merely discouraged
  - **two tests, because one would not be enough.** A canary prompt goes through the gateway — streaming, non-streaming, and two error paths — and every byte of the database, its write-ahead log and the gateway's log is searched for it. That proves today's code. A second test pins the record's field set and the table's column list, which proves there is nowhere to write one: a guarantee that depends on every future author remembering it is not structural
  - *deps:* R3-05
- [x] **R3-16** LiteLLM's configuration is rendered with request logging pinned off, and the pinning is asserted · [pivot §3](../plans/pivot-cmmc.md#litellm-is-now-a-compliance-surface)
  - *done:* asserted continuously rather than configured once, on the same principle as [egress verification](../specs/03-agent.md#5-egress-isolation). Inside a CUI boundary, "LiteLLM begins writing request bodies somewhere by default" is an incident rather than a nuisance
  - six settings plus three empty callback lists, each written explicitly **even where it is already the default**, because a configuration that omits a setting inherits whatever the next default is. `AssertLoggingOff` checks the rendered bytes rather than trusting the renderer, and the gateway calls it before using a configuration
  - *deps:* R3-04
