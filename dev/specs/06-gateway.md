# 06 — Gateway

## 1. Request path

```
client ──► nodary-gateway ──► data plane ──► deployment
           authenticate                      (spread over ready members)
           resolve user
           check quota
           proxy
           meter from usage
           record
```

nodary owns identity, quota, metering and audit. The data plane ([§7](#7-the-data-plane)) owns
OpenAI compatibility, routing, retries and fallbacks. Because identity lives in nodary, **the
data plane runs stateless behind a single credential** that is never exposed to clients, and
needs no database. Two implementations satisfy §7 — Bifrost, the default for a fresh install,
and LiteLLM — and the gateway does not know which is running.

The gateway serves the OpenAI surface: `/v1/chat/completions`, `/v1/completions`,
`/v1/embeddings`, `/v1/models`. `/v1/models` returns only the routes the calling user is
permitted to use — not the full fleet.

## 2. Authentication

Clients present `Authorization: Bearer nodary_sk_…`. The **kind is enforced**, not merely
expected: a personal token is refused here, because [02 §4](02-enrollment.md#4-token-types)
gives each prefix one purpose and a `pt` is the credential on an operator's workstation that
can also mutate the control plane. One leaked credential should not do both jobs.

The gateway:

1. Hashes the presented key and looks it up. Tokens are stored as SHA-256; plaintext is shown exactly once, at creation.
2. Rejects revoked, expired, and suspended-user tokens with `401`.
3. Applies the user's model allowlist; a request for a route outside it returns `403`, not `404` — the route's existence is not a secret, and a misleading error costs support time. **A user with no grants may call nothing**, which is what makes [07 §5](07-identity-audit.md#5-control-mapping)'s "least privilege by default" true: an empty allowlist meaning every route would leave the role as the only real control.
4. Records `last_used_at` for the token, which is what makes stale-credential cleanup possible.

## 3. Metering

Recorded per request: user, token id, route, resolved model, deployment, prompt tokens,
completion tokens, latency, status, whether it streamed, and whether accounting was partial.

### Streaming needs care

OpenAI-compatible streams omit usage unless `stream_options.include_usage` is set. The gateway
**injects it**, reads the final usage chunk, and passes the stream through otherwise untouched.
A client cannot opt out: opting out of usage reporting would be opting out of accounting, which
makes metering advisory. The cost is that a client which set `include_usage: false` receives a
usage chunk it did not ask for — a visible difference from stock behavior, and the right trade
inside a boundary where usage is not optional.

"Otherwise untouched" is byte-for-byte. Chunks are parsed to find usage and forwarded exactly
as received; a gateway that re-serialized them would be a gateway that changed them, and the
difference surfaces as a client library failing on a field nodary round-tripped through a
struct it does not fully model.

A stream that terminates early — client disconnect, network failure — is metered from the
tokens observed so far and flagged `partial`. It is never silently dropped: if disconnection
erased usage, metering would be trivially avoidable by disconnecting, and the quota system
would be decorative.

## 4. Throttling

Limits apply per user, per role, or globally, and are enforced with a token bucket.

| Limit | Unit |
| :--- | :--- |
| `rpm` | requests per minute |
| `tpm` | tokens per minute |
| `daily_tokens` | tokens per day, resetting at a configured UTC hour |
| `max_concurrent` | in-flight requests |

Exceeding a limit returns `429` with `Retry-After`. The response body names which limit was
hit and when it resets — a bare 429 tells a user nothing actionable.

Throttle events are **usage** records. *Changing* a limit is an **audit** record. The
distinction matters: one is telemetry about system behavior, the other is an administrative
act with an accountable author.

## 5. Failure behavior

| Condition | Response |
| :--- | :--- |
| No ready deployment on the route | `503`, `Retry-After`, alert raised |
| Deployment unhealthy mid-request | The data plane retries against another member; if none, `503` |
| Data plane unreachable | `502`; the gateway does not attempt to proxy directly to deployments |
| Deployment hangs rather than refuses | Retried away from per request until the next sync removes it — after LiteLLM's cooldown, or for up to a sync interval under Bifrost, whose open-source build tracks no member health ([ADR 0009](../adr/0009-bifrost-as-the-default-data-plane.md)) |
| Quota exceeded | `429` with limit, usage, and reset time |
| Token revoked mid-stream | Stream completes; the next request is rejected |

## 6. Error envelope

Uniform across gateway and API. `code` is stable and machine-readable; `message` is for humans.

```json
{"error": {"code": "quota_exceeded",
           "message": "daily token budget reached",
           "detail": {"limit": 1000000, "used": 1000420, "resets_at": "2026-08-29T00:00:00Z"},
           "request_id": "req_…"}}
```

`request_id` appears in the usage record and in the gateway log, so a user's report is
traceable to one row without guesswork.

## 7. The data plane

The process the gateway proxies to: a **separate, stateless, OpenAI-compatible router on the
control-plane host**, and the gateway does not know which implementation it is talking to. Two
exist — **Bifrost**, the default for a fresh install, and **LiteLLM**, the original
([ADR 0003](../adr/0003-litellm-as-data-plane.md),
[ADR 0009](../adr/0009-bifrost-as-the-default-data-plane.md)). `data_plane = "bifrost" |
"litellm"` in `/etc/nodary/server.toml` selects. It is deployment configuration in
[00 §1](00-overview.md#tool-versus-deployment)'s sense, like the bind address, and an upgrade
never changes it; a file without the key reads as `litellm`, because that is what every install
predating the key runs.

Whichever runs, the contract is the same, and each clause is a test against the real pinned
image rather than a reading of its documentation:

| | |
| :--- | :--- |
| **Rendered, never edited** | Its configuration is rendered by `nodary gateway sync` from routes and deployments — only members the fleet reports `ready` and not `disabled`, each with its weight — and rewritten whenever a route or deployment moves ([05 §5](05-catalog.md#5-routes)) |
| **Stateless** | No database, no persistent store, no configuration written through a UI or an API. Restarting it from the rendered file loses nothing, because nothing lives there |
| **Records nothing** | Every request-logging, content-logging, tracing, caching and callback setting is written explicitly off, even where off is the default, and the rendered bytes are asserted before the file is written and re-checked on the host. Inside the boundary [ADR 0006](../adr/0006-cui-boundary-and-fips.md) draws, a default that moved under an upgrade is an incident |
| **Loopback, one credential** | Bound to `127.0.0.1:4000`. It answers only with the credential the gateway holds in `gateway.env`; the client's own bearer never reaches it ([R3-04](../tasks/R3-gateway.md)). The credential exists in the clear in the rendered file and in `gateway.env`, both 0600, and the mode is the whole control ([08 §4](08-data-model.md#4-secrets-at-rest)). No unit passes it on a command line |
| **Names who served** | Its response tells the gateway which member of the route answered, so a usage row carries the deployment, node and GPU ([§3](#3-metering)). A response that does not say attributes nothing; the gateway never guesses |
| **Retries on another member** | A member that fails is retried on another before the client sees an error; when none remains, `503` ([§5](#5-failure-behavior)). The retry count and backoff are pinned in the rendered file, never inherited |
| **Restarted on what it loaded** | `gateway sync` restarts it when the running process started on a configuration other than the one rendered, recorded by digest under `/run/nodary`, not when the file changed ([R3-14](../tasks/R3-gateway.md)) |
| **Pinned and advised** | An image in the component manifest by digest ([ADR 0004](../adr/0004-release-artifacts-and-channels.md)), moved by `nodary upgrade`, named by the advisory feed |

What differs between implementations is confined to one place in the code: the renderer, the
assertion table, the unit, the image, the configuration file, and the field or header the
served member arrives in. The proxy, the metering, the throttle and the allowlist do not branch
on it. `nodary status` and `doctor` name which one is running.

Switching is an operator's act on the host: change `data_plane`, run `nodary upgrade`. It
writes the new unit, renders its configuration, stops the old unit and starts the new. The
gateway is not restarted, because nothing it holds changes.
