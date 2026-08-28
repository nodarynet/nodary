# 06 — Gateway

## 1. Request path

```
client ──► nodary-gateway ──► LiteLLM ──► deployment
           authenticate                   (round-robin over ready members)
           resolve user
           check quota
           proxy
           meter from usage
           record
```

nodary owns identity, quota, metering and audit. LiteLLM owns OpenAI compatibility, routing,
retries and fallbacks. Because identity lives in nodary, **LiteLLM runs stateless behind a
single master key** that is never exposed to clients, and needs no database.

The gateway serves the OpenAI surface: `/v1/chat/completions`, `/v1/completions`,
`/v1/embeddings`, `/v1/models`. `/v1/models` returns only the routes the calling user is
permitted to use — not the full fleet.

## 2. Authentication

Clients present `Authorization: Bearer nodary_sk_…`. The gateway:

1. Hashes the presented key and looks it up. Tokens are stored as SHA-256; plaintext is shown exactly once, at creation.
2. Rejects revoked, expired, and suspended-user tokens with `401`.
3. Applies the user's model allowlist; a request for a route outside it returns `403`, not `404` — the route's existence is not a secret, and a misleading error costs support time.
4. Records `last_used_at` for the token, which is what makes stale-credential cleanup possible.

## 3. Metering

Recorded per request: user, token id, route, resolved model, deployment, prompt tokens,
completion tokens, latency, status, whether it streamed, and whether accounting was partial.

### Streaming needs care

OpenAI-compatible streams omit usage unless `stream_options.include_usage` is set. The gateway
**injects it**, reads the final usage chunk, and passes the stream through otherwise untouched.

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
distinction matters: one is telemetry about system behaviour, the other is an administrative
act with an accountable author.

## 5. Failure behaviour

| Condition | Response |
| :--- | :--- |
| No ready deployment on the route | `503`, `Retry-After`, alert raised |
| Deployment unhealthy mid-request | LiteLLM retries against another member; if none, `503` |
| LiteLLM unreachable | `502`; the gateway does not attempt to proxy directly to deployments |
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
