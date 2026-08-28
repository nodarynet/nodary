# 09 — HTTP API

All endpoints under `/api/v1`. Authentication is a session cookie or
`Authorization: Bearer nodary_pt_…`.

Mutating requests carry `X-Nodary-Justify` and, when policy requires it, `X-Nodary-TOTP`
([07](07-identity-audit.md#2-attestation)).

## 1. Surface

| Group | Endpoints |
| :--- | :--- |
| **Auth** | `POST /auth/login` · `POST /auth/logout` · `GET /auth/whoami` |
| **Nodes** | `GET /nodes` · `GET /nodes/{name}` · `POST /nodes/{name}/approve` · `POST /nodes/{name}/drain` · `POST /nodes/{name}/revoke` · `GET /nodes/{name}/verify-egress` |
| **Backends** | `GET /backends` · `GET /backends/{name}` · `POST /backends` · `DELETE /backends/{name}` · `POST /backends/{name}/build` · `GET /backends/{name}/build` ([04](04-backends.md#5-derived-images)) |
| **Models** | `GET /models` · `POST /models` · `GET /models/{id}` · `POST /models/{id}/enable` · `POST /models/{id}/disable` · `POST /models/{id}/restart` · `POST /models/{id}/stage` · `POST /models/{id}/unstage` · `DELETE /models/{id}` |
| **Deployments** | `GET /deployments` · `GET /deployments/{id}` · `GET /deployments/{id}/logs` |
| **Routes** | `GET /routes` · `GET /routes/{name}` · `PUT /routes/{name}` |
| **Users** | `GET /users` · `POST /users` · `PATCH /users/{id}` · `DELETE /users/{id}` |
| **Tokens** | `GET /tokens` · `POST /tokens` · `DELETE /tokens/{id}` · `POST /tokens/join` |
| **Limits** | `GET /limits` · `PUT /limits/{kind}/{id}` |
| **Usage** | `GET /usage?from&to&user&model&group_by` |
| **Audit** | `GET /audit?from&to&actor&action` · `GET /audit/verify` · `GET /audit/export?format=jsonl\|csv` |
| **Policy** | `GET /policy` · `POST /policy/apply` · `GET /policy/diff` |
| **Config** | `GET /revisions` · `GET /revisions/{seq}` · `POST /revisions/{seq}/rollback` · `GET /config/export` |
| **Agent** | `POST /enroll` · `GET /agent/desired` · `POST /agent/status` · `POST /agent/events` · `GET /agent/dist/{version}` ([03](03-agent.md)) |

Inference is served separately on the gateway port and mirrors the OpenAI surface
([06](06-gateway.md)).

## 2. Conventions

**Previews.** Every mutating endpoint accepts `?dry_run=true`, returning the rendered change
and its `intent_hash` without applying it. The subsequent real call sends
`X-Nodary-Intent: <hash>` and is refused if the re-rendered change no longer matches. This is
the mechanism behind attestation, and it is available to API clients, not only the CLI.

**Pagination.** List endpoints take `limit` (default 50, max 500) and `cursor`. Responses
carry `next_cursor` when more remain. Audit and usage listings are always ordered by sequence
or timestamp descending.

**Concurrency.** Mutating endpoints on a versioned object accept `If-Match` with the object's
current revision; a mismatch returns `409`. This prevents two administrators silently
overwriting one another.

**Idempotency.** `POST` endpoints accept `Idempotency-Key`. A repeat within 24h returns the
original response rather than acting twice.

## 3. Errors

Uniform envelope; `code` is stable and machine-readable, `message` is for humans.

```json
{"error": {"code": "backend_capability_unsupported",
           "message": "llama-cpp does not support tensor parallelism",
           "detail": {"backend": "llama-cpp", "requested": {"tensor_parallel": 4},
                      "hint": "use --tensor-split via extra_args"},
           "request_id": "req_…"}}
```

| Status | Used for |
| :--- | :--- |
| `400` | Malformed request |
| `401` | Absent, invalid, revoked or expired credential |
| `403` | Authenticated but not permitted — including a route outside the user's allowlist |
| `404` | Object does not exist |
| `409` | Conflict: `If-Match` mismatch, GPU already claimed, name in use |
| `412` | `X-Nodary-Intent` no longer matches the rendered change |
| `422` | Semantically invalid: capability unsupported, artifact/layout mismatch |
| `429` | Rate or budget limit, with `Retry-After` |
| `503` | No ready deployment on the route |

`403` rather than `404` for a disallowed route is deliberate: hiding existence buys nothing
here and costs support time.
