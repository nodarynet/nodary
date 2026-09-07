# R3a — The gateway, and the closed metering record

**Slice of:** [R3](../tasks/R3-gateway.md) ·
**Tasks:** R3-01 – R3-06, R3-12, R3-15, R3-16 · **Status:** complete

[mvp §4](mvp.md#4-the-route)'s S6, and its note on the row is the whole point: *metering is
closed here or never*. Everything else in this slice can be revised later; the shape of the
usage record cannot, because the moment one customer exports one bundle containing one usage
row, its schema is a compatibility surface.

## 1. What "closed" means, and why it is the first decision

[pivot §3](pivot-cmmc.md) makes one structural guarantee: **nodary records that a request
happened, never what it said.** [0006_fleet.sql](../../internal/store/migrations/0006_fleet.sql)
already cashes that out — the `usage` table has no column for request or response content, and
the comment says there is not going to be one.

This slice is where that stops being a schema comment and becomes a property of running code,
because this slice is the first thing that ever sees a prompt.

**Decided.** The gateway holds the request body in memory only as long as it takes to proxy it,
and no code path exists that can put it anywhere else. Asserted by a test that fails if content
reaches the database or a log — R3-15 — built the same way as
[the audit seam's gate](../tasks/README.md#cross-cutting-constraints): a scan that fails CI,
not a review convention.

**Why a scan and not care.** The failure mode is not somebody deciding to log prompts. It is
`slog.Info("proxying", "body", body)` added at 2am to debug a streaming bug, in a package
where that has never been wrong before. A convention does not survive that; a failing build
does.

## 2. Metering happens on the gateway's side of LiteLLM, always

**Decided.** The gateway reads usage from the response it proxies, and writes the record
itself. LiteLLM is never asked to report usage, and its own logging stays off.

**Why.** [00 §7](../specs/00-overview.md#7-why-litellm-stays) has LiteLLM stateless with no
database precisely so that identity and accounting live in one place. Metering from LiteLLM
would mean either giving it a database — reintroducing the thing that arrangement exists to
avoid — or parsing its logs, which is the request-content surface
[pivot §3](pivot-cmmc.md) is trying to eliminate.

It also settles a question R3-07 will otherwise reopen: a stream that dies early is metered
from what the *gateway* observed, and the gateway is the only component that saw it.

## 3. Streaming: inject `include_usage`, and pass everything else through byte for byte

**Decided.** For a streaming request the gateway sets `stream_options.include_usage = true`,
then relays every chunk unmodified while watching for the final usage chunk.

**Why.** [06 §3](../specs/06-gateway.md#3-metering) requires the injection because
OpenAI-compatible streams omit usage without it. The "otherwise untouched" half is the part
worth being deliberate about: a gateway that re-serialises chunks is a gateway that changes
them, and the difference surfaces as a client library failing to parse a field nodary
round-tripped through a struct it does not fully model.

So the relay is byte-oriented. Chunks are *parsed* to find usage, and *forwarded* as received.

**Rejected — buffer the stream, meter at the end, then send.** Trivially correct accounting.
It destroys streaming, which is the reason the endpoint exists.

**Rejected — set `include_usage` only when the client did not.** Kinder to a client that set
it to false deliberately. A client can opt out of nodary's accounting by opting out of usage
reporting, which makes metering advisory.

**The cost, stated:** a client that set `include_usage: false` now receives a usage chunk it
did not ask for. That is a visible difference from stock OpenAI behaviour, and it is the
correct trade inside a boundary where the point is that usage is not optional.

## 4. `/v1/models` returns the caller's routes, not the fleet

**Decided.** The listing is filtered by the same allowlist that authorises a request, and a
route outside it is `403` rather than `404`.

**Why.** Both halves are [06 §2](../specs/06-gateway.md#2-authentication), and the reasoning
for the status code is given there: the route's existence is not a secret, and a misleading
error costs support time. The listing half matters more than it looks — a client that
discovers a model in `/v1/models` and then gets `403` on it has been told two different things
by the same server.

## 5. LiteLLM's configuration is generated, and its logging is pinned off and asserted

**Decided.** The gateway renders `litellm.yaml` from routes and deployments, with every
request-logging and callback setting explicitly disabled, and asserts the rendered file
carries those settings before it is used.

**Why.** [pivot §3](pivot-cmmc.md) makes LiteLLM a compliance surface. Inside a CUI boundary,
"LiteLLM began writing request bodies somewhere by default in a minor release" is an incident,
not a nuisance — and the failure is silent, because a config that omits a setting inherits
whatever the new default is.

Asserting the rendered output rather than trusting the renderer is the same principle as
[egress verification](../specs/03-agent.md#5-egress-isolation), and it is there for the same
reason: this is a control whose failure looks exactly like success.

**Rejected — document the required settings and check them at review.** Free. It is the
mechanism that has already failed twice in this codebase's short history, both times in
[egress](R4d-egress-isolation.md).

## 6. Limits are set here and enforced in R3-08, and the CLI says so

**Decided.** `nodary limits show|set` lands (R3-12). Throttling does not
([mvp §4](mvp.md#4-the-route) defers R3-08 – R3-10), and `limits set` says plainly that
nothing enforces what it just wrote.

**Why.** [mvp §3](mvp.md#3-stub-discipline)'s first rule: a stub is honest in its data. A verb
that stores a quota and returns success, on a system that will happily blow straight through
it, is the dishonest kind — an operator would reasonably believe a budget was in force.

## 7. The shape

| | |
| :--- | :--- |
| `internal/gateway` | The OpenAI surface, auth, the allowlist, the proxy, metering |
| `internal/gateway/litellm.go` | Rendering `litellm.yaml`, and asserting what it pins |
| `internal/usage` | Writing the closed record |
| `internal/cli/gateway.go` | `nodary gateway start` |
| `internal/cli/limits.go` | `nodary limits show|set`, `nodary usage show` |

## 8. Steps

- [x] The usage record: written through `internal/observed`'s rule, closed by construction
- [x] Bearer auth, the allowlist, `/v1/models`
- [x] The proxy, and metering from a non-streaming response
- [x] Streaming: inject `include_usage`, relay untouched, read the final chunk
- [x] `litellm.yaml` rendered with logging pinned off, and asserted
- [x] `nodary gateway start`, `nodary limits show|set`, `nodary usage show`
- [x] R3-15's scan: no path from a request body to storage
- [x] Run the real pinned LiteLLM against the generated configuration

## 9. Open items

- Throttling (R3-08 – R3-10), partial-stream metering (R3-07), failure behaviour (R3-11),
  retention roll-up (R3-13) and route round-robin (R3-14) are deferred by
  [mvp §4](mvp.md#4-the-route).
- Round-robin across ready members is LiteLLM's job in this arrangement; R3-14 is about the
  membership changing live, which needs the health signal R4c now produces.
