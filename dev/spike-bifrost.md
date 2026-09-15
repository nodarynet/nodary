# Spike — Bifrost as a data plane

**Answers:** part of [R3b §2](plans/R3b-a-second-data-plane.md#2-the-spike-measured-before-anything-is-designed)'s
gate 2 · **Measured on:** `maximhq/bifrost:v2.1.1`,
`sha256:9e65eb4d0b292c25aaf46d194c705344f19c833a29e30155038bbe551eac7245`, 90 MB,
pulled 2026-09-15; docker 29.7.2 / overlayfs / WSL2

Throwaway work, kept as a memo. Everything below was run against the real image, not
reasoned about; the commands are given so each result can be reproduced or contradicted.

**Gate 3 is not yet run.** §1–§4 cover a question pulled forward because it can stop the
whole slice — whether a data plane inside a CUI boundary can be made to stop talking to its
vendor. §6 is gate 1, and it **chooses shape P and contradicts the rule R3b §3.3 wrote for
choosing**.

## 0. The plan's examples are a major version behind

[R3b §3.3](plans/R3b-a-second-data-plane.md#33-the-rendering-shape-is-the-spikes-to-choose)
and [ADR 0009](adr/0009-bifrost-as-the-default-data-plane.md) were written against v1
documentation. The current release is **v2.1.1**, and v2 moved configuration into a SQLite
store: an empty `-app-dir` gets `config.db` and `logs.db`, and there is no `config.json`
unless you write one.

**`config.json` is still read, and it still seeds the store.** That is the finding that
keeps §3.3's shape alive — a rendered file is still the source of truth, and the database is
derived from it:

```
{"message":"loading configuration from: /app/data/config.json"}
```

A `client` block asking for `enforce_auth_on_inference: true` and `enable_logging: false`
came back set on `GET /api/config`, and a `logs_store: {"enabled": false}` turned
`is_logs_connected` to `false`. The file wins.

Two smaller notes from the same run. The binary announces a JSON Schema at
`https://www.getbifrost.ai/schema` and warns on every start when `$schema` is absent — that
schema is the authoritative field list and is what the sections below were read from, rather
than the prose documentation. And `framework` is nested: the pricing fields live under
`framework.pricing`, and because that object is `additionalProperties: false`, a block with
the fields one level too high is **discarded in silence** — the defaults come back and
nothing says why.

## 1. On defaults, it will not start without the internet

This is the finding. Cold start, empty store, a network with no egress:

```sh
docker network create --internal spikenet
docker run -d --name bf --network spikenet -e APP_HOST=0.0.0.0 \
  -v "$PWD/data:/app/data" maximhq/bifrost:v2.1.1
```

```
{"level":"fatal","message":"failed to initialize pricing manager: failed to sync pricing
data: failed to load pricing data from URL and no existing data available: pricing URL
validation failed: failed to resolve hostname: lookup getbifrost.ai ... server misbehaving"}
```

Exit 1. Not degraded — refused. A site that installs behind an air gap, or whose control
plane simply has no route out, gets a data plane that never comes up, and the message names
DNS rather than a policy decision.

**"and no existing data available" is the whole of the difference.** The same directory
after one successful online start runs offline quite happily, because the fetches fall back
to what the store already holds:

```
{"level":"warn","message":"failed to fetch pricing from URL, falling back to existing
database records: ..."}
{"level":"error","message":"failed to load model parameters from URL, falling back to
existing database records: ..."}
{"level":"info","message":"successfully started bifrost, serving UI on http://0.0.0.0:8080"}
```

So the hazard is narrow and exact: **a cold start with no egress.** Which is every
air-gapped install, and every reinstall, and every `dev-reset.sh`.

## 2. Four outbound behaviors, and what turns each off

Read off the published schema, then set and confirmed on `GET /api/config`.

| Field | Default | Off switch | |
| :--- | :--- | :--- | :--- |
| `mcp_library_url` | `getbifrost.ai/mcp-library` | `mcp_library_sync_interval: 0` | the schema documents this as the air-gapped setting, and the URL also accepts `file://` |
| `live_models_sync_interval` | 3600 | `0` | **not phone-home** — it re-fetches each *provider's* `list-models`, which for nodary is a loopback backend |
| `pricing_url` | `getbifrost.ai/datasheet` | none by interval | `pricing_sync_interval` has `minimum: 3600` and no zero case, unlike the MCP one |
| `model_parameters_url` | `getbifrost.ai/datasheet/model-parameters` | none by interval | same |

The two without an interval switch are the two that make startup fatal. They are, however,
**URLs**, and that is the way out.

## 3. `file://` works, and the content is almost free

Cold start, empty store, `--internal` network, with the two URLs pointed at a file the
container already has mounted:

```json
"framework": { "pricing": {
  "pricing_url": "file:///app/data/pricing.json",
  "model_parameters_url": "file:///app/data/pricing.json",
  "mcp_library_url": "file:///app/data/pricing.json",
  "mcp_library_sync_interval": 0,
  "live_models_sync_interval": 0 } }
```

with `pricing.json` containing `{}`. Result:

```
fatal lines : 0
error lines : 0
mentions of getbifrost.ai anywhere in the log : 0
GET /health -> {"components":{"db_pings":"ok"},"status":"ok"}
```

**The content is nearly free because nodary does not use it.** The real datasheet is 2.3 MB
describing 4 760 *hosted* models — `ai21.j2-mid-v1`, `bedrock`, `dall-e-3` — and nodary
serves local weights on GPUs the site owns. An empty object satisfied the pricing manager.
Whether a stub or a trimmed copy is the right artifact is R3-19's to decide; what is settled
here is that the vendor round trip is not compulsory.

## 4. What this costs the plan

- **[§3.5](plans/R3b-a-second-data-plane.md#35-pinned-off-asserted-on-the-bytes-and-re-checked-on-the-host)'s
  pinned-off table gains a category.** It covers the config store, the logs store, content
  logging and callbacks — all of them "it might keep what it should not". `framework.pricing`
  is a different kind of entry: not what it retains but *where it reaches*, and the assertion
  walked over the rendered JSON has to cover both URLs and both intervals. A default that
  moves here is not an incident about content, it is an egress the boundary did not agree to.
- **R3-19 renders two files, not one.** `bifrost.json` and the stub datasheet beside it, both
  mounted read-only. Small, and currently unmentioned.
- **`additionalProperties: false` argues for asserting on the parsed document.** A
  misplaced block is accepted and ignored, so a renderer that is one level off produces a
  data plane on vendor defaults and a clean startup log. §3.5 already chose to walk the JSON
  rather than string-match it; this is the reason it was the right call.
- **ADR 0009 keeps its shape.** This is a gate 2 *finding* with a remedy, which is what §2
  says such a result should be, not a gate failure.

## 5. Open

- Gate 3 is unrun: whether the `vllm` provider type serves llama.cpp and TensorRT-LLM's
  OpenAI frontends unchanged, and the timeout numbers.
- `enforce_auth_on_inference` defaults to **false**, and `GET /api/config` answered 200 with
  no credential on a default install. Both are gate 2 items in their own right and are only
  noted here, not yet measured against
  [§3.4](plans/R3b-a-second-data-plane.md#34-the-credential-lives-where-litellms-does).
- `enable_logging` defaults to **true** with `disable_content_logging: false`. Turning the
  logs store off set `is_logs_connected: false`, but what the process does with content
  before that point is not yet measured.
- Whether the pricing scheduler, which "checks every 5m", ever retries the URL after a
  `file://` load — the run above was watched for minutes, not hours.

## 6. Gate 1 — both shapes report who served; only one of them fails over

Two upstreams behind one model name, each answering `served-by-a` / `served-by-b` so the
signal can be checked against the truth rather than taken on trust. Run from the pinned
LiteLLM image, the way
[`litellm_docker_test.go`](../internal/gateway/litellm_docker_test.go) already does.

### Both shapes carry an accurate signal

**Shape K** — one `vllm` provider, two keys, weights 3 and 1 — reports the key by name:

```
X-Bifrost-Routing-Info-Key: dep_tiny_gpu02        (also extra_fields.routing_info.key)
```

Over 40 requests the header named the upstream that actually answered **40 times out of 40**,
and the spread was 31/9 against a configured 3:1. Streaming carries it in the response header
*and* in every SSE chunk's `extra_fields`. On §2's decision table that is "a key-level
signal", which is the condition §3.3 wrote for choosing **K**.

**Shape P** — one custom provider per member, `base_provider_type: "openai"` — reports the
provider by name in the same places, equally accurate.

### And then a member dies

This is the finding. With one upstream stopped, **shape K returns the error to the client**:

| | |
| :--- | :--- |
| 4 of 12 | `502`, `routing_info.key: dep_tiny_gpu01`, after **10–17 seconds** |
| 3 of 12 | `200` — the share weighted to the healthy member anyway |
| 5 of 12 | still unanswered when the client gave up at 15 s |

`max_retries: 2` retried **the same key**. It never tried the other member. The schema says
why: the only fallback Bifrost has is `routing_rule.fallbacks`, "Fallback provider chain in
order" — and `load_balancer_config.append_fallbacks_to_pinned` likewise appends *providers*.
**Failover is provider-level; a key has nothing to fall back to.**

Shape P, same dead member, with the sibling named as a fallback:

```
HTTP/1.1 200 OK
X-Bifrost-Routing-Info-Provider: dep_tiny_gpu02          <- who served
X-Bifrost-Routing-Info-Is-Fallback: true                 <- that it was not the first choice
X-Bifrost-Routing-Info-Primary-Provider: dep_tiny_gpu01  <- who should have
X-Bifrost-Fallback-Index: 1
X-Bifrost-Upstream-Latency-Ms: 15684.390
```

with `served-by-b` in the body. Identical under streaming, in the header and in every chunk.

### What this does to §3.3's rule

[§3.3](plans/R3b-a-second-data-plane.md#33-the-rendering-shape-is-the-spikes-to-choose) says
"**K** if gate 1 finds a key-level signal", and prefers K *because* it "keeps member selection
in the component that owns retries, which is ADR 0003's split". Gate 1 finds a key-level
signal — and finds that the second half of that sentence is not true of this software.
Bifrost's retries stay inside a key; its failover crosses providers. A shape that puts every
member in one provider therefore cannot satisfy
[R3-14](tasks/R3-gateway.md)'s "retried on another member, not returned to the client", which
the rule assumed would come for free.

**So: shape P.** Not because K's signal was missing, but because K's *reason* was. P also
turns out to report strictly more — `is_fallback` and `primary_provider` say not just who
served but who was meant to, which is a distinction
[R3-21](tasks/R3-gateway.md)'s usage row can record and LiteLLM's single header cannot.

### Two numbers worth keeping

- **15.7 seconds** from request to fallback answer, against a member whose host had gone away
  entirely. That is [§7](plans/R3b-a-second-data-plane.md#7-open-items)'s hung-member window,
  measured rather than feared, and it is per request until `gateway sync` removes the member.
- `provider_response_headers` passes the upstream's own headers through
  (`{"X-Upstream-Name":"b"}`), which is a second attribution channel nodary does not need and
  should know exists.

### One trap found on the way

The first shape-K run failed every request with `502` and
`connection to private IP 172.19.0.2 is not allowed`. `network_config.allow_private_network`
defaults to **false** — RFC 1918 is refused — and the message reads like a fault rather than a
policy. Loopback is exempt "regardless of this setting", and
[`gatewaysync.go:293`](../internal/cli/gatewaysync.go) renders every member as
`http://127.0.0.1:<port>/v1`, so **nodary as it stands is unaffected**. It is recorded because
the day a member is addressed by anything but loopback, this is the error, and nothing in the
tree would explain it.
