# ADR 0009 — Bifrost as the default data plane, LiteLLM retained

**Status:** Accepted · **Date:** 2026-09-15 ·
**Amends:** [ADR 0003](0003-litellm-as-data-plane.md) ·
**Settles the reconsider-if in:** [ADR 0003](0003-litellm-as-data-plane.md)

Accepted on the spike in [R3b §2](../plans/R3b-a-second-data-plane.md#2-the-spike-measured-before-anything-is-designed)
passing its three gates, and not before. [ADR 0008](0008-container-runtime.md) was written after
its measurements; this one was written before them, and said so rather than reading as though
the measurements were in.

**All three gates have now run** ([the spike](../spike-bifrost.md)), against v2.1.1 rather
than the v1 documentation this was written from. **None of them fails**, so this is Accepted —
with one cost this ADR did not originally price, paid deliberately and recorded below.

**Gate 1 chose shape P** — not the shape §3.3's rule pointed at. Both shapes name who served,
accurately; only one fails over, because Bifrost retries inside a key and falls back only
between providers. §2's `max_retries` row is corrected below.

**Gate 2** found the data plane reaches its vendor on a timer and on defaults **refuses to
start** without that reach, both pinned in §2's table below and both closed by `file://` URLs.

**Gate 3** found the dialect survives — chat, streamed chat, `/v1/completions`, tool calls and
embeddings all pass through against a real backend — and found that **this release has no
`vllm` provider type**, only the generic `openai` custom type, which is sufficient.

**The cost, from [§7.10](../spike-bifrost.md): the config store is not optional.**
`enforce_auth_on_inference` is inert without it — the auth middleware is skipped outright and
the admin API answers unauthenticated — so the credential §3 gives the data plane cannot be
enforced from the rendered file alone. §2's "config store: off" row becomes "on, on a SQLite
file under `/var/lib/nodary/bifrost/`, holding provider configuration and keys and no content",
and that directory joins the set [R3-15](../tasks/R3-gateway.md)'s canary is searched for
across. **Paid rather than avoided**, because the alternative is a data plane on loopback that
anything local can call without a credential, and an admin API beside it — which is a worse
trade than one more directory inside a boundary the canary already sweeps.

## Context

[ADR 0003](0003-litellm-as-data-plane.md) chose LiteLLM as the data plane and named the terms
on which to reconsider: if its direction diverged from nodary's needs, or if pinning its
logging off proved insufficient. Neither has happened. What has happened is that the
arrangement has run for a milestone, and the cost of that particular process has been priced
by the work of keeping it in line:

- It is a Python service in a **1.64 GB** image (the pinned
  `ghcr.io/berriai/litellm@sha256:20b5044…`, measured on the development host) on a host whose
  every other nodary service is one static binary. The control plane carries containerd, runc
  and nerdctl *for it* — the note in [`components.json`](../../internal/components/components.json)
  says so in as many words.
- The one thing the gateway needs from it beyond OpenAI compatibility — which member of a route
  served a request — arrives in a header nobody promised ([R3-05](../tasks/R3-gateway.md)),
  asserted against the pinned image on every build because a version bump could drop it.
- Six logging settings and three empty callback lists are written explicitly and asserted on
  the rendered bytes ([R3-16](../tasks/R3-gateway.md)), because its defaults include writing
  request content, and inside the boundary [ADR 0006](0006-cui-boundary-and-fips.md) draws a
  default that moves is an incident.
- Its retry, cooldown and spread behaviors are `router_settings` pinned against whatever a
  future release defaults them to ([R3-14](../tasks/R3-gateway.md)).

None of that is a defect in LiteLLM. It is the cost of a third-party process in the data path,
and the question is whether a different process costs less.

**Bifrost** ([github.com/maximhq/bifrost](https://github.com/maximhq/bifrost)) is an
OpenAI-compatible gateway written in Go under Apache-2.0, by a single vendor (Maxim AI, H3 Labs
Inc.). Verified against its documentation and repository on 2026-09-15, not recalled:

| | |
| :--- | :--- |
| Runs stateless from one file | `config_store.enabled: false` and `logs_store.enabled: false` — "for headless, GitOps-friendly deployments without database persistence", in upstream's words |
| Ships as a digest-pinnable image | `maximhq/bifrost`, tags `vX.Y.Z`, `linux/amd64` and `linux/arm64`, about 77 MB |
| Covers the surface ADR 0003 refused to reimplement | streaming, tool calls, the Responses API, error mapping, retries with backoff, per-request fallbacks, weighted spread across several upstream URLs for one model |
| Speaks to what nodary runs | first-class `vllm` and `sgl` providers with a URL per key; a generic OpenAI-compatible provider for llama.cpp and TensorRT-LLM's frontends |
| Has a record-nothing configuration | but not by default — its logging plugin is on in gateway mode and stores complete prompts and responses to SQLite. §2 |
| Publishes benchmarks against LiteLLM | about 1 ms of overhead against 40 ms, 120 MB against 372 MB, at 500 requests per second on a two-vCPU instance with a 60 ms mock upstream. §5 |

## Decision

**Bifrost becomes the default data plane for a fresh install. LiteLLM remains an
implementation an operator can select. Both sit behind one contract,
[06 §7](../specs/06-gateway.md#7-the-data-plane), and the gateway does not know which is
running.**

ADR 0003's split is unchanged, and is the point: nodary owns identity, quota, metering and
audit; the data plane owns OpenAI compatibility, routing, retries and fallbacks; it runs
stateless, behind one credential the gateway holds, on loopback, with no database and no
record of content.

### 1. As an image, pinned by digest, in the manifest — the shape LiteLLM already has

Bifrost publishes three things: the image; an npm wrapper that downloads a binary at install
time; and static binaries served from `downloads.getmaxim.ai`, a Cloudflare R2 bucket. **The
binaries carry no checksum and no signature.** The release workflow generates none, GitHub
Releases holds only source archives, and the npm wrapper verifies nothing it downloads.

[ADR 0004](0004-release-artifacts-and-channels.md) pins every component by a digest from the
project that builds it. The only Bifrost artifact that is content-addressed is the image, so
that is what the manifest carries: `kind: image`, `roles: [server]`, `group: core`, beside
LiteLLM's entry, pulled by digest by the runtime the control plane already has. The unit is
`nodary-bifrost.service`, `nerdctl run --network host` for the reason
[R5-29](../tasks/R5-install.md) gives — a deployment publishes on the host's loopback — bound
to **`127.0.0.1:4000`**, the same address LiteLLM binds, so `--upstream`'s default and the
gateway do not move.

A static binary would have let the control plane drop the container runtime for the data
plane. It cannot, yet: without a published digest, nodary would be pinning the hash of
whatever it downloaded first, which is trust-on-first-use dressed as a pin. And containerd
stays on the control plane regardless — derived images ([04 §5](../specs/04-backends.md))
build there.

### 2. Not used, and pinned off: everything Bifrost offers that nodary already owns or forbids

Bifrost ships with a logging plugin enabled in gateway mode that stores complete prompts and
responses to a SQLite file; a config store, also SQLite, that its web UI and admin API write
to; a governance layer of virtual keys, budgets, rate limits, teams and customers; an
OpenTelemetry exporter whose spans carry the full chat history; a semantic cache; and an MCP
gateway that executes tools. Every one is a place content can land, or an identity nodary
would not hold.

The rendered configuration turns each off explicitly, even where off is the default, and the
rendered bytes are asserted before the file is written — R3-16's rule with a second table,
because the failure looks exactly like success:

| Setting | Pinned | Because |
| :--- | :--- | :--- |
| `config_store.enabled` | **`true`**, on a SQLite file under `/var/lib/nodary/bifrost/` | it was `false` here until [§7.10](../spike-bifrost.md) measured what that costs: **the auth middleware is skipped outright without it**, so `enforce_auth_on_inference` below is inert and the admin API answers unauthenticated. The store holds provider configuration and keys and no content, the rendered file stays the source of truth (it seeds the store on every start), and the directory joins the set [R3-15](../tasks/R3-gateway.md)'s canary is searched for across |
| `logs_store.enabled` | `false` | the logging plugin stores complete prompts and responses by default. This is the setting whose default is the incident |
| `client.disable_content_logging` | `true` | belt over braces: if a logs store ever appears, it holds metadata only |
| `client.enforce_auth_on_inference` | `true` | the data plane answers only the gateway (§3). Inert without the config store above, which is why that row moved |
| `plugins` | none | a plugin is how content leaves the process — `otel`, `maxim`, `datadog` and `semantic_cache` each do |
| `mcp` | absent | a tool executor in the data path is a new capability, never a default |
| `governance.auth_config.is_enabled` | `true`, under a credential nobody keeps | Bifrost has no switch that removes its dashboard and admin API, and both are open until an administrator exists. On loopback, locked under a password rendered and recorded nowhere, they are off in effect |
| `providers.*.network_config.max_retries` | `2` | the default is `0`. **It does not satisfy [R3-14](../tasks/R3-gateway.md) on its own**: measured, a retry re-tries the same key and a dead member returns `502` to the client. "Another member" is a *fallback*, which is provider-level — the reason [the spike](../spike-bifrost.md#6-gate-1--both-shapes-report-who-served-only-one-of-them-fails-over) chose shape P |
| `providers.*.network_config.allow_private_network` | left `false` | the default refuses RFC 1918, and loopback is exempt regardless. `gatewaysync.go` renders every member on `http://127.0.0.1:<port>`, so nothing needs it — recorded because the error when it does bite names an IP rather than a policy |
| `providers.*.network_config.default_request_timeout_in_seconds` | pinned | a generation takes minutes, and the default is **300 s** — [measured](../spike-bifrost.md#76-the-numbers-gate-3-asked-for), not read off documentation, because `GET /api/providers` reports `0` for it, meaning *unset*. Five minutes holding a request for a member that will never answer, against a 15.7 s fallback window |
| `providers.*.network_config.stream_idle_timeout_in_seconds` | pinned | default `120` per the schema, echoed nowhere by the running process |
| `client.compat.convert_text_to_chat` | `true` | `/v1/completions` ([06 §1](../specs/06-gateway.md#1-request-path)) is served **by this shim**, not natively — [§7.2](../spike-bifrost.md). A default that turns off is a route that stops answering |
| `client.compat.should_drop_params` | `false` | it defaults `true`: a parameter Bifrost does not recognize is **dropped**, not passed and not refused. In front of backends whose vocabularies [04 §3](../specs/04-backends.md#3-normalize-the-few-pass-through-the-rest) deliberately does not normalize, silent loss between the gateway and the engine |
| `framework.pricing.pricing_url`, `.model_parameters_url`, `.mcp_library_url` | `file://` paths into the rendered directory | **measured, not read off documentation.** On defaults these are fetched from `getbifrost.ai`, and on a cold start with no egress the process exits 1 rather than degrading. [The spike](../spike-bifrost.md#1-on-defaults-it-will-not-start-without-the-internet) |
| `framework.pricing.mcp_library_sync_interval`, `.live_models_sync_interval` | `0` | the schema names `0` as the air-gapped setting for the first. The second re-fetches each *provider's* model list, which for nodary is a loopback backend, and is off because nothing here changes between renders |

Governance in particular: Bifrost's virtual keys, budgets and rate limits duplicate
[06 §2–§4](../specs/06-gateway.md) and are held in memory per process, so they would be a
second, unaudited ledger that a restart forgets, beside the one nodary keeps. ADR 0003's
argument applies unchanged.

### 3. One credential, as today

Bifrost enforces no inference authentication by default. Left so, any process on the
control-plane host could reach the data plane past nodary's allowlist, quota and metering with
no credential at all — a regression on the control [08 §4](../specs/08-data-model.md#4-secrets-at-rest)
describes. So inference authentication is enforced, and one virtual key rendered into the
configuration and held in `gateway.env` is the credential. Both files are 0600 and the mode is
the whole control, exactly as for LiteLLM's master key. The word in 08 §4 changes; the sentence
does not.

### 4. Attribution is a gate, not a hope

[R3-05](../tasks/R3-gateway.md) attributes every usage row to the deployment, node and GPU
that served it, through a header LiteLLM returns. Bifrost's documentation names no response
signal identifying the key or provider that served a request. That is the spike's first gate:
either Bifrost can be made to say which member served, streamed and not, or the gateway
chooses the member itself and tells Bifrost, or this ADR is not accepted. A data plane that
cannot say who served a request breaks per-node chargeback, which R3-05 recorded as "most of
what metering is for at this size."

### 5. What Bifrost's speed is worth here

Upstream's numbers are upstream's conditions: a mock upstream answering in 60 ms, saturated
at 500 requests per second on two vCPUs. At this product's scale — a handful of GPU hosts and
a dozen users, answered by a model in seconds — per-request overhead is immaterial, the same
judgment [ADR 0004](0004-release-artifacts-and-channels.md) made about an 8% AES-GCM cost. The
memory and the image are real on a small control-plane host and in an offline bundle. **Speed
is not why this ADR exists**, and nothing in it depends on the benchmark.

## Rationale

**Why change at all.** Three things, each modest on its own:

1. A Go process in a 77 MB image beside a Go binary is a smaller and more legible control plane
   than a Python service in a 1.64 GB one, and a smaller surface to account for inside the
   boundary: fewer things that can write.
2. The behaviors nodary depends on — retry on another member, weighted spread across replicas
   of one model, stateless from one file — are first-class in Bifrost's configuration schema
   rather than router settings pinned against a moving default.
3. A second implementation behind one contract is what makes ADR 0003's "absorbing the proxy
   later is a contained change" true rather than asserted. Nine touchpoints name LiteLLM today
   and no seam exists ([R3b §1](../plans/R3b-a-second-data-plane.md#1-what-the-code-has-today-nine-touchpoints-and-no-seam)).
   The seam is the durable output of this work, whichever plane is the default.

**Why retain LiteLLM.** An install running it today keeps running it; a site that has written it
into a System Security Plan is not moved by an upgrade; and a Bifrost regression has an exit that
is one line in `server.toml`. Two is also the smallest number of implementations that proves the
seam is one.

**Why default to Bifrost rather than merely offer it.** A default is a recommendation. Once the
spike passes, nodary would otherwise be recommending the larger, more stateful process for no
reason it could state.

**Rejected — embed Bifrost's Go library in the gateway.** The obvious move for a Go project, and
the one that would remove the hop, the credential and the unit at once. Three things stop it.
`core` declares twenty direct dependencies — fasthttp, sonic, the AWS, GCP and Azure SDKs,
mcp-go, starlark — against nodary's three, and they would land inside the FIPS build and inside
the process that holds the database handle. `core` is not the HTTP transport, so the OpenAI
dialect — streaming, tool calls, error mapping — would be nodary's to implement over Bifrost's
structs, which is exactly the parity work ADR 0003 refused. And a separate process under its own
unit, with no database and loopback only, is better isolation than a library in the gateway.
Reconsider-if below.

**Rejected — Bifrost's static binary as a `kind: binary` component.** §1: nothing upstream
publishes lets nodary pin it.

**Rejected — hand routing to the gateway and use Bifrost only for the dialect.** The gateway
already reads ready members for the `503` ([R3-11](../tasks/R3-gateway.md)); choosing one is a
few lines, and attribution becomes a local fact. It is the fallback if the first gate fails, not
the first choice, because it moves member selection out of the component that owns retries — and
a request served by a fallback would be attributed to a member that did not serve it unless
Bifrost says otherwise, which is the same question in a different place.

**Rejected — use Bifrost's governance for keys and quota.** §2. It would also put an identity in
the data plane, which is the arrangement ADR 0003 exists to avoid.

**Rejected — replace LiteLLM outright.** No exit, no proof the seam is real, and a change to what
a running install runs.

## Consequences

**Gained.** A data plane that is one Go process in a small image. A contract two implementations
satisfy, which is what makes a third — none, or an absorbed one — a contained change. An exit
from either plane that is an edit and an upgrade.

**Lost.** LiteLLM's router cooldown. Bifrost's open-source build chooses keys by static weighted
random and tracks no health — adaptive balancing and the circuit breaker are in its enterprise
tier — so a member that hangs is retried away from per request rather than removed after three
failures, until the next sync drops it. A crashed member costs microseconds per affected request;
a hung one costs a timeout, for up to about a minute. Named here and in
[06 §5](../specs/06-gateway.md#5-failure-behavior) rather than discovered.

**Cost.** Two renderers, two assertion tables, two unit templates, and the seam that keeps every
list naming the data plane's unit to one place. **A SQLite config store inside the CUI
boundary**, which this ADR did not originally price: §2's table explains why it is on, and the
directory it lives in joins R3-15's canary sweep so that "no request content lands here" stays
a checked claim rather than an assumed one. A second single-vendor upstream on a two-to-three
day patch cadence to pin, upgrade and advise on. Bifrost's enterprise features — clustering,
adaptive balancing, the circuit breaker, OIDC and SCIM, RBAC, guardrails, secret-manager
references — are gated by Maxim's license; nodary neither needs nor depends on any of them. The
enterprise build uses the same configuration schema, so a site that buys it pins a different
image and nothing nodary renders changes. That is a fact about upstream, not a plan.

**What it does not claim.** Bifrost's image is not a FIPS build in any sense that matters to
[ADR 0006](0006-cui-boundary-and-fips.md). The data plane speaks plain HTTP on loopback and
protects no CUI with cryptography — as LiteLLM does not. Upstream's "FIPS 140-2 validated Alpine
base image" statement concerns the image's OpenSSL, which a statically linked Go binary does not
use; nodary repeats no such claim.

**Reconsider if** Bifrost publishes checksummed or signed release binaries — the container
runtime then stops being a data-plane concern and `kind: binary` is the smaller install. If
`core` grows an HTTP transport with a dependency footprint a three-dependency module can absorb,
embedding is the shape that removes the hop, the credential and the unit together, and
[06 §7](../specs/06-gateway.md#7-the-data-plane) is written so that it would be a third
implementation rather than a rewrite. And if the spike's gates cannot be met, LiteLLM stays the
default and this ADR is amended to record which gate failed and why.
