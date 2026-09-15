# R3b — A second data plane, and Bifrost as the default

**Slice of:** [R3](../tasks/R3-gateway.md) ·
**Tasks:** R3-17 – R3-25 · **Status:** planned, nothing built; §2's spike decides the shape

[ADR 0009](../adr/0009-bifrost-as-the-default-data-plane.md) proposes Bifrost as the default
data plane with LiteLLM retained, and [06 §7](../specs/06-gateway.md#7-the-data-plane) states
the contract both satisfy. This plan is how: what the code has, what must be measured before
anything is designed, the decisions, and the order. It restates neither document.

## 1. What the code has today: nine touchpoints and no seam

`grep "interface {" internal/gateway/*.go internal/install/*.go` returns nothing. LiteLLM is
named wherever it is touched, and a second plane would have to duplicate every one of these:

| | Where | What it does |
| :--- | :--- | :--- |
| 1 | [`gateway/litellm.go:14-41`](../../internal/gateway/litellm.go) | `LiteLLMConfig` and `LiteLLMModel{Name, APIBase, Model, Weight, ID}` — the neutral member list, misnamed |
| 2 | [`gateway/litellm.go:75`](../../internal/gateway/litellm.go) | `Render()` — `openai/<route>` at `api_base`, `model_info.id` per member, `router_settings` pinned |
| 3 | [`gateway/litellm.go:57,182`](../../internal/gateway/litellm.go) | `pinnedOff` and `AssertLoggingOff` — six settings and three callback lists, checked on the rendered bytes |
| 4 | [`gateway/gateway.go:205`](../../internal/gateway/gateway.go) | `X-Litellm-Model-Id`, read at [`proxy.go:160`](../../internal/gateway/proxy.go) into the usage row |
| 5 | [`install/units.go:250`](../../internal/install/units.go) | `nodary-litellm.service` — `nerdctl run --network host`, `${NODARY_LITELLM_IMAGE}` from `litellm.env` |
| 6 | [`cli/server.go:820-921`](../../internal/cli/server.go) | `writeLiteLLM`, `writeLiteLLMConfig`, `writeLiteLLMImage`; `restrictConfigSecrets`' allowlist names `litellm.yaml` |
| 7 | [`cli/gatewaysync.go:96-158`](../../internal/cli/gatewaysync.go) | render, assert, write, and restart on `/run/nodary/litellm.applied` |
| 8 | [`cli/upgrade.go:239-337`](../../internal/cli/upgrade.go) | repin `litellm.env`, restart the unit, `--check` diffs its pin |
| 9 | [`hack/update-manifest.py:207`](../../hack/update-manifest.py) | the `IMAGES` row that generates the manifest entry |

Beside them, every list that names the unit: `Units("server")`, `startedUnits`, `hostUnits`,
`restartUnits`, [`dev-reset.sh`](../../scripts/dev-reset.sh) and
[`verify-privileged.sh`](../../scripts/verify-privileged.sh) §13.

What is already neutral, and stays untouched: the proxy needs a URL and a bearer
(`gateway.Options`); the metering parses the OpenAI wire format, not LiteLLM's; the throttle,
the allowlist and the `503` read nodary's own tables. **The gateway process does not change in
this slice except at touchpoint 4**, and at the one request field §3.3 names.

## 2. The spike, measured before anything is designed

ADR 0009 is accepted on three gates, and the point of running them first is that any one can
send the design a different way, or stop it. Two days, against the real image, thrown away.
The output is a page beside [the FIPS spike](../spike-fips-and-manifest.md) and the result
written into ADR 0009's status line.

### Gate 1 — the response names the member that served it

Run Bifrost with two upstreams for one model name — two `python3` fake servers, the way
[`litellm_docker_test.go`](../../internal/gateway/litellm_docker_test.go) already does — and
read every header and body field of a completion, streamed and not, under both rendering
shapes in §3.3. Record what, if anything, identifies the key or provider that answered, and
whether it still does after a fallback.

| Found | Shape |
| :--- | :--- |
| a key-level signal | **K** — one provider, one key per member; Bifrost spreads and reports |
| a provider-level signal only | **P** — one provider per member; the gateway picks, Bifrost falls back and reports |
| neither | **the gate fails.** ADR 0009 is not accepted as written |

### Gate 2 — stateless, credentialed, and it records nothing

With `config_store.enabled: false`, `logs_store.enabled: false`,
`client.enforce_auth_on_inference: true` and one virtual key seeded in the file:

- a request without the key is refused with the documented `virtual_key_required`; with it,
  served;
- the dashboard and `/api/*` refuse without the rendered admin credential;
- the configuration mounted read-only starts, and the container's writable layer holds no new
  file after a hundred requests — `nerdctl diff`, or a canary prompt searched for across the
  container's filesystem the way [R3-15](../tasks/R3-gateway.md) searches the database;
- a loopback `base_url` is accepted. `network_config` carries an `allow_private_network` field
  whose default must be read, not assumed.

Any of these failing is a finding rather than a stop; §3.4 and §3.5 name the fallback for each.

### Gate 3 — the dialect survives what the fleet sends

Through the real image against a real llama.cpp on this host, the cheapest pinned backend: a
completion streamed one byte at a time, a tool call, an embedding, `/v1/completions` — and the
gateway's existing suite pointed at Bifrost instead of its stub upstream. Read off: the default
request timeout, the stream-idle timeout, what the response's `model` field carries, and
whether the `vllm` provider type serves llama.cpp and TensorRT-LLM's OpenAI frontends unchanged
or whether they need the generic `openai` custom type.

### Also measured, not gated

The container's memory at rest and under the suite; time from `systemctl start` to `/health`
answering 200; the image's pull size; whether `-app-dir` needs to be writable at all in
file-only mode.

## 3. Decisions

### 3.1 The seam is one value, chosen in one place

**Decided.** A `gateway.Plane` describing an implementation — name, component, unit, config
file, image env file, applied marker, the served-member signal, a renderer and an assertion —
with two values, `LiteLLM` and `Bifrost`. `data_plane` in `server.toml` selects; `server
install --data-plane` writes it; `gateway sync`, `upgrade`, `status`, `doctor` and the gateway
read it through one function. Nothing else names either plane.

**Why.** Two implementations is the number at which an abstraction pays for itself, and §1's
list is the argument: nine places that would otherwise become nine conditionals. It is one
struct value rather than an interface because the differences are data — names and two
functions — and a struct is what a test can compare field by field.

**Rejected — `data_plane` as a configuration revision.** It is not one. Which software runs on
this host beside the gateway is a fact about the host, like the bind address and the TLS
certificate paths, and [00 §1](../specs/00-overview.md#tool-versus-deployment) puts those in
`server.toml`. It is still an attributable fact: `nodary status` names it, the component
manifest pins it, and switching is an act an operator performs as root on the host, which is
what every other `server.toml` edit already is.

**Rejected — a boolean, or Bifrost hard-wired as the only plane.** The first is the seam with
two values and a worse name; the second is ADR 0009's rejected "replace outright."

### 3.2 The refactor lands first, alone, with nothing to show

**Decided.** R3-17 moves LiteLLM behind the seam and changes no behavior: every existing test
passes, `litellm.yaml` renders byte-identical, and the docker tests still run the pinned image.
Bifrost arrives in the commit after.

**Why.** A refactor and a feature in one change is a change whose failures cannot be
attributed. It is also the step that proves the seam is real before a second implementation
depends on it.

### 3.3 The rendering shape is the spike's to choose

Two shapes satisfy the contract on paper. Both render from the member list `routeModels` builds
today; the difference is where the spread happens and what the request has to say.

**Shape K — one provider, one key per member.** Bifrost's `vllm` provider carries a URL per key
and a `models` list per key, so a route's members are keys under one provider, weighted, and
Bifrost chooses — the structure of LiteLLM's `model_list` exactly:

```json
{"providers": {"vllm": {"keys": [
  {"name": "dep_tiny_gpu01", "value": "", "models": ["acme/tiny"], "weight": 3,
   "vllm_key_config": {"url": "http://127.0.0.1:8001", "model_name": "acme/tiny"}},
  {"name": "dep_tiny_gpu02", "value": "", "models": ["acme/tiny"], "weight": 1,
   "vllm_key_config": {"url": "http://127.0.0.1:8002", "model_name": "acme/tiny"}}],
  "network_config": {"max_retries": 2}}}}
```

The request must address `vllm/acme/tiny`: Bifrost requires a provider prefix and splits on the
first slash, so a route named `acme/tiny` sent bare would be read as provider `acme`. The gateway
rewrites that one field, the way it already rewrites `stream_options`
([`proxy.go:200`](../../internal/gateway/proxy.go)). Attribution needs a key-level signal.

**Shape P — one provider per member.** Each deployment is a custom provider of
`base_provider_type: "openai"` — which is what [04 §8](../specs/04-backends.md#8-routing-implications)'s
`api = openai` means, and what `openai/<route>` renders for every member today — with its own
`base_url`. The gateway picks a member by weight over the ready set it already reads for the
`503`, rewrites `model` to `dep_tiny_gpu01/acme/tiny`, and injects `fallbacks` naming the rest:

```json
{"providers": {"dep_tiny_gpu01": {
  "keys": [{"name": "dep_tiny_gpu01", "value": "", "models": ["*"], "weight": 1}],
  "network_config": {"base_url": "http://127.0.0.1:8001", "max_retries": 2},
  "custom_provider_config": {"base_provider_type": "openai"}}}}
```

Attribution is the gateway's own pick unless a fallback served the request, which needs a
provider-level signal — the same measurement as K's, one level up.

**The rule.** K if gate 1 finds a key-level signal; P if it finds only a provider-level one. K
is preferred because it keeps member selection in the component that owns retries, which is
ADR 0003's split; P is acceptable because the gateway already holds the ready set and a weighted
pick is a few lines rather than a router. Whichever wins, the other is deleted rather than kept
behind a flag.

### 3.4 The credential lives where LiteLLM's does

**Decided.** One virtual key, minted at install the way the master key is, held in `gateway.env`
under the variable the gateway already reads, rendered into `bifrost.json`, both 0600 under
`paths.ModeMasterKey`, whose comment gains one word. `restrictConfigSecrets`' allowlist gains
the file. `enforce_auth_on_inference: true` is in the assertion table.

**Fallback if gate 2 finds virtual keys need the config store.** The config store is enabled on
a SQLite file under `/var/lib/nodary/bifrost/`, holding provider configuration and keys and no
content — and that directory joins the set R3-15's canary is searched for in, because a file
the data plane writes is a file the guarantee has to cover. Recorded in ADR 0009 as a cost if it
comes to that; not designed for until it does.

### 3.5 Pinned off, asserted on the bytes, and re-checked on the host

**Decided.** ADR 0009 §2's table becomes a Go table beside `pinnedOff`, rendered explicitly and
asserted by walking the rendered JSON — not string-matched, because JSON has no fixed line shape
the way the YAML renderer's output does. `verify-privileged.sh` §13 reads the selected plane
from `server.toml` and checks that plane's file with that plane's keys.

**The admin credential is rendered and kept nowhere.** A random value into
`governance.auth_config.admin_password`, regenerated on every render; nodary never logs in, so
nothing needs it. If gate 2 finds admin authentication needs the config store, the dashboard
stays open on loopback and the finding goes into ADR 0009's "what it does not claim": an
unauthenticated read-only surface on `127.0.0.1` exposing route names and loopback ports,
which `nodary route list` also shows.

### 3.6 Switching is `nodary upgrade`, honoring what `server.toml` says

**Decided.** An operator changes `data_plane` and runs `nodary upgrade`. It already rewrites
every unit and restarts those whose inputs changed ([R5-15](../tasks/R5-install.md)); the
selector becomes an input. It writes the selected plane's unit and image pin, renders its
configuration, stops and disables the other unit, and starts the new one. The gateway is not
restarted — nothing it holds changes. `upgrade` must converge a host at the version it already
runs, which it may not do today; R3-25 says so.

**Rejected — `nodary gateway switch <plane>`.** One verb per act reads well, and it is a second
road to a convergence `upgrade` already owns. `upgrade` must know how to switch regardless, or
an upgrade after a switch would put the old unit back, so the verb would be a wrapper.

**Rejected — re-running `server install`.** It rewrites `server.toml` from flag defaults, which
is exactly why `upgrade` exists as a separate verb.

### 3.7 A fresh install defaults to Bifrost; nothing already installed moves

**Decided.** `server install` writes `data_plane = "bifrost"` unless `--data-plane litellm`; the
wizard asks, with the flag equivalent every prompt has ([R5-05](../tasks/R5-install.md)). A
`server.toml` with no `data_plane` key reads as `litellm`, because every install that predates
this slice runs LiteLLM and a missing key must describe what is actually there. `upgrade` never
writes the key.

### 3.8 What is adopted from Bifrost, said exactly

Retries with backoff, fallback to another member, weighted spread, and the OpenAI surface the
gateway already serves. `/metrics` is scraped by the pinned Prometheus once the observability
units exist to scrape it — LiteLLM's is not enterprise-gated either, so that is parity rather
than a gain. Nothing else: not governance, not the dashboard, not OTel, not the semantic cache,
not MCP, not the drop-in `/anthropic` and `/bedrock` prefixes. The gateway's surface is
[06 §1](../specs/06-gateway.md#1-request-path)'s four routes, and widening it is a spec change
rather than a property of whichever plane happens to speak more dialects.

## 4. The shape

| | |
| :--- | :--- |
| `internal/gateway/plane.go` | `Plane`, the two values, `Select(serverConfig)` |
| `internal/gateway/litellm.go` | unchanged in output; `LiteLLMModel` becomes `Member` |
| `internal/gateway/bifrost.go` | the JSON renderer, its pinned table, its assertion |
| `internal/gateway/bifrost_docker_test.go` | the pinned image on the generated file — R3-04's test for the second plane |
| `internal/install/units.go` | `bifrostUnit`; `Units("server")` takes the plane |
| `internal/cli/server.go`, `gatewaysync.go`, `upgrade.go`, `status.go`, `doctor.go` | read the plane; name it |
| `internal/components/components.json`, `hack/update-manifest.py` | the `bifrost` image row |
| `scripts/verify-privileged.sh`, `scripts/dev-reset.sh` | §13 and the unit list per plane |

## 5. Steps

- [ ] The spike (§2): three gates measured against the pinned image, written up beside the FIPS spike, ADR 0009's status line updated with the result
  - part of gate 2 is measured and written up in [the spike](../spike-bifrost.md): the vendor round trip, and the cold start that fails without it. Gates 1 and 3 remain
- [ ] R3-17 — the seam, LiteLLM alone behind it, no behavior change, every test green
- [ ] R3-18 — `bifrost` in the manifest by digest, generated, moved by `upgrade`
- [ ] R3-19 — the renderer in the shape the spike chose, the pinned table, the assertion — **two files**: `bifrost.json` and the stub datasheet its `file://` URLs name ([the spike](../spike-bifrost.md#3-file-works-and-the-content-is-almost-free))
- [ ] R3-20 — the credential, the locked admin surface, the unit, no secret on argv
- [ ] R3-21 — attribution through the signal the spike found, asserted against the image streamed and not
- [ ] R3-22 — the real image on the generated file, through the gateway, the canary searched for
- [ ] R3-23 — retries and fallback pinned; membership live through sync; the applied marker per plane
- [ ] R3-24 — `status`, `doctor`, the two scripts, `uninstall` and `backup` name and check the selected plane
- [ ] R3-25 — Bifrost the default for a fresh install; `upgrade` switches; administering.md says how
- [ ] §6's corrections applied

## 6. Spec corrections this plan owes

Per [the rules](README.md#the-rules), a plan that finds a spec wrong records it as an open item
until the spec is corrected. [06](../specs/06-gateway.md) is corrected with this plan because
§7 is the contract the tasks cite; the rest describe a running system and move when the slice
does.

| Document | Correction | |
| :--- | :--- | :--- |
| [06 §1, §5, §7](../specs/06-gateway.md) | "the data plane" where it said LiteLLM; §7 states the contract | done |
| [00 §2](../specs/00-overview.md#2-topology) | the topology diagram's `LiteLLM` box becomes the data plane, naming both | open |
| [00 §6](../specs/00-overview.md#6-component-inventory) | the `litellm` unit row becomes `nodary-bifrost` or `nodary-litellm`, one of them | open |
| [00 §7](../specs/00-overview.md#7-why-litellm-stays) | retitled "Why the data plane is a separate process"; the argument is unchanged and names both | open |
| [01 §2, §3 step 8](../specs/01-install.md) | the component list and the units started name the selected plane; `--data-plane` beside the other flags | open |
| [01 §12](../specs/01-install.md#12-filesystem-layout) | `/etc/nodary/bifrost.json` and `bifrost.env` beside the LiteLLM pair; `server.toml`'s summary gains `data_plane` | open |
| [08 §4](../specs/08-data-model.md#4-secrets-at-rest) | "the LiteLLM master key" becomes "the data plane's credential", the two files named per plane | open |
| [09 §1](../specs/09-api.md) | the backup archive's contents: "the data plane's credential" | open |
| [11 §4](../specs/11-failure-modes.md#4-gateway) | "LiteLLM unreachable" becomes "data plane unreachable"; a row for a member that hangs rather than refuses | open |
| [10 §3](../specs/10-cli.md#3-nodary-doctor) | a `data plane` line in `doctor`'s output | open |
| [tasks README §4](../tasks/README.md#4-gateway) | the failure-mode row follows 11 §4 | open |
| `components.json` notes, [`update-manifest.py`](../../hack/update-manifest.py) | "runs LiteLLM as a container" becomes "runs the data plane as a container" | open |
| `README.md` | the diagram; "LiteLLM's request logging is pinned off" becomes "the data plane's" | open |
| `docs/administering.md` | attribution, the master key, backup contents, the CVE path, and a section on choosing and switching the plane | open |

## 7. Open items

- **The version this plan was written against.** §3.3's JSON and ADR 0009's table come from v1
  documentation; the release is **v2.1.1**, which moved configuration into a SQLite store.
  A rendered `config.json` is still read and still seeds that store, so the shape survives —
  but every field name in this plan is a v1 field name until the spike confirms it, and
  `framework` is already known to be nested one level deeper than §3.5 assumes. Worse, that
  object is `additionalProperties: false`: a block written at the wrong depth is accepted,
  ignored, and leaves no message.

- **The hung-member window.** Bifrost's open-source build has no cooldown, so between a member
  hanging and the next sync, a weight's share of requests wait a timeout before falling back.
  The sync interval is a minute and the agent's probe needs three failures first
  ([03 §7](../specs/03-agent.md#7-gpu-assignment-health-restart-reboot)). If the spike's timeout
  numbers make that window worse than [11 §4](../specs/11-failure-modes.md#4-gateway) should
  promise, the answer is a shorter sync interval for the data plane, not a cooldown written into
  the gateway.
- **Offline bundles.** Images are pulled by digest and not mirrored
  ([R5-05](../tasks/R5-install.md)); whether `bundle create` carries them is the same question
  for both planes and is not this slice's.
- **`ubi9`.** Upstream publishes a UBI-based variant of every tag. A site whose policy prefers it
  pins a different digest through a manifest revision
  ([ADR 0007](../adr/0007-independent-component-manifest.md)); nodary's default stays the
  smaller image.
- **The `/anthropic` prefix.** Bifrost would let a client holding an Anthropic SDK talk to a local
  model. That is a change to 06 §1's surface and needs its own decision.
