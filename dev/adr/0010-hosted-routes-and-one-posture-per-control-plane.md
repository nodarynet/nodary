# ADR 0010 — Hosted providers behind the same gateway, one posture per control plane

**Status:** Proposed · **Date:** 2026-09-15 ·
**Depends on:** [ADR 0009](0009-bifrost-as-the-default-data-plane.md)'s seam, not on its outcome ·
**Restates as a decision:** [00 §1](../specs/00-overview.md#1-scope)'s "not multi-tenant isolation"

## Context

A small business under CMMC Level 2 can hold two kinds of work on two kinds of machine: a
CUI enclave whose prompts may go to a hosted model when the provider is authorized for it,
and a more sensitive enclave whose prompts may never leave the building. Both want the same
thing from nodary — one gateway, one identity, one usage table, one evidence bundle — and they
want it with different answers to the question "where may a prompt go".

The data planes nodary runs are built for the first case. Local inference is their special case:
LiteLLM reaches over a hundred hosted providers and Bifrost a first-class set including OpenAI,
Anthropic, Azure, Bedrock and Vertex AI, and both translate the client's OpenAI request into the
provider's dialect and normalize the response, usage included. So the gateway would see the same
wire format it sees today, and the metering that reads `usage` from it would not change.

What nodary lacks is the object: a route member today **is** a deployment — a node, a GPU set
and a port ([`0006_fleet.sql`](../../internal/store/migrations/0006_fleet.sql), `route_member`
references `deployment`), and the ready-member query behind the `503`, the sync renderer and the
usage row's attribution columns all assume one. A hosted model has none of those.

Two facts frame the decision, and both were verified rather than recalled:

- **The endpoint is the authorization.** DFARS 252.204-7012 requires a cloud service that
  stores, processes or transmits covered defense information to meet the FedRAMP Moderate
  baseline or equivalent. Google lists *Generative AI on Vertex AI* in its FedRAMP High scope;
  the same Gemini models behind the AI Studio API are a different service with a different
  endpoint. Both planes already treat them as different providers — `vertex/` against `gemini/`
  in Bifrost, `vertex_ai/` against `gemini/` in LiteLLM — so the distinction an assessor cares
  about is one nodary can see at the route.
- **nodary cannot see what a prompt is.** [ADR 0006](0006-cui-boundary-and-fips.md) closes the
  metering schema and [R3-15](../tasks/R3-gateway.md) asserts nothing about a request's content
  is ever held. A classification is therefore not something nodary can attach to a request, a
  user or a route and have it mean anything: it would be a label, and the control would be the
  label.

## Decision

**A route may hold hosted members. Which endpoints a hosted member may name is a policy
allowlist, empty by default under every profile. A control plane has one posture, and a site
with two data classifications runs two control planes.**

### 1. One posture per control plane

A control plane runs one active policy profile
([07 §4](../specs/07-identity-audit.md#4-policy-profiles)), and whether prompts may leave the
building is a property of that profile. nodary provides no per-request, per-user or per-route
way to keep one classification's prompts local while another's go out, because any such
mechanism would rest on a label nodary cannot check. Separation is structural: a separate
control plane, a separate network, a separate user population with separate tokens, each with
its own chain and its own evidence bundle.

For the scenario above that means a **CUI control plane** whose profile names the authorized
endpoints, and an **isolated control plane** whose profile names none, installed from the
offline bundle and taking manifest and advisory revisions the same way. The second is the
product as it exists today. The first is what the rest of this ADR adds.

### 2. A hosted member is its own kind of route member

A hosted member names a **provider kind** (`vertex`, `openai`, `anthropic`, `openai-compatible`,
and whatever else both planes spell), an **endpoint**, a **model name** and a **credential
reference**. It has a weight like any member. It is "ready" by declaration — no agent probes it —
and a route may mix hosted and local members, so a local model can carry a hosted fallback or
the reverse, with the same retry and fallback behavior
[06 §7](../specs/06-gateway.md#7-the-data-plane) already requires of the data plane.

It is a second table, not a nullable column on `route_member`: every query that joins a member
to a deployment stays true as written, and a hosted member has nothing to join to.

**Attribution is additive.** The usage row gains one nullable column naming the hosted member;
deployment, node and GPU stay null for a hosted request. The row's existing fields are a
compatibility surface the moment a customer holds a bundle ([mvp §2](../plans/mvp.md#2-the-rule-that-decides-what-gets-built)),
so nothing is renamed.

### 3. The allowlist, and why empty means none on every profile

The profile gains `hosted_endpoints`, a list of hostnames a hosted member may name. **Empty
means no hosted member may be applied**, on `default` as on `regulated`. That breaks with
`model_origin_allowlist`, where empty means any origin, and follows `egress_default = "deny"`,
which the `default` profile also ships: a route that sends prompts off the box is egress, and
egress is something an operator turns on by an act with an author, not something a fresh install
permits because nobody said otherwise.

Under `regulated`, `*` is refused, and a hosted member whose endpoint is not listed is refused
at apply time with the endpoint named — the shape [05 §2](../specs/05-catalog.md#2-provenance-as-a-control)
gives model origins. Adding an endpoint to the profile is `policy apply`, audited with a
justification. Adding the member is a revision. Between them the chain records who decided that
CUI may reach that host, when, and why.

**What nodary does not decide** is whether the host is authorized. That determination is the
customer's, against the provider's current FedRAMP scope, and it belongs in their System
Security Plan. nodary records the decision and enforces its consequence, which is the product's
standing position: it makes the mechanism, the customer makes the claim.

### 4. The credential is host material, never configuration

A hosted member's credential — an API key, or for Vertex AI a service-account JSON with a
project and region — lives in a 0600 file under `/etc/nodary/hosted/`, referenced by name from
the member. It is rendered into the data plane's configuration by `gateway sync`, which already
runs as root for exactly this kind of write, and the rendered file is 0600 for the reason
[08 §4](../specs/08-data-model.md#4-secrets-at-rest) gives the master key.

It is never in the configuration snapshot, never in `config export`, and never crosses the API.
`backup create` captures `/etc/nodary` and so captures it, which makes the archive as sensitive
as it already was.

### 5. The endpoint list is enforced on the wire, not only in a file

Both planes can be pointed at an outbound proxy. nodary already has one:
[`derive.Proxy`](../../internal/derive/proxy.go) is an allowlisting CONNECT proxy that refuses
any host outside its list and names what it refused, built for derived-image builds
([R6-09](../tasks/R6-backends.md)). Lifted out of `derive` and run inside `nodary-gateway`, reading
the active profile's `hosted_endpoints`, it makes "prompts leave only to the endpoints the
policy names" a mechanism with a refusal log, and a policy change takes effect without
re-rendering the data plane. The data plane's outbound-proxy setting is pinned and asserted with
its logging settings; loopback stays direct.

**A proxy setting is configuration, and the data plane runs on the host's network.** A plane
that ignored its proxy setting would reach the internet unhindered. The control is a kernel
rule: the data plane's container runs as its own uid, and an nftables rule permits that uid
outbound connections to loopback only — the proxy's port and the deployments' ports. The proxy
then decides which loopback-originated tunnels go where. This is
[03 §5](../specs/03-agent.md#5-egress-isolation)'s principle on the control-plane host, with
the lesson [R4d](../plans/R4d-egress-isolation.md) paid for already applied: a filter on the
launcher is not a filter on the workload, so the rule is on the uid, not the unit.

**Measured before claimed.** Whether a `nerdctl run --network host --user` process is matched by
an nftables owner rule as expected is a spike measurement, not an assumption. Until it is
measured, the documentation says the allowlist is *configured*, not *enforced* —
[pilot](../plans/pilot.md)'s Tier 0 rule.

### 6. Through the data plane, whichever it is

The hosted call goes through the data plane, not through code in the gateway. Translating a
request into a provider's dialect and its response back is the work
[ADR 0003](0003-litellm-as-data-plane.md) refused to reimplement, and the seam
[ADR 0009](0009-bifrost-as-the-default-data-plane.md) introduces is where each plane's spelling
of a provider kind lives. Nothing here depends on which plane is the default.

## Rationale

**Why through nodary at all.** The alternative is that users call the provider directly with a
key the business hands out. Then the SSP describes two paths, the provider attributes every
request to one key, and the allowlist, the per-person usage row and the quota do not apply to
the path that leaves the boundary — which is the path an assessor asks about first. Through the
gateway, a hosted request is authorized, metered and attributed exactly as a local one, and the
bundle can show every CUI-to-cloud request by person, route, endpoint and time, with no content.
That is direct evidence for 800-171 practice 3.1.3, controlling the flow of CUI under approved
authorizations, which most organizations of this size cannot produce.

**Why two control planes rather than one with a switch.** Because nodary is content-blind on
purpose, and any single-cluster design has to answer "which prompts may go out" with a label. A
user granted both a local route and a hosted route moves data between classifications by
choosing a model name. Authorization is not isolation, and [00 §1](../specs/00-overview.md#1-scope)
already declines to claim the second. Two control planes cost a second install and a second
chain, and they cost nothing in code.

**Why deny by default on every profile.** The homelab is the community edition, and a homelab
wanting Claude beside a local model adds one line to its profile. A fresh install that could
reach any host with any prompt because nobody edited a list is the wrong default for a product
whose regulated posture is something an operator adopts rather than discovers.

**Rejected — a classification tag on routes and users.** Content-blind, so the tag is a claim
nodary cannot check, and a control that is a claim is what this product exists not to ship.

**Rejected — per-user "may use hosted routes" as the isolation.** That is what the allowlist
already provides, and it is authorization: useful under one classification, meaningless across
two.

**Rejected — `hosted_endpoints` empty meaning any, for consistency with origin lists.** An origin
list constrains what comes in; this constrains where prompts go. The consistent precedent is
`egress_default`.

**Rejected — the credential in the snapshot, so `config export` and `apply` carry it.** A secret
in an export is a secret in a support thread. Host material stays on the host.

**Rejected — the allowlist enforced by the plane's configuration alone.** Configuration a plane
could ignore is not a control, and calling it one is the mistake [the review](../review-2026-09-11.md)
found this product making about limits. The uid rule is what makes the word "enforced" true.

**Rejected — nodary implementing the provider call.** ADR 0003, unchanged.

## Consequences

**Gained.** One gateway, one identity, one usage table and one bundle across local and hosted
models. An attributable record of every prompt that left the boundary, and to where. A control
that maps to 3.1.3 by mechanism rather than by narrative. A feature the community edition wants
for its own reasons.

**Lost.** The CUI control plane's data plane is no longer a process with no reason to reach the
network. That is the point, and it is why §5 exists.

**Cost.** A second member table through the applier, the API, the CLI and both renderers. A
credential directory with the master key's handling. The proxy lifted out of `derive` and a uid
rule asserted by `doctor` the way egress is on a node. A policy field. One documentation page
stating the endpoint distinction, the retention and abuse-monitoring settings to ask a provider
for, and that the authorization determination is the customer's.

**What it does not claim.** nodary does not certify a provider, does not control what the
provider retains, and does not extend the boundary to it; a zero-data-retention agreement is a
contract and an SSP sentence, not a setting. Two control planes separate two enclaves only if
the network between them does; nodary asserts nothing about that network. If "isolated" means
classified in the NISPOM sense, nodary's claims stop at its mechanisms — accreditation of such a
system is a different regime, and nodary says nothing about it.

**Reconsider if** a provider offers private connectivity into the customer's network, in which
case the allowlist becomes an address and the uid rule's job changes; or if no regulated
customer adopts a hosted route within a few pilots, in which case the capability stays on and
the documentation page moves to the community edition's, since the mechanism costs nothing to
keep.
