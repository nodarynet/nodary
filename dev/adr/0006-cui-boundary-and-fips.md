# ADR 0006 — The CUI boundary and the FIPS build

**Status:** Accepted · **Date:** 2026-09-06

## Context

[The pivot](../plans/pivot-cmmc.md#22-nodary-sits-inside-the-customers-cui-boundary) assumes
prompts and completions are CUI. A subcontractor wants on-prem inference precisely because
its prompts are CUI — that is the entire reason it is not calling a hosted API — and the
gateway proxies every request, so an assessor places nodary in scope whether or not our
documentation does.

Two things follow that are cheaper to decide than to discover: what nodary may hold, and
which cryptography it uses to hold it.

## Decision

### 1. nodary records that a request happened, never what it said

**The metering record schema is closed.** No free-text body field exists to write into, and a
test fails if request or completion content reaches the database or a log
([R3-15](../tasks/R3-gateway.md)). [06 §3](../specs/06-gateway.md#3-metering) already records
token counts, latency, status and partial-accounting and never content; this promotes that
from a schema detail to an enforced property.

The technique is the one behind [the audit seam](../tasks/README.md#cross-cutting-constraints):
a path that must not exist is made unreachable rather than discouraged. A guarantee that
depends on nobody adding a `body` column is not a guarantee.

**LiteLLM's configuration is rendered with request logging pinned off, and the pinning is
asserted** ([R3-16](../tasks/R3-gateway.md)). It is a third-party process in the data path,
and inside this boundary "LiteLLM begins writing request bodies somewhere by default" is an
incident rather than a nuisance. Asserted continuously, on the same principle that makes
[egress verification](../specs/03-agent.md#5-egress-isolation) continuous rather than
configured.

There is no flag that turns content retention on. If it is ever needed it arrives as a
separate, loudly-named capability, not as an option on the metering path.

### Amended: a failed container's own output, and where the line actually falls

Found while building [R2-29](../tasks/R2-control-plane.md), and recorded because §1 as written
and [11 §2](../specs/11-failure-modes.md) contradicted each other. 11 §2 asks the agent to
capture a failed deployment's last hundred log lines; the unit's `ExecStart` is `nerdctl run`,
so that journal is the **container's** stdout, and nothing in nodary constrains what a backend
prints into it. Those lines were going to `deployment.last_error` *and*, verbatim, into the
`node.deployment_failed` event — which is a record in the append-only chain that
[13 §3](../specs/13-evidence.md) exports to an assessor.

**The line is not "no bytes from a container", it is "nothing nodary cannot retract".** §1's
subject is what nodary *records about a request*: the metering schema is closed and has no
field to write a body into, and that is unchanged. A crashed server's own output is not nodary
recording a request — it is the evidence an operator needs to fix the thing, and removing it
would leave them with the sentence nodary wrote and nothing the container said.

So the two sinks are treated differently, and the difference is what is reversible:

| | `deployment.last_error` | the audit chain |
| :--- | :--- | :--- |
| Holds the log | yes — 11 §2's hundred lines, bounded to 2048 bytes | **no** — the reason, and `captured_log_bytes` |
| Overwritten | by the next failure on that deployment | never; append-only by construction |
| Leaves the boundary | no | yes, in the evidence bundle |

`captured_log_bytes` is there so the fact survives when the content does not: an assessor
reading the chain can see a log was captured and how much of one, and
`GET /deployments/{id}/logs` is where it is.

**What this does not claim.** A backend could still be *told* to log prompts — by a deployment's
`env`, which is an unconstrained string map — and a server that dies mid-request may print that
request in a traceback whatever its settings say. Neither is closed by a flag, and a denylist of
environment variables would need every variable four upstreams read at every version they are
pinned to, which is advice rather than a control and would read as a guarantee. What is closed is
the irreversible path, and it is closed structurally: `noteChange` is not given the log to carry,
and a test plants a canary in the journal and searches every byte of the emitted event
([R4-45](../tasks/R4-agent.md)).

All four backends this build pins print no prompt text at their defaults, read from the version
each digest is a build of rather than recalled — which is why this is a boundary worth stating
rather than an incident.

### 2. The FIPS artifact ships in `fips140=on`, and `fips140=only` is a named target

A `GOFIPS140=v1.0.0` build ships through the four existing channels
([R5-26](../tasks/R5-install.md)). It runs in **`GODEBUG=fips140=on`**: the validated module
is in service for every approved algorithm. It does **not** ship in `fips140=only`, which
additionally refuses every non-approved algorithm.

**It is the one artifact, not a second one.** [ADR 0004](0004-release-artifacts-and-channels.md)
ships a single binary and every channel carries the same object; a FIPS variant beside a plain
one would end that. The cost of making the only build the FIPS build was measured rather than
assumed — static, 0.27MB smaller, no slower to start, SHA-256 unchanged and AES-GCM about 8%
slower — and `GODEBUG=fips140=off` remains available to anyone who needs the non-FIPS paths.

[The spike measured](../spike-fips-and-manifest.md#2-on-and-only-are-different-products-and-the-difference-is-the-finding)
what separates them, and it is not theoretical:

| | `on` | `only` |
| :--- | :--- | :--- |
| Full test suite | passes | **3 of 8 packages fail** |
| TOTP's HMAC-SHA-1 | works | **panics inside `hmac.New`** |
| At-rest sealing's AES-GCM with a caller-supplied IV | works | **refused** |

Reaching `only` is gated on exactly two changes, and neither is a refactor:

1. **TOTP moves off HMAC-SHA-1**, or a second factor that is not RFC 6238 replaces it. One
   call site, and an interoperability decision about authenticator apps rather than a code
   problem.
2. **At-rest sealing moves to `cipher.NewGCMWithRandomNonce`**, keeping the existing HKDF
   per-message subkey. This changes the wire format, so **it must land before
   [R2-40](../tasks/R2-control-plane.md) seals the CA private key** — today the only sealed
   values are TOTP seeds and there are no installs to migrate; after R2 it is a migration of
   live secrets on customer machines.

## Rationale

**`on` is the claim that is true, and it is the claim 3.13.11 asks about.** The requirement
concerns cryptography employed to protect the confidentiality of CUI. Under `on`, every such
path — TLS, at-rest sealing, the chain's digests — runs through the validated module. `only`
is a statement about algorithms nodary uses *anywhere*, including a TOTP construction that
protects an authenticator secret rather than CUI. It is a stronger claim than the control
requires, and it is not free.

**Shipping `only` today would mean shipping a panic.** HMAC-SHA-1 does not fail politely
under `only`; it panics inside `hmac.New`, and it does so on a path that runs within
`audit.Act` within `store.WriteTx` — a crash in the middle of an audited mutation, in the
process that owns the chain. A mode whose failure is a crash in the audit writer is not a
mode to enable by default and then discover.

**Rejected — ship `only` and change TOTP first.** Strongest possible claim, and the TOTP
change is genuinely small. It front-loads an interoperability decision and a sealing-format
migration into the milestone that has neither a control plane nor a gateway, in service of
a claim no customer has yet asked for.

**Rejected — do not ship a FIPS artifact at all until it is needed.** Honest, and defers
everything. The [MVP](../plans/mvp.md#6-what-an-mvp-install-cannot-claim) explicitly does not
claim FIPS, so this is arguable; it is rejected because the artifact costs one build matrix
entry once the CI job in [R5-25](../tasks/R5-install.md) is green, and because the sealing
deadline exists whether or not the artifact ships.

**Rejected — position the control plane as outside the boundary.** Much less engineering and
no FIPS obligation at all. Indefensible: the gateway is in the data path.

## Consequences

**Gained.** The strongest claim available in this market — the product cannot retain CUI
because there is nowhere for it to go — resting on a test rather than on a policy document.
A FIPS artifact through every channel for the cost of a build matrix entry.

**Lost.** Debugging and evaluation workflows that want prompt capture are not served, and
will not be. That is a real cost to a real user, paid deliberately.

**Cost.** Two obligations with dates rather than intentions: the sealing format before
R2-40, and a decision on TOTP before anyone is promised `fips140=only`. A non-gating CI job
([R5-25](../tasks/R5-install.md)) keeps both measured rather than assumed.

**Reconsider if** a customer's assessor reads 3.13.11 as requiring approved algorithms
everywhere rather than on CUI-protecting paths. That converts `only` from a target into a
requirement, and the two gates above become the schedule.
