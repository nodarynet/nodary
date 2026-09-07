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

### 2. The FIPS artifact ships in `fips140=on`, and `fips140=only` is a named target

A `GOFIPS140=v1.0.0` build ships through the four existing channels
([R5-26](../tasks/R5-install.md)). It runs in **`GODEBUG=fips140=on`**: the validated module
is in service for every approved algorithm. It does **not** ship in `fips140=only`, which
additionally refuses every non-approved algorithm.

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
