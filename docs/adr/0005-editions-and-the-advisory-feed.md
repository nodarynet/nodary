# ADR 0005 — Editions, the licence key, and the advisory feed

**Status:** Accepted · **Date:** 2026-09-06

## Context

[The pivot](../plans/pivot-cmmc.md#21-the-open-core-line-operational-free-evidence-paid)
chose a buyer — a small defence-supply-chain business under CMMC Level 2 — and with it the
question of what that buyer pays for. The features that justify nodary over four
`docker compose` files are compliance ceremony: the hash chain, `intent_hash` binding,
required justification, provenance allowlists, retention windows. A homelab operator
experiences all of it as friction. The site that wants it is the site that has to
demonstrate control to a third party.

## Decision

### 1. The line: the mechanism is free, the knowing and the proving are paid

**Everything that runs the fleet is Apache 2.0** — control plane, agent, gateway, every
backend, both policy profiles, the full hash chain, `audit verify`, `audit export`,
enrollment, staging, guardrails, the FIPS build, the SIEM sink, OIDC.

**The commercial edition sells what turns records into a deliverable a human assessor
consumes:** `nodary evidence export`, the control index and SSP narratives, and the signed
advisory feed.

In one sentence: **we do not sell security, we sell the paperwork.**

### 2. One binary, an `ee/` directory, a signed licence key

The repository stays public. Everything outside `ee/` stays Apache 2.0; `ee/` carries a
commercial licence and the root `LICENSE` gains a pointer. One binary continues through the
four channels of [ADR 0004](0004-release-artifacts-and-channels.md). Commercial features are
inert until `nodary license apply` verifies a minisign-signed licence against an embedded
key — **the same Ed25519 verifier [ADR 0007](0007-independent-component-manifest.md)
introduces**, with the same non-prehashed constraint and no second trust root. Applying a
licence is a mutation and lands in the chain.

Two properties are **not negotiable**:

1. **An unlicensed install still carries every commercial verb and explains what it would
   produce.** `nodary evidence export` without a licence names the bundle's members and
   refuses. The commercial surface is discoverable, never hidden.
2. **An expired licence never makes existing evidence unreadable.** The bundle format is
   documented, the raw chain export is free, and a bundle produced under a licence still
   verifies after it lapses. Compliance evidence held hostage by a lapsed subscription is a
   story that ends a company, and it is the first thing a careful buyer tests
   ([R9-04](../tasks/R9-evidence-remediation.md)).

### 3. The advisory feed is ours, signed, and generated rather than curated

nodary publishes a signed feed mapping component digest → advisory → recommended digest,
delivered online or inside a `bundle create` output. It is **generated**: scanners run
against our own pinned component set in CI, the delta against the previous revision is
reviewed by a human, then signed and published.

**The feed carries an explicit statement of what it is and is not.** It is a report of what
public sources say about digests we pin, at the time it was generated. It is **not** a
warranty, not a guarantee of completeness, and not a substitute for the customer's own
vulnerability management. That statement ships inside every revision, not only in
documentation, because the revision is what outlives the sales conversation.

## Rationale

**An edition that disables the chain contradicts the specification.**
[07 §4](../specs/07-identity-audit.md#4-policy-profiles) states the chain "is the product
rather than a posture" and that no profile disables it. A community edition without it is a
worse `docker compose` that nobody adopts and therefore nobody converts from.

**Two content subscriptions is a business; one formatter is a feature.** With FIPS, OIDC and
the SIEM sink all free, the paid column would otherwise be a formatter over data the chain
already holds, plus some markdown. The feed answers that: it has genuine currency
requirements and a real maintenance obligation. Generating rather than curating turns an
unbounded editorial commitment into a pipeline with a review step — and it is the same
pipeline that tells us when to move the manifest.

**Trial-to-paid is one command rather than a reinstall**, which is the difference between a
funnel and a wall. Any edition scheme that doubles [R0](../tasks/R0-release.md)'s pipeline
spends that milestone twice.

**Rejected — paywall the `regulated` profile.** Cleanest enforcement point, since a profile
is already one reviewable object. It contradicts 07 §4, paywalls security posture in a market
that is loud about that, and makes the free tier the homelab product the pivot decided is not
the market. The trial would be of the wrong product.

**Rejected — a node or seat ceiling with no feature split.** Whole product evaluable, no
forking. Fatal here specifically: an SMB under CMMC *is* four nodes and twelve users, so any
ceiling is either too low to trial or too high to ever bill.

**Rejected — two repositories, OSS core vendored by a private build.** The cleanest licensing
story. It doubles the release pipeline, splits CI, makes community-to-paid a reinstall, and
makes behavioural parity between editions something to maintain rather than something
structural.

**Rejected — stay fully Apache and sell services.** Zero licensing friction, strongest
community story. The product does not defend itself, and the customer able to self-serve the
binder is exactly the customer who would not buy the service.

**Rejected — relicense to BUSL.** Cheap now, with no outside contributors, and it stops
resale. It costs the open-source standing that makes the community edition a funnel, and
"source available" reads as closed to most of the people who would trial it.

**Rejected — consume the customer's scanner output instead of publishing a feed.** No content
obligation, no liability, ships fast. An SMB with four GPU boxes runs no scanner, and one
that does has already solved the part we would be selling. Scanner ingest is additive later.

## Consequences

**Gained.** A community edition that is a complete, defensible product, and a paid column
with two things in it that have real maintenance obligations rather than one formatter.

**Lost.** The repository is no longer uniformly Apache 2.0, and every contribution to `ee/`
carries a different licence. That is a permanent cost to the open-source story, accepted
because the alternative was a second repository.

**Cost.** Publishing the feed makes us a security-information vendor, with the disclosure
obligations that implies. A licence key is a support surface: expiry, clock skew and reissue
all become things a customer contacts us about.

**Reconsider if** the bet in [pivot §11](../plans/pivot-cmmc.md#11-what-this-bets-on) fails —
if buyers treat tooling as free and purchase assessment services from an RPO instead. The
paid column would then be worth little, and the business is support and hosting rather than
content.
