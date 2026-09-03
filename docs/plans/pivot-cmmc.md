# Pivot — SMB CMMC as the primary market

**Changes:** README, [00](../specs/00-overview.md), [07](../specs/07-identity-audit.md),
[ADR 0003](../adr/0003-litellm-as-data-plane.md), [ADR 0004](../adr/0004-release-artifacts-and-channels.md) ·
**Adds:** specs 13–14, ADRs 0005–0007 · **Status:** in flight

Not a slice of a milestone. This plan re-aims the product at a buyer, and the specs
follow it rather than the other way round — which makes it the one plan in this
directory that changes what the authoritative documents say instead of describing how
to build what they already said.

## 1. What changed

[00 §1](../specs/00-overview.md#1-scope) names the target as "a homelab or a small
business with direct control of its hardware," with a regulated posture available as an
opt-in profile. That framing was written before anyone asked who pays.

The features that justify nodary's existence over four `docker compose` files — the hash
chain, `intent_hash` binding, required justification, provenance allowlists, retention
windows — are compliance ceremony. A homelab operator experiences all of it as friction
protecting them from nobody. The site that wants it is the site that has to demonstrate
control to a third party.

**The primary market is a small defence-supply-chain business under CMMC Level 2 that
wants on-prem inference because its prompts contain CUI.** The homelab is not deleted; it
becomes the community edition's story and the path by which the product is discovered and
dogfooded. `default` remains the profile a fresh install runs, because a first-run
experience that demands a TOTP code before a user exists converts nobody.

Everything below follows from that single change of audience.

## 2. Decisions

Recorded with what was rejected, per [the rule](README.md#the-rules) that a decision
without its alternatives is half-recorded.

### 2.1 The open-core line: operational free, evidence paid

**Decided.** Everything that runs the fleet is Apache 2.0 — control plane, agent, gateway,
every backend, both policy profiles, the full hash chain, `audit verify`, `audit export`,
enrollment, staging, guardrails, the FIPS build, the SIEM sink, OIDC. The commercial
edition sells what turns records into a deliverable a human assessor consumes.

**Why.** [07 §4](../specs/07-identity-audit.md#4-policy-profiles) already states that the
chain "is the product rather than a posture" and that no profile disables it. An edition
that disables it contradicts the spec, and a community edition without it is a worse
`docker compose` that nobody adopts and therefore nobody converts from.

The line states in one sentence: **we do not sell security, we sell the paperwork.**

**Rejected — paywall the `regulated` profile.** Cleanest enforcement point, since a
profile is already one reviewable object. It contradicts 07 §4, paywalls security posture
in a market that is loud about that, and makes the free tier the homelab product this
plan just decided is not the market. The trial would be of the wrong product.

**Rejected — a node or seat ceiling with no feature split.** Whole product evaluable, no
forking. Fatal here specifically: an SMB CMMC site *is* four nodes and twelve users, so
any ceiling is either too low to trial or too high to ever bill.

**Rejected — a hybrid feature line plus a soft size gate.** Two things to explain and get
wrong instead of one, for revenue protection against a customer profile that does not
exist in this market.

### 2.2 nodary sits inside the customer's CUI boundary

**Decided.** Assume prompts and completions are CUI. Make **"nodary records that a request
happened, never what it said"** a load-bearing, structurally enforced guarantee.

**Why.** A subcontractor wants on-prem inference precisely because the prompts are CUI —
that is the entire reason they are not calling a hosted API. The gateway proxies every
request, so an assessor will place it in scope whether or not the documentation does.
Being wrong about this in a sales cycle is more expensive than doing the work.

[06 §3](../specs/06-gateway.md#3-metering) already gets the hard part right by accident of
taste: it records token counts, latency, status and whether accounting was partial, and
never request content. This decision promotes that from a schema detail to the claim the
product is sold on.

**Rejected — optional content retention behind a policy flag.** Honest about what teams
want for debugging and eval, and enabling it would be audited. But it means the product
sometimes stores CUI, which weakens the claim to "can be configured not to" and lengthens
every assessor conversation. If it is ever needed it arrives as a separate, loudly-named
capability, not as a flag on the metering path.

**Rejected — position the control plane as out of boundary.** Much less engineering and
no FIPS obligation. Indefensible: the gateway is in the data path.

### 2.3 One binary, an `ee/` directory, a signed licence key

**Decided.** The repository stays public. Everything outside `ee/` stays Apache 2.0;
`ee/` carries a commercial licence and the root `LICENSE` gains a pointer. One binary
continues through the four existing channels. Commercial features are inert until
`nodary license apply` verifies a minisign-signed licence against an embedded key, reusing
[`internal/components/verify.go`](../../internal/components/verify.go) — no new crypto and
no new trust root. Applying a licence is a mutation and lands in the chain.

**Why.** [R0](../tasks/R0-release.md) is built and exercised: one signed binary, four
channels, tamper rejection tested end to end. Any edition scheme that doubles that
pipeline spends the milestone twice. Trial-to-paid becomes one command instead of a
reinstall, which is the difference between a funnel and a wall.

Two properties are **not negotiable**, because together they remove the strongest reason
not to buy:

1. An unlicensed install still carries the verb and explains what it would produce. The
   commercial surface is discoverable, never hidden.
2. **An expired licence never makes existing evidence unreadable.** The bundle format is
   documented and the raw chain export is free, so a customer can always reconstruct their
   binder without us. Compliance evidence held hostage by a lapsed subscription is a
   story that ends a company, and it is the first thing a careful buyer will test for.

**Rejected — two repositories, OSS core vendored by a private build.** The cleanest
licensing story, and the public repository would stay uniformly Apache. It doubles the
release pipeline, splits CI, makes community-to-paid a reinstall, and makes behavioural
parity between editions something to maintain rather than something structural.

**Rejected — stay fully Apache and sell services.** Zero licensing friction, strongest
community story. The product does not defend itself, and the customer able to self-serve
the binder is exactly the customer who would not buy the service.

**Rejected — relicense to BUSL.** Cheap now, with no outside contributors, and it stops
resale. It costs the open-source standing that makes the community edition a funnel, and
"source available" reads as closed to most of the people who would trial it.

### 2.4 The paid deliverable is a signed evidence bundle with narratives

**Decided.** `nodary evidence export` produces a signed bundle plus parameterised SSP
narrative text per practice, filled with the install's real values. Spec 13.

**Why.** The gap the customer is paying to close is between raw material and a deliverable.
The bundle is mostly a formatter over data the chain already holds, which makes it a
defensible v1; the narratives are markdown rather than code, which makes them cheap to
write and disproportionately valuable in a sales call.

**Rejected — the bundle alone, without narratives.** Ships fastest, no content to maintain
as the standard moves. It hands over raw material and leaves the customer exactly where
they started.

**Rejected — continuous posture monitoring in v1.** Where recurring revenue actually
lives, and what renewals are for. It is a subsystem rather than a formatter, and it
presumes R2 and R4 exist. Deferred deliberately, and named as the intended thickener.

### 2.5 The advisory feed is ours, signed, and generated rather than curated

**Decided.** nodary publishes a signed feed mapping component digest → advisory →
recommended digest, delivered online or inside a `bundle create` output. It is
**generated** — scanners run against our own pinned component set in CI, the delta against
the previous revision is reviewed by a human, then signed and published.

**Why.** It is the same business shape as the narratives: signed content with genuine
currency requirements, consumed by a free binary. It answers the one weakness in §2.1 —
that with FIPS, OIDC and the SIEM sink all free, the paid column was a formatter and some
markdown. Two content subscriptions with real maintenance obligations is a business; one
formatter is a feature.

Generating rather than curating turns an unbounded editorial commitment into a pipeline
with a review step, and it is the same pipeline that tells us when to move the manifest.

**Cost, stated plainly.** This makes us a security-information vendor. The feed must carry
an explicit statement of what it is — a report of what public sources say about digests we
pin — and what it is not, which is a warranty. That statement belongs in ADR 0005.

**Rejected — consume the customer's scanner output.** No content obligation, no liability,
ships fast. An SMB with four GPU boxes runs no scanner, and one that does has already
solved the part we would be selling.

**Rejected — both, feed and scanner ingest, in v1.** The natural end state and strictly
more useful. Two integrations to build and test for a product that has not yet shipped a
control plane. Scanner ingest is additive later.

## 3. What the CUI decision forces

### The guarantee is structural, not documentary

The metering record schema is **closed** — no free-text body field exists to write into —
and a test fails if request content reaches the database or a log. This is the same
technique as [the audit seam](../tasks/README.md#cross-cutting-constraints): a path that
must not exist is made unreachable rather than merely discouraged.

### FIPS is a build, not a rearchitecture

`GOFIPS140=v1.0.0` produces a second artifact through the four existing channels. This
works only because [ADR 0002](../adr/0002-go-with-package-manager-wrappers.md) chose a
single static binary and the SQLite driver is `modernc` rather than cgo-based: BoringCrypto
needs cgo and would break the static property
[R0 asserts in CI](../tasks/R0-release.md). The constraint was adopted for unrelated
reasons and pays for itself here.

Two consequences in code:

| | |
| :--- | :--- |
| **argon2id is not FIPS-approved** | [07 §1](../specs/07-identity-audit.md#1-users-and-roles) specifies it and [R2-42](../tasks/R2-control-plane.md) implements it. The approved password KDF is PBKDF2 (SP 800-132). R2-42 has not been built — it was deferred out of [R1c](R1c-identity.md) because nothing hashes a user row yet — so this costs a spec edit now and a rewrite later. Take PBKDF2 rather than argue to an assessor that password hashing does not protect CUI confidentiality; the argument may well be right and is still more expensive than the change |
| **TOTP uses HMAC-SHA-1** | [`totp.go:128`](../../internal/identity/totp.go), per RFC 6238, already shipped. HMAC-SHA-1 is understood to remain acceptable under SP 800-131A even though SHA-1 is disallowed for signatures, and SHA-1 retires in 2030. Whether Go's FIPS module permits it in this construction is **unknown and must be measured, not assumed** — it is an explicit output of the spike (§10) |

### LiteLLM is now a compliance surface

[ADR 0003](../adr/0003-litellm-as-data-plane.md) priced LiteLLM as a dependency on an
external release cadence and an extra network hop. Inside a CUI boundary it costs more
than that: it is a third-party process in the data path whose request logging, temporary
files and error paths are now ours to account for. "LiteLLM begins writing request bodies
somewhere by default" changes from a nuisance to an incident.

The mitigation is to render its configuration with logging pinned off and **assert it**,
on the same principle that makes [egress verification continuous rather than
configured](../specs/03-agent.md#5-egress-isolation). ADR 0003's "reconsider if" gains
this: if pinning proves insufficient, absorbing the proxy stops being a contained change
we might make and becomes one we have to.

### What does not change

Neither non-goal in [00 §1](../specs/00-overview.md#1-scope) blocks the pivot. CMMC does
not require high availability, and multi-tenant isolation is irrelevant inside one
company. Both stay non-goals, and saying so explicitly is worth more than leaving it to be
inferred.

## 4. The edition line

| Community — Apache 2.0 | Commercial — `ee/` |
| :--- | :--- |
| Control plane, agent, gateway, every backend | `nodary evidence export` — the signed bundle |
| Full hash chain, `audit verify`, `audit export` | Control index and SSP narratives |
| Both policy profiles, enrollment, staging, guardrails | The signed advisory feed |
| FIPS build, SIEM/WORM sink, OIDC | Posture monitoring — deferred, the renewal story |
| `upgrade`, derives, staged rollout, `doctor` | Support |

The mechanism is free; the knowing and the proving are paid. A community install can
always patch, always verify its own chain, and always export it. What it cannot do is be
told what to patch, or hand an assessor a bound artifact.

## 5. Evidence and assessment — spec 13

`nodary evidence export --from --to --out bundle.tar.gz`

| Member | Contents |
| :--- | :--- |
| `chain.jsonl` | The audit segment for the period, with the anchoring hashes either side so it verifies standalone |
| `verify.txt` | `audit verify` output over that segment |
| `controls.json`, `controls.md` | Practice → evidence index, pointing at record sequences |
| `narratives/` | Parameterised SSP text per practice, filled with this install's values |
| `revisions.jsonl` | Configuration revision history |
| `nodes.json` | Approval records with offered inventory as at approval |
| `identity.jsonl` | User and token lifecycle |
| `remediation.jsonl` | §6 — what was known, decided, and applied |
| `manifest.json` + `.minisig` | Digest of every member, signed |

**The property that makes it worth money: the bundle verifies without nodary installed.**
An assessor receives a tarball and a documented procedure, not a request to log into
something.

### The mapping is owed a verification pass

[07 §5](../specs/07-identity-audit.md#5-control-mapping) currently maps to 800-53 control
identifiers — AU-2, AC-3, SC-7. A CMMC assessor works from 800-171 practice identifiers.
The table is in the wrong vocabulary for the audience this plan just chose, and its
opening line, "most deployments will never need this section," is now exactly backwards.

**The practice identifiers must be transcribed from the publication, not from memory or
from a model.** This document deliberately does not enumerate them: a mapping table is the
one artifact in the product where being approximately right is worse than being absent,
because a customer will paste it into an SSP. Rewriting 07 §5 is a task with a citation
requirement, tracked in §7.

One live question to settle in the same pass: **CMMC 2.0 Level 2 is understood to assess
against 800-171 Rev 2**, while Rev 3 exists and renumbers. Which revision the narratives
target is a product decision with a migration behind it, and it must be confirmed against
the current rule rather than assumed.

## 6. Flaw remediation — spec 14, ADR 0007

### The tension to resolve

Every property nodary has was chosen so that **nothing changes without an explicit human
act**: components digest-pinned in a manifest embedded in the binary, backend images
pinned, [derives never rebuilt on a base bump](../specs/04-backends.md#building), nodes
with no egress, `allow.package_install = false`. 800-171 asks that flaws be corrected in a
timely manner. These pull against each other, and the resolution is designed here rather
than discovered in an assessment.

The resolution is **not** to weaken the property. It is to keep every change explicit and
audited, and make *inaction* visible instead.

### ADR 0007 — the component manifest becomes an independent artifact

**This is the item to do first if only one gets done.**

[ADR 0004](../adr/0004-release-artifacts-and-channels.md) embeds the manifest in the
binary and names the maintenance burden. Under CMMC it is worse than a burden: containerd
ships a fix and the customer cannot take it until we cut a release. **We would have
coupled every customer's patch timeline to our release cadence, and their assessor holds
them to a window we do not control.**

The manifest becomes separately versioned and separately signed. The binary keeps its
embedded copy as a floor; a signed manifest revision supersedes it, verified identically,
delivered online or through `bundle create`. Every property ADR 0004 argued for survives —
pinned, signed, verified in Go rather than in shell — and only the embedding goes. ADR
0004 stays Accepted and gains a pointer; it is amended, not superseded, because its
reasoning still holds.

### Backend images: the honest answer is not patching

A vLLM image is PyTorch, CUDA and a Linux userland. A scanner will report hundreds of
findings against it on any given day, most unfixed upstream. No SMB will remediate that,
and a product that implies they should sets up a failed assessment.

The answer is documented risk acceptance with a compensating control, **and the
compensating control is already built.** A finding that requires network reachability, in
a container with no default route, no DNS and a port bound to loopback, with
[`verify-egress` asserting it after every start](../specs/03-agent.md#5-egress-isolation),
is a materially different risk from the same finding on a reachable host. Made per-finding
with the assertion attached as evidence, that is a POA&M entry an assessor can accept.

It is also narrative content nobody else can write, because nobody else has the assertion.

When a fix genuinely must land ahead of upstream,
[derived images already are the mechanism](../specs/04-backends.md#5-derived-images) — §5
names a CVE backport as a motivating case. It is built. Nothing currently tells anyone to
use it.

### Know, decide, apply, prove

| | |
| :--- | :--- |
| **Know** | The signed advisory feed (§2.5), matched against pinned digests. Offline sites receive revisions through `bundle create` |
| **Decide** | Never automatic. A known advisory with no decision after a configured interval becomes a POA&M item with a clock. The decision — patch, defer with justification, or accept with a compensating control — is an audited mutation, so **the chain already is the remediation record** and no parallel workflow is needed |
| **Apply** | [R5-15](../tasks/R5-install.md) extends from whole-version upgrade to per-component update: staged node by node, drained, health-gated, rolling back to the previous digest on failure, inside the maintenance window [node.toml already defines](../specs/12-node-guardrails.md) |
| **Prove** | `remediation.jsonl` in the bundle: known, decided, by whom, with what justification, applied when |

### What nodary does not manage, it reports

Host OS patch level and NVIDIA driver version are outside nodary's control and stay there
— `allow.package_install = false` is correct and should not change. Node inventory and
`doctor` surface both, so the bundle can state what is managed elsewhere rather than
leaving a gap an assessor has to ask about.

## 7. Spec corrections this plan owes

Per [the rules](README.md#the-rules), a plan that finds a spec wrong records it as an open
item until the spec is corrected. All of these are open.

| Document | Correction |
| :--- | :--- |
| [00 §1](../specs/00-overview.md#1-scope) | Target inverts: regulated small site primary, homelab is the community edition. `default` stays the fresh-install profile — say why |
| [00 §5](../specs/00-overview.md#5-trust-boundaries) | Add the CUI boundary row |
| [00 §8](../specs/00-overview.md#8-milestones) | R9 added |
| [07 §1](../specs/07-identity-audit.md#1-users-and-roles) | argon2id → PBKDF2 under FIPS |
| [07 §5](../specs/07-identity-audit.md#5-control-mapping) | Rewrite against 800-171 practice identifiers, transcribed from the publication. Reframe the opening |
| [ADR 0003](../adr/0003-litellm-as-data-plane.md) | "Reconsider if" gains the CUI-surface condition |
| [ADR 0004](../adr/0004-release-artifacts-and-channels.md) | Pointer to ADR 0007 |
| `README.md` | Lead with the CUI and CMMC framing; editions table; the notary thesis becomes the headline rather than a footnote |

## 8. New documents

| | |
| :--- | :--- |
| **ADR 0005** | Editions, the licence key, and the advisory feed's liability statement |
| **ADR 0006** | The CUI boundary and the FIPS build |
| **ADR 0007** | The component manifest as an independently versioned artifact |
| **Spec 13** | Evidence and assessment |
| **Spec 14** | Flaw remediation |

## 9. Roadmap deltas

| | |
| :--- | :--- |
| R0 / R5 | FIPS artifact through the four channels; manifest revisions; `upgrade` extends to per-component staged rollout |
| R2-42 | PBKDF2, not argon2id |
| R2-41 | SIEM sink unchanged, stays core, stays where it is |
| **R9 — evidence and remediation** | New. Depends on R1's chain and R2's revisions; lands after R2 |
| OIDC | Still a later swap behind the same interface. Now community |

## 10. The spike

**Before resuming R1.** Two days, thrown away, output is a memo in `docs/`.

One GPU host, one vLLM container under a hand-written systemd unit rendered by throwaway
Go, weights from a local path, a health probe. Then a `GOFIPS140=v1.0.0` build of the
current tree.

It answers four questions that are currently answered by assumption:

1. What does unit rendering actually need, and what does containerd GPU binding really
   look like? [ADR 0001](../adr/0001-no-orchestrator.md)'s accepted risk — "nodary now
   owns a distributed system" — is unexercised, and R2 through R5 are being written
   against it.
2. Does the FIPS build compile and pass the existing suite?
3. **Does HMAC-SHA-1 survive it?** §3.
4. Can a manifest revision be verified independently of the binary? ADR 0007 is
   load-bearing and unproven.

## 11. What this bets on

Stated so it can be checked later rather than quietly revised.

- **That an SMB under CMMC will buy compliance artefacts from an infrastructure vendor.** If they buy assessment services from an RPO instead and treat tooling as free, the paid column is worth little and the business is support and hosting.
- **That the advisory feed can be generated cheaply enough to keep current.** If it needs sustained editorial work, it becomes the most expensive thing here and it is the one that visibly rots when neglected.
- **That being in the CUI boundary is a moat and not a millstone.** It buys the strongest claim available in this market and imposes FIPS, a third-party process to account for, and a guarantee that must never be broken by an error message.
- **That R4 is roughly the size R4 looks.** §10 exists because nothing has tested it.

## Steps

- [ ] ADR 0007 — the independent manifest. First, per §6
- [ ] ADR 0006 — CUI boundary and FIPS
- [ ] ADR 0005 — editions, licence key, feed liability
- [ ] Spec 13 — evidence and assessment
- [ ] Spec 14 — flaw remediation
- [ ] Spec corrections, §7 — 07 §5 last, it needs the publication open
- [ ] README
- [ ] Tracker: R9, R2-42, R0/R5 deltas, plans README row
- [ ] The spike, §10
