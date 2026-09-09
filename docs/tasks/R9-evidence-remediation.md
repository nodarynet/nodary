# R9 — Evidence and remediation

**Deliverable:** `ee/`, a signed license key, `nodary evidence export`, and the
signed advisory feed.
**Proves:** records become a deliverable an assessor consumes.
· [13](../specs/13-evidence.md),
[§6](../plans/pivot-cmmc.md#6-flaw-remediation--spec-14-adr-0007)

R9 is the commercial milestone [pivot §9](../plans/pivot-cmmc.md#9-roadmap-deltas) added.
It depends on [R1](R1-core-audit-identity.md)'s chain and [R2](R2-control-plane.md)'s
revisions, and everything it produces is a formatter over data those milestones already
hold — which is what makes it small, and what makes its **format** the expensive part.
Nothing here is security: [pivot §2.1](../plans/pivot-cmmc.md#21-the-open-core-line-operational-free-evidence-paid)
keeps the mechanism free and sells the knowing and the proving.

**The remediation citations are provisional.** [13](../specs/13-evidence.md) now exists and
the bundle tasks cite it. Spec 14 does not, so §"Flaw remediation" still cites
[the pivot](../plans/pivot-cmmc.md#6-flaw-remediation--spec-14-adr-0007); those links move
when it lands. · [tasks README](README.md#task-format)

R9 also has a route through it that is not the whole milestone:
[MVP §4](../plans/mvp.md#4-the-route) takes R9-01 – R9-09 and R9-12 in full, ships
R9-10, R9-11, R9-13, R9-14 and R9-15 as stubs, and leaves the rest.

## License and editions

- [x] **R9-01** `ee/` under a commercial license, with a pointer from the root `LICENSE`; everything outside it stays Apache 2.0 · [pivot §2.3](../plans/pivot-cmmc.md#23-one-binary-an-ee-directory-a-signed-license-key)
  - *done:* one binary still ships through the four existing channels, and the split is a directory rather than a build tag — an edition that needs its own pipeline spends [R0](R0-release.md) twice
- [x] **R9-02** `nodary license apply|show` — minisign verification against an embedded key, in [`internal/minisign`](../../internal/minisign/minisign.go)
  - *done:* applying a license is a mutation and lands in the chain, and the stored license is re-verified on every read rather than trusting a verdict recorded once — the row lives in a database an administrator can write
  - *note:* **not** a reuse of `components/verify.go`, which does digest checks over HTTP and holds no signature verification at all. The verifier is ~200 lines of standard library, shared with [R5-27](R5-install.md) and R9-14 · [ADR 0007](../adr/0007-independent-component-manifest.md)
  - *note:* `Ed`, never `ED`. Measured against minisign 0.11: **`minisign -S` writes a prehashed signature by default and `-l` is what asks for the legacy format**, so anything nodary verifies must be signed `-S -l`. The refusal names the flag, and the tests sign with the real binary in both directions including the no-flag default · [spike](../spike-fips-and-manifest.md)
  - *deps:* R1-12
- [x] **R9-03** An unlicensed install carries every commercial verb and explains what it would produce
  - *done:* `nodary evidence export` without a license names the bundle's members and refuses; the commercial surface is discoverable, never hidden · [pivot §2.3](../plans/pivot-cmmc.md#23-one-binary-an-ee-directory-a-signed-license-key)
  - *deps:* R9-02
- [x] **R9-04** An absent or expired license never makes existing evidence unreadable
  - *done:* a bundle produced under a license still verifies after it lapses, `audit export` is unaffected, and the bundle format is documented well enough to reconstruct a binder without nodary. This is the first property a careful buyer tests
  - *deps:* R9-02, R9-05

## The bundle

- [x] **R9-05** `nodary evidence export --from --to --out bundle.tar.gz` writing every member named in [13](../specs/13-evidence.md)
  - *done:* a member with no producer yet is present and declared empty rather than absent, so a member gaining rows later is not a format change. `manifest.json` carries a record count for every `.jsonl` member, because a zero-byte file cannot say whether nothing happened or nothing was written
  - *deps:* R1-11
- [x] **R9-06** `manifest.json` and `manifest.json.minisig` — a digest of every member, signed
  - *done:* the manifest lists members rather than fixing a schema per member
  - *deps:* R9-05
- [x] **R9-07** The bundle verifies with nodary not installed
  - *done:* an assessor with `sha256sum`, `minisign` and the documented procedure can check every digest and the chain itself. This is the property that makes the bundle worth money — a tarball, not a request to log into something
  - *note:* tested by running the documented commands against a real bundle with the real tools, in both directions: the checks pass, and an edited member fails them. A procedure asserted only against our own reimplementation would pass just as well if both sides were wrong in the same way
  - *deps:* R9-06
- [x] **R9-08** `chain.jsonl` — the audit segment for the period, with the anchoring hashes either side
  - *done:* the segment verifies standalone, without the records before or after it
  - *deps:* R1-09, R9-05
- [x] **R9-09** `verify.txt` — `audit verify` output over that segment
  - *deps:* R1-09, R9-05
- [x] **R9-10** `controls.json` and `controls.md` — the practice → evidence index, pointing at record sequences
  - *done:* until R9-19 lands, every entry carries its structure and `"status": "unmapped"`; a plausible guess here is worse than an absent member, because a customer pastes it into an SSP · [MVP §5.2](../plans/mvp.md#52-the-control-mapping-ships-as-a-stub-with-no-claims)
  - *deps:* R9-05
- [ ] **R9-11** `narratives/` — parameterized SSP text per practice, filled with this install's values
  - *done:* the parameters resolve from the install's real configuration, so a narrative naming a value nodary does not hold fails to render rather than emitting a placeholder into a deliverable
  - *deps:* R9-05, R9-19
- [x] **R9-12** `revisions.jsonl`, `nodes.json` and `identity.jsonl` — configuration history, approval records with the inventory offered at approval, and user and token lifecycle
  - *deps:* R2-11, R9-05
- [x] **R9-13** `remediation.jsonl` — what was known, decided, by whom, with what justification, and applied when
  - *done:* the member and its schema ship; the rows arrive with R9-17. It is written as one object saying the category exists and this install has nothing in it, which is an answer where a missing file is a question
  - *deps:* R9-05, R9-17

## Flaw remediation

- [x] **R9-14** The advisory feed format: signed, mapping component digest → advisory → recommended digest · [pivot §2.5](../plans/pivot-cmmc.md#25-the-advisory-feed-is-ours-signed-and-generated-rather-than-curated)
  - *done:* a revision carries an explicit statement of what the feed is — a report of what public sources say about digests we pin — and what it is not, which is a warranty
  - the statement is **enforced at parse time**: a revision without one does not decode. [ADR 0005 §3](../adr/0005-editions-and-the-advisory-feed.md) requires it *inside every revision, not only in documentation, because the revision is what outlives the sales conversation*, and that is the difference between a requirement and a note somebody remembers
  - matching is on the **digest**, never the version. A version string is what a project calls a release; a digest is what is on the disk, which is the whole point of [ADR 0007](../adr/0007-independent-component-manifest.md). `sha256:AAAA` and `aaaa` are the same artifact, because treating them as different would report a clean install — the one wrong answer this must never give
  - an unknown field is **refused, not ignored**: silently dropping a key is how a revision comes to say less than its publisher thinks it does, and the dropped one could be the one that matters
  - **its own key, not the license key**, though the mechanism is R9-02's. A license signs entitlements — low volume, long-lived, a key that can live offline — while a revision is *generated in CI* ([ADR 0005 §3](../adr/0005-editions-and-the-advisory-feed.md)), so its key must be reachable from a pipeline. One key for both would put a CI-accessible secret in the position of also minting licenses, and a feed-key rotation would invalidate every license in the field
- [x] **R9-15** `nodary advisory check` — feed revisions matched against pinned digests
  - *done:* an empty signed feed produces an honest empty result rather than an error; verification reuses the same trust root as R9-02
  - it prints **how many digests it checked**, because "nothing found" and "nothing looked at" read identically and only one is good news
  - **no license gate.** [ADR 0005 §1](../adr/0005-editions-and-the-advisory-feed.md) puts the mechanism free and the content paid, and possession of a *current* signed revision is itself the entitlement — an old one is worth nothing, which is what a subscription sells. Gating the verb as well would only stop somebody reading content we had already given them, so `internal/advisory` holds no license check at all
  - a missing feed and an empty feed are different answers. A site with no subscription is told there is no feed; a revision that found nothing says so and names the revision it read
  - there is **no unsigned mode**. An attacker who can substitute a feed can tell a site its runtime is fine, which is a more useful lie than any single forged advisory
  - *deps:* R9-14
- [ ] **R9-16** A known advisory with no decision after a configured interval becomes a POA&M item with a clock
  - *done:* inaction is visible. The property that nothing changes without an explicit human act is not weakened · [pivot §6](../plans/pivot-cmmc.md#6-flaw-remediation--spec-14-adr-0007)
  - *deps:* R9-15
- [ ] **R9-17** The decision — patch, defer with justification, or accept with a compensating control — as an audited mutation
  - *done:* no parallel workflow exists, because the chain already is the remediation record
  - *deps:* R1-12, R9-16
- [ ] **R9-18** Offline sites receive feed revisions through `nodary bundle create`
  - *deps:* R5-13, R9-14

## The mapping

- [~] **R9-19** Rewrite [07 §5](../specs/07-identity-audit.md#5-control-mapping) against 800-171 practice identifiers, transcribed from the publication
  - *done:* transcribed from the publication itself, not from memory and not from a model, and the section's opening — "most deployments will never need this section" — is reframed for the audience the pivot chose · [pivot §5](../plans/pivot-cmmc.md#the-mapping-is-owed-a-verification-pass)
  - **the reframe is done; the transcription is not, and deliberately so.** The table still carries 800-53 control families, and the section now says so in a block quote rather than letting the left column look like something to paste into a plan. A practice identifier recalled rather than transcribed is the one error in this document a customer would carry into an assessment — the same reason `controls.json` ships every entry as `"status": "unmapped"` rather than guessing
  - *blocked on:* the publication in hand. This row does not close from memory
  - *deps:* R9-20
- [ ] **R9-20** Settle which revision the narratives target
  - *done:* CMMC 2.0 Level 2 is understood to assess against 800-171 Rev 2 while Rev 3 exists and renumbers. Confirmed against the current rule rather than assumed, and recorded with the migration it implies
