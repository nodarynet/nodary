# R9 — Evidence and remediation

**Deliverable:** `ee/`, a signed licence key, `nodary evidence export`, and the
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

## Licence and editions

- [ ] **R9-01** `ee/` under a commercial licence, with a pointer from the root `LICENSE`; everything outside it stays Apache 2.0 · [pivot §2.3](../plans/pivot-cmmc.md#23-one-binary-an-ee-directory-a-signed-licence-key)
  - *done:* one binary still ships through the four existing channels, and the split is a directory rather than a build tag — an edition that needs its own pipeline spends [R0](R0-release.md) twice
- [ ] **R9-02** `nodary license apply|show` — minisign verification against an embedded key, reusing [`internal/components/verify.go`](../../internal/components/verify.go)
  - *done:* no new crypto and no new trust root; applying a licence is a mutation and lands in the chain
  - *deps:* R1-12
- [ ] **R9-03** An unlicensed install carries every commercial verb and explains what it would produce
  - *done:* `nodary evidence export` without a licence names the bundle's members and refuses; the commercial surface is discoverable, never hidden · [pivot §2.3](../plans/pivot-cmmc.md#23-one-binary-an-ee-directory-a-signed-licence-key)
  - *deps:* R9-02
- [ ] **R9-04** An absent or expired licence never makes existing evidence unreadable
  - *done:* a bundle produced under a licence still verifies after it lapses, `audit export` is unaffected, and the bundle format is documented well enough to reconstruct a binder without nodary. This is the first property a careful buyer tests
  - *deps:* R9-02, R9-05

## The bundle

- [ ] **R9-05** `nodary evidence export --from --to --out bundle.tar.gz` writing every member named in [13](../specs/13-evidence.md)
  - *done:* a member with no producer yet is present and declared empty rather than absent, so a member gaining rows later is not a format change
  - *deps:* R1-11
- [ ] **R9-06** `manifest.json` and `manifest.json.minisig` — a digest of every member, signed
  - *done:* the manifest lists members rather than fixing a schema per member
  - *deps:* R9-05
- [ ] **R9-07** The bundle verifies with nodary not installed
  - *done:* an assessor with `sha256sum`, `minisign` and the documented procedure can check every digest and the chain itself. This is the property that makes the bundle worth money — a tarball, not a request to log into something
  - *deps:* R9-06
- [ ] **R9-08** `chain.jsonl` — the audit segment for the period, with the anchoring hashes either side
  - *done:* the segment verifies standalone, without the records before or after it
  - *deps:* R1-09, R9-05
- [ ] **R9-09** `verify.txt` — `audit verify` output over that segment
  - *deps:* R1-09, R9-05
- [ ] **R9-10** `controls.json` and `controls.md` — the practice → evidence index, pointing at record sequences
  - *done:* until R9-19 lands, every entry carries its structure and `"status": "unmapped"`; a plausible guess here is worse than an absent member, because a customer pastes it into an SSP · [MVP §5.2](../plans/mvp.md#52-the-control-mapping-ships-as-a-stub-with-no-claims)
  - *deps:* R9-05
- [ ] **R9-11** `narratives/` — parameterised SSP text per practice, filled with this install's values
  - *done:* the parameters resolve from the install's real configuration, so a narrative naming a value nodary does not hold fails to render rather than emitting a placeholder into a deliverable
  - *deps:* R9-05, R9-19
- [ ] **R9-12** `revisions.jsonl`, `nodes.json` and `identity.jsonl` — configuration history, approval records with the inventory offered at approval, and user and token lifecycle
  - *deps:* R2-11, R9-05
- [ ] **R9-13** `remediation.jsonl` — what was known, decided, by whom, with what justification, and applied when
  - *deps:* R9-05, R9-17

## Flaw remediation

- [ ] **R9-14** The advisory feed format: signed, mapping component digest → advisory → recommended digest · [pivot §2.5](../plans/pivot-cmmc.md#25-the-advisory-feed-is-ours-signed-and-generated-rather-than-curated)
  - *done:* a revision carries an explicit statement of what the feed is — a report of what public sources say about digests we pin — and what it is not, which is a warranty
- [ ] **R9-15** `nodary advisory check` — feed revisions matched against pinned digests
  - *done:* an empty signed feed produces an honest empty result rather than an error; verification reuses the same trust root as R9-02
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

- [ ] **R9-19** Rewrite [07 §5](../specs/07-identity-audit.md#5-control-mapping) against 800-171 practice identifiers, transcribed from the publication
  - *done:* transcribed from the publication itself, not from memory and not from a model, and the section's opening — "most deployments will never need this section" — is reframed for the audience the pivot chose · [pivot §5](../plans/pivot-cmmc.md#the-mapping-is-owed-a-verification-pass)
  - *deps:* R9-20
- [ ] **R9-20** Settle which revision the narratives target
  - *done:* CMMC 2.0 Level 2 is understood to assess against 800-171 Rev 2 while Rev 3 exists and renumbers. Confirmed against the current rule rather than assumed, and recorded with the migration it implies
