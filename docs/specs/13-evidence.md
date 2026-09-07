# 13 — Evidence and assessment

An assessor does not log into things. They receive a folder, read it, and ask questions about
what is in it. Everything nodary records exists so that folder can be produced without a
week of screenshots, and this document specifies the folder.

The bundle is a **commercial** capability ([ADR 0005](../adr/0005-editions-and-the-advisory-feed.md)).
The chain it is built from, and `audit export` over that chain, are free and always will be.

## 1. The command

```sh
nodary evidence export --from 2026-01-01 --to 2026-03-31 --out q1-bundle.tar.gz
```

`--from` and `--to` bound the reporting period. Every member covers that period and no more,
except where a member must reach outside it to remain verifiable — see `chain.jsonl`.

Without a licence the command **names every member it would produce, explains what each one
is for, and exits non-zero without writing a file.** The commercial surface is discoverable;
it is never silent and never hidden.

## 2. Members

| Member | Contents |
| :--- | :--- |
| `chain.jsonl` | The audit segment for the period, with the anchoring hashes either side so it verifies standalone |
| `verify.txt` | `audit verify` output over that segment |
| `controls.json`, `controls.md` | Practice → evidence index, pointing at record sequences |
| `narratives/` | Parameterised SSP text per practice, filled with this install's values |
| `revisions.jsonl` | Configuration revision history |
| `nodes.json` | Approval records with the inventory offered as at approval |
| `identity.jsonl` | User and token lifecycle |
| `remediation.jsonl` | What was known, decided, by whom, with what justification, and applied when · [pivot §6](../plans/pivot-cmmc.md#6-flaw-remediation--spec-14-adr-0007), pending spec 14 |
| `manifest.json` + `manifest.json.minisig` | Digest of every member, signed |

**Every member is always present.** A member with no producer yet, or no rows in the period,
is written empty with its schema rather than omitted. An assessor who sees a file with a
header and no rows learns something; an assessor who sees a missing file has to ask.

`manifest.json` lists members and their digests. It does not fix a schema per member, so a
member gaining rows in a later release is not a format change.

## 3. The bundle verifies without nodary installed

**This is the property that makes it worth money.** An assessor receives a tarball and a
documented procedure, not a request for access to a system.

```sh
tar xzf q1-bundle.tar.gz && cd q1-bundle
minisign -Vm manifest.json -P "$(cat nodary-release.pub)"   # the manifest is authentic
sha256sum -c manifest.sha256                                # every member matches it
```

Verifying the chain itself needs nothing but a SHA-256 implementation: each record's `hash` is
the digest of its canonical JSON including `prev_hash`
([07 §3](07-identity-audit.md#3-the-audit-chain)), and the procedure to walk it is written into
`verify.txt`'s header rather than assumed. `chain.jsonl` carries the anchoring hash on either
side of the period so the segment chains to something the reader can check, rather than
beginning at a record with no predecessor.

Nothing in this procedure requires the `nodary` binary, a licence, or a network. A bundle
produced under a licence that has since expired verifies exactly the same way
([ADR 0005](../adr/0005-editions-and-the-advisory-feed.md)).

## 4. Control mapping

`controls.json` maps each practice to the evidence that demonstrates it, by record sequence
rather than by prose:

```json
{ "practice": "3.3.1", "status": "mapped",
  "evidence": [ { "member": "chain.jsonl", "seq": [1204, 1207, 1319] } ] }
```

**Until the mapping is transcribed from the publication, every entry carries
`"status": "unmapped"` and no `evidence` array.** A mapping table is the one artifact in the
product where being approximately right is worse than being absent, because a customer pastes
it into an SSP. The structure ships so the shape is visible; the claims do not ship until they
are checked against the source ([R9-19](../tasks/R9-evidence-remediation.md)).

[07 §5](07-identity-audit.md#5-control-mapping) is the mapping's home, and it is currently
written against 800-53 control identifiers rather than 800-171 practices. Which revision of
800-171 the narratives target is a product decision with a migration behind it
([R9-20](../tasks/R9-evidence-remediation.md)).

## 5. Narratives

`narratives/` holds one markdown file per practice, written as a template and rendered with
this install's real values — the active policy profile, the retention window, the node count,
the egress-verification result, the actual configuration rather than a description of a
typical one.

**A narrative that names a value nodary does not hold fails to render.** It does not emit a
placeholder, and it does not quietly omit the sentence. A deliverable that reaches an assessor
containing `{{ retention_days }}` is worse than one that was never produced, because the
customer has already sent it.

## 6. What the bundle does not claim

Stated in the bundle itself, not only here, because the bundle is what outlives the
conversation.

- **Host OS patch level and GPU driver version are outside nodary's control**
  (`allow.package_install = false` is deliberate). Node inventory and `doctor` report both, so
  the bundle states what is managed elsewhere rather than leaving a gap an assessor must ask
  about.
- **The bundle is evidence, not an assessment.** It reports what happened on this install. It
  does not assert that the install satisfies any practice, and nothing in it should be read as
  a certification.
