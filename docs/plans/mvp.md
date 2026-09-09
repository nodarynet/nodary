# MVP — the shortest honest route

**Route through:** [R1](../tasks/R1-core-audit-identity.md) – [R5](../tasks/R5-install.md),
[R9](../tasks/R9-evidence-remediation.md) · **Status:** proposed

Not a slice. [Pivot](pivot-cmmc.md) chose the buyer; this chooses the order, and its only
question is what a first customer can be shown without building something that has to be
unbuilt. It does not change what a specification says — where it finds one wrong it waits
for the correction, per [the rules](README.md#the-rules).

## 1. What MVP means here

One control-plane host, one GPU node, one model, a dozen users, and an evidence bundle
that verifies. Demonstrable end to end, and **not qualified for CMMC** — §6 names every
gap, and each one is a stub with a task number rather than an omission.

The target is not a slice of the product. It is the whole shape of the product with the
content missing, which is the opposite of the usual MVP and is forced by what nodary
sells: a customer who receives a bundle holds a format we then owe them forever.

## 2. The rule that decides what gets built

Not cost. **What cannot be retrofitted.**

| | | Why it cannot wait |
| :--- | :--- | :--- |
| **Preimage** | canonical JSON, the audit record's fields, `intent_hash` | It sits inside a hash. Adding a field later invalidates every chain a customer has already exported, and the export is the thing they keep |
| **Seam** | `audit.Act`, the closed metering schema, one core behind CLI and API | A path that must not exist has to be unreachable rather than merely unwritten · [tasks README](../tasks/README.md#cross-cutting-constraints) |
| **Format** | bundle member names, the manifest as an independent artifact, evidence surviving a lapsed license | A compatibility surface the moment one customer holds one |

Everything else is **content or conformance** — SSP narratives, the 800-171 mapping,
advisory entries, FIPS validation, POA&M clocks, posture monitoring, OIDC — and content
can arrive later without moving anything already written.

## 3. Stub discipline

The mechanism exists: [`cli.go`](../../internal/cli/cli.go)'s `planned` map already prints
*specified, not yet implemented* for every verb R0 did not build. Three rules extend it.

1. **A stub is a real verb with real output shape**, honest in its data — a `controls.json`
   whose entries say `"status": "unmapped"`, not an absent member and not a plausible
   guess. This is [pivot §2.3](pivot-cmmc.md#23-one-binary-an-ee-directory-a-signed-license-key)'s
   first non-negotiable applied one level down: the commercial surface is discoverable, and
   so is the unfinished one.
2. **Every stub carries a task number.** A `TODO` nobody numbered is scope nobody agreed to.
3. **No stub may later change a hash preimage or a bundle member name.** If it would, it is
   not a stub — it belongs in §2's first column and gets built now.

## 4. The route

| | Slice | Contains | Notes |
| :--- | :--- | :--- | :--- |
| **S0** | The spike | [pivot §10](pivot-cmmc.md#10-the-spike), unchanged | First. Two days, thrown away. It is the only thing that prices S4 |
| **S1** | Documents that constrain code | ADR 0007, ADR 0006, ADR 0005, spec 13 | Four of the eight documents [pivot §7–8](pivot-cmmc.md#7-spec-corrections-this-plan-owes) owes. The rest are content and wait |
| **S2** | Finish R1 | R1-13 – R1-17, R1-25 – R1-31 | The R1d and R1e slices [R1c](R1c-identity.md) named. Nothing after this can be written without attestation and profiles |
| **S3** | Evidence export | R9-01 – R9-09, R9-12; R9-10, R9-11, R9-13 as stubs | Out of order deliberately — §5.1 |
| **S4** | R2 thin | R2-01, R2-04 – R2-13, R2-15 – R2-20, R2-24 – R2-26, R2-28 – R2-31, R2-33 – R2-36, R2-39, R2-40 | ~24 of 42. Deferred: pagination, `If-Match`, `Idempotency-Key`, backends API, usage API, retention, backup, the SIEM sink |
| **S5** | R4 thin | R4-01 – R4-04, R4-07 – R4-09, R4-13, R4-18 – R4-20, R4-26, R4-27, R4-29, R4-34, **and R6-01 – R6-03** | ~14 of 37, and the plan's whole risk — §7. The three R6 tasks are a prerequisite this route missed: an agent cannot render an argv without a descriptor, and [04 §1](../specs/04-backends.md#1-why-descriptors-rather-than-plugins) already embeds them in the binary · [R4b §1](R4b-backends-and-the-plan.md) |
| **S6** | R3 thin | R3-01 – R3-06, R3-12, R3-15, R3-16 | Metering is closed here or never — §2 |
| **S7** | R5 thin | R5-01, R5-02, R5-04, R5-05, R5-08 – R5-12, R5-18, R5-25 | Deferred: offline bundle, upgrade, uninstall, WSL2 |
| **S8** | The remaining stubs | R9-14, R9-15 | The feed's format and an empty signed revision, so the verb exists and the shape is fixed |

S0–S3 are worth reaching on their own: they produce a signed bundle from a real chain,
which is the paid artifact, without a fleet under it.

## 5. Decisions

### 5.1 Evidence export lands before the control plane

**Decided.** S3 sits between R1 and R2, out of milestone order.

**Why.** The bundle's only input that exists today is the chain, and the chain is finished.
Building the format while it has one producer is the cheapest it will ever be, and the
format is the thing §2 says we can never take back. It also makes the commercial artifact
demonstrable months before the fleet works, which is the only way to test
[pivot §11](pivot-cmmc.md#11-what-this-bets-on)'s first bet — that anyone will pay for it —
while it is still cheap to be wrong.

**Rejected — build it last, in milestone order.** Every member would have a real producer
and no stub would be needed. It puts the one irreversible format decision at the end of the
schedule, where it is discovered by a customer rather than by us, and it delays the only
question worth answering early.

**Rejected — defer the format and ship `audit export` as the evidence story.** Free, and
already built. It hands over raw material, which is precisely the gap
[pivot §2.4](pivot-cmmc.md#24-the-paid-deliverable-is-a-signed-evidence-bundle-with-narratives)
says the customer is paying to close.

**The cost, stated:** `revisions.jsonl` and `nodes.json` are written against R2 and R4
tables that do not exist. They ship as declared-empty members with their schema, and
`manifest.json` lists members rather than fixing a schema per member, so a member gaining
rows later is not a format change.

### 5.2 The control mapping ships as a stub with no claims

**Decided.** `controls.json` and `controls.md` carry the index structure and mark every
practice `"status": "unmapped"`. R9-19 stays open.

**Why.** [Pivot §5](pivot-cmmc.md#the-mapping-is-owed-a-verification-pass) is right that a
mapping table is the one artifact where approximately right is worse than absent, because a
customer pastes it into an SSP. A stub that says so is honest; it also shows the assessor
the shape of what is coming, which a missing member does not.

**Rejected — ship 07 §5's existing 800-53 identifiers.** They are real, transcribed, and
already in the specification. They are the wrong vocabulary for a CMMC assessor, and a
customer would map them by hand and attribute the result to us.

**Rejected — transcribe 800-171 now.** It is the correct end state and it is not hard. It
needs the publication open and a decision on Rev 2 versus Rev 3 (R9-20) that must be
confirmed against the current rule; done under schedule pressure it produces exactly the
approximately-right table this decision exists to avoid.

### 5.3 Egress isolation is built; node guardrails are not

**Decided.** S5 takes R4-26, R4-27 and R4-29 in full, and takes only R4-13 from the
guardrails group — `node.toml` parsed, nothing enforced beyond it.

**Why.** They look like the same kind of work and are not.
[Pivot §6](pivot-cmmc.md#backend-images-the-honest-answer-is-not-patching) rests the entire
flaw-remediation narrative on egress isolation being *asserted after every start*: a
finding that needs network reachability, in a container with no route, is a POA&M entry an
assessor accepts, and nobody else can write that narrative because nobody else has the
assertion. Remove it and the paid content has no argument in it. Guardrails, by contrast,
protect an operator from themselves on a machine they own, and their absence is visible
rather than silent.

**Rejected — defer egress too and describe the intended control.** Roughly a week of S5
back. It converts the strongest sentence in the product into a promise, and it is the one
claim a technically curious buyer will test in the demo.

### 5.4 Staging is local-path only

**Decided.** R4-34, the air-gapped path. R4-33's resumable remote download is deferred.

**Why.** [04 §5](../specs/04-backends.md) already treats local staging as first-class
rather than a workaround, and a defense subcontractor is the buyer most likely to be
running without egress anyway. It removes resumability, partial-transfer recovery and disk
-full handling from the MVP for a demo path that is `cp`.

**Rejected — remote staging first, as the default experience.** Better for the community
funnel and for our own dogfooding. It is the larger half of the staging work and it serves
the audience the pivot demoted.

### 5.5 One license check, no edition build

**Decided.** As [pivot §2.3](pivot-cmmc.md#23-one-binary-an-ee-directory-a-signed-license-key)
already decided — `ee/`, a signed key, verified through
[`components/verify.go`](../../internal/components/verify.go). The MVP adds nothing to it
and takes nothing from it, including R9-04: an absent or expired license must not make an
existing bundle unreadable, and that test lands with the first bundle rather than later.

**Rejected — skip licensing entirely for the MVP.** Nothing to build, and the funnel is a
later problem. R9-04 is the property a careful buyer tests first, and a test written after
the fact is written against code that already assumed the other answer.

### 5.6 FIPS builds in CI and does not gate

**Decided.** R5-25 adds a `GOFIPS140=v1.0.0` job that builds and reports. Failing it does
not fail the pull request, and no artifact ships.

**Why.** The spike's third question — whether TOTP's HMAC-SHA-1 survives the FIPS module —
is currently answered by assumption. A non-gating job answers it continuously and for free
from the day the spike ends. Gating on it would block every pull request on a dependency
we have not yet measured, in service of a claim the MVP explicitly does not make.

**Rejected — gate immediately.** It makes the constraint real and prevents drift. It stops
all work on the first unrelated FIPS incompatibility, which is the wrong trade before the
product runs.

## 6. What an MVP install cannot claim

Written down so it is not overstated in a room. Each row has a task number, which is the
honest form of "it is on the roadmap".

| Gap | Where it lands |
| :--- | :--- |
| No 800-171 practice mapping | R9-19, R9-20 |
| No SSP narrative content beyond a worked example | R9-11 |
| No flaw-remediation record — the member exists and is empty | R9-13, R9-16 – R9-18 |
| No advisory feed content | R9-14, R9-15 |
| No FIPS-validated build shipped | R5-25, R5-26 |
| No offline install, no upgrade path | R5-13 – R5-17 |
| No node guardrail enforcement — the limits are reported, not enforced | R4-14 – R4-16 |
| No remote weight staging | R4-33 |
| Password hashing still specified as argon2id | 07 §1, open — §8 |

## 7. The risk

**S5 is the plan.** [ADR 0001](../adr/0001-no-orchestrator.md)'s accepted risk — that
nodary now owns a distributed system — is unexercised, and S4 through S7 are written
against it. If the spike says unit rendering and containerd GPU binding are twice their
apparent size, the fallback is to ship **S0–S4 plus S6 and S7 as a single-box control
plane and gateway**, with no agent and no fleet. That still installs, still meters, still
exports a bundle that verifies, and still demonstrates the thing being sold. It is a
smaller product, not a broken one, and deciding that now is cheaper than deciding it in
month three.

## 8. Open items

This plan waits on corrections [pivot §7](pivot-cmmc.md#7-spec-corrections-this-plan-owes)
owes, and does not pre-empt them:

- **07 §1 still specifies argon2id.** R2-42 therefore still says argon2id, and is correct
  until the specification changes. S1 makes the edit; the tracker follows it, not this plan.
- **00 §8 does not yet list R9.** [R9](../tasks/R9-evidence-remediation.md) exists in the
  tracker and cites [pivot §5–6](pivot-cmmc.md#5-evidence-and-assessment--spec-13) until
  specs 13 and 14 land, at which point every citation in it moves.
- **Specs 13 and 14 do not exist.** S1 writes 13; 14 waits, and R9's remediation tasks are
  unstarted rather than blocked, since none is in the MVP.

## Steps

- [x] S0 — the spike, [pivot §10](pivot-cmmc.md#10-the-spike) — [memo](../spike-fips-and-manifest.md)
  - two findings change S1's documents rather than waiting for a milestone: ADR 0005 and
    ADR 0007 both need a signature verifier written in Go, and the sealing format decision
    has a deadline at [R2-40](../tasks/R2-control-plane.md) rather than at the FIPS artifact
  - §7's risk is **reduced, not cleared**: unit rendering is the size it looked, but the
    spike ran on docker rather than containerd, and `nodary-isolated` is where the sharp
    edge is — [R4-26](../tasks/R4-agent.md) gains an ingress assertion it did not have
- [x] S1 — ADR 0007, ADR 0006, ADR 0005, spec 13, and the 07 §1 correction
  - ADR 0006 picks `fips140=on` and names the two gates to `only`; the sealing-format gate
    has a hard deadline at [R2-40](../tasks/R2-control-plane.md)
- [x] S2 — R1d policy, R1e attestation — R1 complete, 36 of 36
- [x] S3 — evidence export and the license key
- [x] S4 — R2 thin — 28 of 42; the MVP subset complete
- [x] S5 — R4 thin — every listed row except **R6-02**, which stays partial by design: vLLM and
  SGLang are embedded, and llama.cpp and TensorRT-LLM need `[backend.extra]` and
  `[backend.prepare]`. A descriptor embedded whose features are unimplemented would be a
  backend the binary claims to support and cannot run
- [x] S6 — R3 thin
- [x] S7 — R5 thin — verified as root on a real host: 36 checks, 0 failures, including a live
  container on `nodary-isolated` proving egress dead and ingress alive
- [x] S8 — the advisory feed's format and an empty signed revision
