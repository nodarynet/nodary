# Pilot — from demonstrable to defensible

**Route through:** the [2026-09-11 review](../review-2026-09-11.md) · **Status:** proposed ·
**Supersedes the ordering in** [mvp.md](mvp.md), not its decisions

[mvp.md](mvp.md) reached every step it set: S0–S8 are checked, and `install → enroll →
approve → stage → apply → reconcile → completion` runs on real hardware. An external
adoption review at `cc77239` nevertheless returned *pilot on non-CUI workload, do not cite
in the SSP*. Both are true, and the gap between them is what this plan is for.

## 1. The row mvp.md §2 was missing

That plan decides what gets built by one rule — **what cannot be retrofitted** — and names
three columns: Preimage, Seam, Format. The review found a fourth.

| | | Why it cannot wait |
| :--- | :--- | :--- |
| **Claim** | the README, `policy show`, the editions table | A reader who is told a control is enforced, tests it, and finds a column nothing reads does not come back to read the correction. It is un-sayable rather than un-buildable |

This is why the plan could complete and the product still not be handed to anyone. MVP was
defined as *what runs*; the review measured *what is said*. The correction is cheap, and it
is the half that is irreversible, so it goes first.

The project already keeps the honest list — [mvp.md §6](mvp.md#6-what-an-mvp-install-cannot-claim).
The failure is that it lives in a plan and the overstatement lives on the front page.

## 2. What was verified

Re-checked at `af5553a` rather than taken from the review:

| Finding | At HEAD |
| :--- | :--- |
| `token_max_ttl_days` never consulted when minting | `TokenMaxTTLDays` has no reference outside `internal/policy` |
| LiteLLM master key in `argv` | [`units.go:139`](../../internal/install/units.go) |
| Limits are stored and never read | `internal/gateway/` references no limit field |
| 11 of 16 policy settings unenforced | Exactly 11. Enforced: `require_totp`, `require_justification`, `min_justification_length`, `allow_unattended_tokens`, `session_ttl_minutes` |
| 90-day agent certificates, no renewal | [`pki.go:203`](../../internal/api/pki.go) |
| Egress drop rule is IPv4 only | [`network.go:184`](../../internal/agent/network.go) |
| Usage rows carry no node or deployment | `internal/gateway/proxy.go` sets neither field |
| README claims OIDC, the SIEM sink, a FIPS build | Editions table; none exist in the tree |

## 3. The order

### Tier 0 — make the documents true · days

No new capability. Each item removes a statement the tree does not support, or supports one
it already makes.

| | Change | Where |
| :--- | :--- | :--- |
| 0.1 | `policy show` marks every unenforced setting, with the task number that will enforce it | `internal/policy/diff.go` |
| 0.2 | `token_max_ttl_days` enforced at mint; over-ceiling refused and audited | `internal/cli/token.go` |
| 0.3 | README corrected — editions table, the limits bullet, the guardrails bullet | `README.md` |
| 0.4 | Master key read from the environment inside the process, not interpolated into `ExecStart=` | `internal/cli/gateway.go`, `internal/install/units.go` |
| 0.5 | IPv6 drop rule and `disable_ipv6` on `nodary0` | `internal/agent/network.go` |

0.1 is the highest-leverage item in this plan. [`diff.go`](../../internal/policy/diff.go)'s
`fields` table is already the single place every setting must appear — a test asserts its
count against the struct, precisely so a new setting cannot be added silently. One `enforced`
column on that table makes the same test the forcing function for honesty: a new setting must
declare whether anything acts on it. It closes the review's §3 in an afternoon, and it stays
true on its own as each row below lands.

It is also [mvp.md §3](mvp.md#3-stub-discipline)'s stub discipline applied one level down —
rule 2, *every stub carries a task number* — to a setting rather than a verb.

### Tier 1 — the clock and the fairness · weeks

| | Change | Task |
| :--- | :--- | :--- |
| 1.1 | Certificate renewal at two-thirds of lifetime over the existing mTLS channel | R4-05 |
| 1.2 | Token bucket on `rpm`, `tpm`, `daily_tokens`, `max_concurrent`; `429` naming the limit hit | R3-08/09/10 |
| 1.3 | Login throttle and lockout; password verification out of the single write transaction | new |
| 1.4 | `backup create` / `restore`, capturing `secret.key`, refusing a world-readable destination | R2-37 |

1.1 is a dated failure rather than a missing feature: every certificate issued in one install
window expires in one window, and the control plane loses the fleet at once while the models
keep serving. Until it lands, the cliff has to be diarized.

1.3 is one change closing two findings. There is no throttle anywhere, which is 800-171 3.1.8
on the one endpoint reachable before a credential exists; and because password verification
correctly runs inside the audit mutation seam, 600k-iteration PBKDF2 at ~68 ms holds the
single writer connection, so roughly fifteen unauthenticated attempts per second block audit
records, agent status and usage behind an attacker.

### Tier 2 — operability · weeks

| | Change | Task |
| :--- | :--- | :--- |
| 2.1 | `nodary upgrade`, required for CVE response on the digest-pinned LiteLLM | R5-15 |
| 2.2 | Session principals re-checked against user state, or a bounded `default` TTL | new |
| 2.3 | Usage rows carry `deployment_id` and `node_name` | new |

### Out of the pilot, said out loud

Not deferred quietly. Each is a sentence the README owes a reader.

| Deferred | Consequence to state |
| :--- | :--- |
| Remote administration — `--server`, the remaining API surface, a client | Every administrator needs root on the control plane, and privileged actions attribute to `root`/`local` |
| R4-14 – R4-16 node guardrail enforcement | `node.toml` is reported and not enforced — 0.1 marks it |
| R2-14, R3-13 retention pruning | Windows are displayed and nothing prunes — 0.1 marks it |
| R4-32 origin allow/deny | An operator's declared provenance, recorded and attributable, not a verified one — 0.1 marks it |
| R2-41 network audit sink | The chain's off-box anchor is a customer log shipper into WORM, verified with `audit verify --mirror` |
| R7, R8 — the UI | CLI only, as the README already says |
| R6-08 – R6-12 derived images | The settings governing them are placeholders for unbuilt features — 0.1 distinguishes these from the ones above |
| R9-16 – R9-18 POA&M clocks | The bundle member exists and is empty |
| R2-21/22/23, R5-13/14 | Conventions and offline install, neither on the pilot path |

## 4. Decisions

### 4.1 The claim correction precedes every fix

**Decided.** Tier 0 ships before Tier 1 begins, including before R4-05.

**Why.** It costs hours against weeks, and it is the only work here that is irreversible in
the reader rather than in the code. The review's own framing is that the danger is not
insecurity but an SSP author writing down a control that is display-only — which converts an
acknowledged gap into an unknowing misstatement, a worse position than having no tool. That
harm lands the moment the document is read, and no later fix retrieves it.

**Rejected — fix the certificate cliff first, correct the documents alongside.** R4-05 is the
more serious engineering failure and the clock is already running. It also takes weeks, during
which the front page keeps making the claims; and a correction written while racing a
deadline is the one most likely to be partial.

### 4.2 Unenforced settings are marked, not hidden and not rushed into enforcement

**Decided.** `policy show` renders every setting, with unenforced ones marked and carrying a
task number.

**Why.** The review offers marking or enforcement as equally acceptable. Marking is true the
day it ships, stays true as rows land, and makes the next unenforced setting visible by
construction. Enforcing eleven settings against a pilot date produces approximately-right
controls, which is the failure [mvp.md §5.2](mvp.md#52-the-control-mapping-ships-as-a-stub-with-no-claims)
already refused once for the control mapping — same argument, same answer.

**Rejected — hide unenforced settings from `policy show`.** Smaller output and no false claim.
It also hides the roadmap from the operator and makes `policy diff` inconsistent with `policy
show`, and a setting nobody can see is one nobody notices is missing.

**Rejected — enforce all eleven before the pilot.** The honest end state. It is months, it
blocks everything behind it, and several govern features that do not exist yet, so most of the
work would be enforcement sites with nothing to enforce against.

### 4.3 Rate limiting is enforced rather than struck

**Decided.** R3-08/09/10 in Tier 1, and the README bullet is qualified in Tier 0 until it lands.

**Why.** The claim could be removed instead, at no cost. But the configured object, the CLI,
the export and the diff all exist — what is missing is the read at request time. At a dozen
users on four to eight GPUs, one overnight batch starving interactive work is the ordinary
complaint, not an edge case, and the product currently does not even notice.

**Rejected — strike the claim and defer.** Free, and consistent with Tier 0's rule. It leaves
the fairness problem to a site that bought the product partly to solve it.

## 5. What this does not change

The [mvp.md §2](mvp.md#2-the-rule-that-decides-what-gets-built) columns still hold and nothing
here touches them: no hash preimage moves, no seam is widened, no bundle member name changes.
Tier 0 is renderers and refusals; Tier 1 adds tables and a renewal path, none inside a hash.

## Steps

- [ ] Tier 0 — the claim correction
  - [ ] 0.1 `policy show` marks unenforced settings
  - [ ] 0.2 `token_max_ttl_days` enforced at mint
  - [ ] 0.3 README corrected
  - [ ] 0.4 master key off the command line
  - [ ] 0.5 IPv6 egress drop
- [ ] Tier 1 — the clock and the fairness
  - [ ] 1.1 R4-05 certificate renewal
  - [ ] 1.2 R3-08/09/10 throttling and quota
  - [ ] 1.3 login throttle, and PBKDF2 out of the write transaction
  - [ ] 1.4 R2-37 backup and restore
- [ ] Tier 2 — operability
  - [ ] 2.1 R5-15 upgrade
  - [ ] 2.2 session principals re-checked
  - [ ] 2.3 usage attributed to node and deployment
