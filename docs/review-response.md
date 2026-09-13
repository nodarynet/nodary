# Review response — 2026-09-11

Every finding in the [adoption review](review-2026-09-11.md), with what was done about it.
One row per concern, in the review's own order, so nothing is quietly dropped and nothing is
quietly claimed.

**Status vocabulary.** *Fixed* means the behavior changed and a test fails if it regresses.
*Disclosed* means the behavior did not change and the product now says so where a reader
will see it — which is the right answer for a gap that is real, known, and scheduled.
*Corrected* means the finding was inaccurate and the record says how. *Open* means neither
yet.

Ordering follows [pilot.md](plans/pilot.md), which reorders the review's own recommendations
behind the claim correction its §1 argues for.

---

## Tier 0 — the claim correction

| # | Finding | Status | Where |
| :--- | :--- | :--- | :--- |
| 0.1 | `policy show` displays settings nothing enforces (§3, §5 item 11) | **Fixed** | R1-38 · `9461c42` |
| 0.2 | A `regulated` install mints credentials its own policy forbids (§4.1) | **Fixed** | R1-37 · `8b5462f` |
| 0.3 | The README presents stored capabilities as enforced (§1, §5 item 4) | **Fixed** | `456f292`, and the docs site in `e85b6ee` |
| 0.4 | The LiteLLM master key is visible in `ps` (§4.2, §5 item 1) | **Fixed** | R5-28 · `010b752` |
| 0.5 | Egress isolation covers IPv4 only (§4.3, §5 item 2) | **Fixed** | R4-39 · `e368b7b` |

### Corrections to the review

| Finding | What is actually true |
| :--- | :--- |
| "11 of 16 profile settings have no enforcement site" (§3) | **8.** The grep is right; two of its hits are not gaps. `require_signed_artifacts` and `egress_default` are *invariants* — `Profile.validate` refuses a profile that sets either to anything else, and the mechanisms behind them run unconditionally, so nothing reads the field because nothing can vary. A third, `token_max_ttl_days`, is now enforced. `policy show` distinguishes all three |
| "have `policy show` mark unenforced fields as declarative" (§5 item 11) | Done, and one step further: each marked setting names the task that will enforce it, and a test pins the counts — so a setting cannot change standing without the commit saying so |
| "Ship `audit.jsonl` into WORM storage" (§5 item 3) | Not ours to ship. It is a customer integration, and it is now documented as one in the administering guide rather than carried as a task |

---

## Tier 1 — the clock and the fairness

| # | Finding | Status | Where |
| :--- | :--- | :--- | :--- |
| 1.1 | Every node falls off the fleet 90 days after enrollment (§4.1, §5 item 5) | **Fixed** | R4-05 |
| 1.2 | One user can consume the entire fleet (§4.1, §3, §5 item 6) | **Fixed** | R3-08/09/10 |
| 1.3 | No lockout or throttle on failed authentication; PBKDF2 runs inside the single write transaction (§4.2, §5 item 7) | **Fixed** | R2-43 |
| 1.4 | No backup or restore (§4.1, §5 item 8) | **Fixed** | R2-37 |

---

**Tier 1 is complete.** The review's recommendation was to re-evaluate when R3 and R5 close;
R3's blockers are closed and R5's remaining rows are the upgrade path and the offline bundle.

## Tier 2 — operability

| # | Finding | Status | Where |
| :--- | :--- | :--- | :--- |
| 2.1 | No upgrade path, required for CVE response on the pinned LiteLLM (§4.1, §5 item 10) | **Open** | R5-15 |
| 2.2 | Suspending a user does not end their session (§4.3, §5 item 9) | **Open** | new |
| 2.3 | Usage records cannot be attributed to a node or a GPU (§4.3) | **Open** | new |

Username enumeration (§4.3) was fixed with 1.3, as the review predicted it would have to be —
every authentication failure now returns one envelope, and the timing oracle went with it.

---

## Disclosed rather than fixed

Real, known, scheduled, and now stated where a reader meets the claim rather than only in a
plan. Each is a row in the README's status tables and, where it is a policy setting, a mark
in `policy show`.

| Finding | Disclosed as | Lands in |
| :--- | :--- | :--- |
| Model origin allow/deny lists are stored only (§3, §4.3) | README; marked in `policy show`. The review's deeper question — attestation or enforced control — is answered: it is an operator's declared provenance, recorded and attributable, and the mark says so | R4-32 |
| Retention windows are stored only (§3) | README; marked in `policy show` | R2-14, R3-13 |
| Node guardrails are reported, not enforced (§3) | README, and the editions table no longer lists guardrails as a shipped capability | R4-14 – R4-16 |
| The SIEM sink is not built (§3, §4.2) | README; the administering guide documents the log-shipper-into-WORM workaround and what it does and does not prove | R2-41 |
| OIDC is not built (§3) | Struck from the editions table | — |
| The FIPS build is overstated (§3) | Struck from the editions table; README says CI proves the tree builds and passes under `GODEBUG=fips140=on` and ships no artifact | R5-25/26 |
| No remote administration; every administrator needs root on the control plane (§4.2) | README, and a standing note at the top of the administering guide saying privileged acts attribute to `root`/`local` | R2-21 – R2-32 |
| No upgrade or uninstall (§4.1) | README | R5-15, R5-17 |
| The audit chain has no anchor outside the box it protects (§4.2) | The administering guide, including why the signed bundle does not close it — the signing key is sealed on the same host, so the signature establishes integrity since export, not since the event | R2-41 |
| Egress verification is structurally inconclusive at an air-gapped site (§4.3) | The administering guide, under `verify-egress` | R4-29 |

---

## Still open, not yet scheduled

| Finding | Note |
| :--- | :--- |
| The gateway holds a read-write handle to the audit database (§4.3) | The largest attack surface in the product shares a file with the tamper-evident log. Splitting metering into its own database, or putting the usage write behind an append-only interface, is the review's suggestion and is not costed yet |
| Spec 08 §4 says the master key is sealed at rest; it is not (§4.3) | The TOTP seeds and agent CA key *are* sealed as documented — only this one is not. Either the implementation or the specification is wrong, and which one is a decision, not a bug fix |
| `verify-egress` probes IPv4 only (§4.3) | A v6 target would report `inconclusive` on every v4-only site, because the host control would fail for the ordinary reason. Recorded against R4-39; the decision belongs to R4-29 |

---

## Not accepted

| Recommendation | Why not |
| :--- | :--- |
| Pilot on non-CUI workload; do not cite in the SSP (§1) | Accepted, not refused — recorded here because it is the review's headline and remains the right advice until Tier 1 closes. Re-evaluate at R3 and R5 close, as the review says |
