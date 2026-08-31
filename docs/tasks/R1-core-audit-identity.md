# R1 — Core, audit and identity

**Deliverable:** `core` + `audit` + `identity` — chain, attestation, roles, policy
profiles, `audit verify/export`.
**Proves:** accountability, before any rearchitecture.
· [00 §8](../specs/00-overview.md#8-milestones)

R1 is first because everything after it writes audit records. Adding the chain
afterwards would mean threading an attestation path through code written to
assume it never attests — the same argument [00 §8](../specs/00-overview.md#8-milestones)
makes for landing node guardrails with the reconcile loop.

There is no HTTP server in R1 and no control-plane state beyond what identity and
audit need. The CLI operates on a local database directly. R2 puts an API in
front of the same core functions.

## Foundation

- [x] **R1-01** Canonical JSON encoding — deterministic key order, stable number and string forms · [07 §3](../specs/07-identity-audit.md#3-the-audit-chain)
  - *done:* the same record encodes byte-identically across processes and Go versions; this is what makes a hash reproducible, so it is a prerequisite for every hash below
- [x] **R1-02** Open SQLite in WAL mode through `modernc.org/sqlite` · [08](../specs/08-data-model.md)
  - *done:* `CGO_ENABLED=0 go build` still produces a static binary · [ADR 0002](../adr/0002-go-with-package-manager-wrappers.md)
  - *deps:* R1-01
- [x] **R1-03** Embedded, forward-only migration runner recording each migration's checksum · [08 §5](../specs/08-data-model.md#5-migrations)
  - *done:* a checksum mismatch aborts startup rather than proceeding against an unexpected schema; downgrade is refused
  - *deps:* R1-02
- [x] **R1-04** `/etc/nodary/secret.key` generation (0400 root) and the at-rest encryption helper · [08 §4](../specs/08-data-model.md#4-secrets-at-rest)
  - *done:* TOTP seeds round-trip through encrypt/decrypt; a database copied without the key yields no plaintext secret
  - *deps:* R1-02

## Audit chain

- [ ] **R1-05** `audit` record type carrying every field in the table · [07 §3](../specs/07-identity-audit.md#3-the-audit-chain)
  - *done:* `seq`, `ts`, `actor`, `source`, `action`, `target`, `intent_hash`, `justification`, `outcome`, `detail`, `prev_hash`, `hash` all populated on write
  - *deps:* R1-03
- [ ] **R1-06** Record hashing: SHA-256 over canonical JSON of the record including `prev_hash`
  - *done:* re-hashing a stored record reproduces its stored `hash`
  - *deps:* R1-01, R1-05
- [ ] **R1-07** Chain records by `prev_hash` on insert, under a monotonic `seq`
  - *done:* concurrent writers cannot interleave to produce two records claiming the same `seq` or the same predecessor
  - *deps:* R1-06
- [ ] **R1-08** Append-only JSONL mirror at `/var/log/nodary/audit.jsonl` · [07 §3](../specs/07-identity-audit.md#3-the-audit-chain)
  - *done:* the mirror is written on every record and survives loss of the database, which is what makes it independent evidence · [11 §5](../specs/11-failure-modes.md#5-recovery)
  - *deps:* R1-07
- [ ] **R1-09** `nodary audit verify` walks the chain and reports the first break by sequence number
  - *done:* mutating record *k* in a chain of *N* makes verify name *k*, not "chain invalid"; the server keeps running and raises a critical alert rather than repairing the chain · [11 §3](../specs/11-failure-modes.md#3-security-controls)
  - *deps:* R1-07
- [ ] **R1-10** `nodary audit list` with `--from`, `--to`, `--actor`, `--action`, ordered by sequence descending · [10 §1](../specs/10-cli.md#1-verbs)
  - *deps:* R1-07
- [ ] **R1-11** `nodary audit export --format jsonl|csv` · [09 §1](../specs/09-api.md#1-surface)
  - *deps:* R1-07
- [ ] **R1-12** The audit layer: one seam every mutating call passes through · [10 §1](../specs/10-cli.md#1-verbs)
  - *done:* a mutating core function cannot be reached without producing a record — enforced structurally, not by convention, because R2 through R8 all depend on this holding
  - *deps:* R1-07

## Attestation

- [ ] **R1-13** Render a preview of exactly what a mutation will change, and hash it into `intent_hash` · [07 §2](../specs/07-identity-audit.md#2-attestation)
  - *done:* `--dry-run` prints the rendered change and its hash and applies nothing · [10 §2](../specs/10-cli.md#2-global-flags)
  - *deps:* R1-01, R1-12
- [ ] **R1-14** Re-render and re-hash at apply time; refuse when the hash no longer matches
  - *done:* moving state between preview and apply produces a refusal with exit code 4, not a silent apply of something the operator never saw · [11 §3](../specs/11-failure-modes.md#3-security-controls)
  - *deps:* R1-13
- [ ] **R1-15** `--justify TEXT`, with `min_justification_length` enforced by the active profile
  - *done:* under `regulated` a 5-character justification is refused; under `default` the record is still written with actor and outcome
  - *deps:* R1-12, R1-25
- [ ] **R1-16** TOTP re-entry when `require_totp` is set
  - *done:* re-authentication is per-act, not per-session — a valid session cookie alone does not satisfy it
  - *deps:* R1-19, R1-25
- [ ] **R1-17** `--allow-unattended` tokens: an audited grant, refused when `allow_unattended_tokens = false`
  - *done:* non-interactive mutation is possible under `default` and impossible under `regulated`, and the grant itself appears in the chain
  - *deps:* R1-21, R1-25

## Identity

- [ ] **R1-18** `user` table, argon2id password hashing, states `active → suspended → deleted` · [07 §1](../specs/07-identity-audit.md#1-users-and-roles)
  - *deps:* R1-03
- [ ] **R1-19** TOTP enrollment and verification, seed encrypted at rest
  - *done:* the seed is displayed exactly once at enrollment and is never readable back · [10 §4](../specs/10-cli.md#4-output-discipline)
  - *deps:* R1-04, R1-18
- [ ] **R1-36** Record the active key id, and refuse to start under a key that does not match it · [11 §5](../specs/11-failure-modes.md#5-recovery)
  - *done:* deleting `/etc/nodary/secret.key` and restarting is refused rather than silently minting a fresh key. Today the two are indistinguishable, so the recovery path and the unrecoverable one look identical — every TOTP seed, the LiteLLM key and the CA key become permanently unreadable, with a clean startup to say nothing is wrong. The id belongs in a table, so it lands with the schema rather than in R1a
  - *deps:* R1-03, R1-04
- [ ] **R1-20** Roles `viewer`, `user`, `operator`, `admin` and the permission checks between them · [07 §1](../specs/07-identity-audit.md#1-users-and-roles)
  - *done:* an `operator` can restart a model and cannot approve a node
  - *deps:* R1-18
- [ ] **R1-21** Token kinds `nodary_jt_`, `nodary_sk_`, `nodary_pt_`: SHA-256 at rest, plaintext shown once at creation · [02 §4](../specs/02-enrollment.md#4-token-types)
  - *done:* the distinct prefixes survive into logs so the kinds stay greppable; no plaintext appears in any list output or `--format json`
  - *deps:* R1-18
- [ ] **R1-22** Personal-token credentials at `~/.nodary/credentials`, mode 0600 · [07 §1](../specs/07-identity-audit.md#1-users-and-roles)
  - *deps:* R1-21
- [ ] **R1-23** `nodary user add|list|show|suspend|delete|passwd|totp` · [10 §1](../specs/10-cli.md#1-verbs)
  - *deps:* R1-12, R1-18, R1-19, R1-20
- [ ] **R1-24** `nodary token create|list|revoke` · [10 §1](../specs/10-cli.md#1-verbs)
  - *done:* revocation takes effect immediately and `last_used_at` is recorded, which is what makes stale-credential cleanup possible · [06 §2](../specs/06-gateway.md#2-authentication)
  - *deps:* R1-12, R1-21

## Policy profiles

- [ ] **R1-25** Parse and validate a policy profile from TOML · [07 §4](../specs/07-identity-audit.md#4-policy-profiles)
  - *done:* unknown keys are rejected rather than ignored; a profile is a reviewable object, and a silently dropped key defeats that
  - *deps:* R1-03
- [ ] **R1-26** Embed the built-in `default` and `regulated` profiles; `default` is active on a fresh install
  - *done:* both profiles' values match [07 §4](../specs/07-identity-audit.md#4-policy-profiles) exactly
  - *deps:* R1-25
- [ ] **R1-27** Enforce the invariants no profile can turn off · [07 §4](../specs/07-identity-audit.md#4-policy-profiles)
  - *done:* a profile attempting to disable the audit chain, `intent_hash` binding, signature verification, digest pinning or egress isolation is rejected at apply. What a profile adjusts is ceremony and retention, never whether the record exists
  - *deps:* R1-25
- [ ] **R1-28** `nodary policy show|apply|diff`
  - *done:* `diff` names exactly which constraints would loosen; loosening is permitted, doing it silently is not
  - *deps:* R1-12, R1-26

## CLI surface

- [ ] **R1-29** Exit codes 0–6 wired through every R1 verb · [10 §5](../specs/10-cli.md#5-exit-codes)
  - *done:* policy refusal exits 5, intent mismatch exits 4, authorization failure exits 3 — distinguishable without parsing stderr
- [ ] **R1-30** Output discipline across every R1 verb · [10 §4](../specs/10-cli.md#4-output-discipline)
  - *done:* `--format json` emits a stable schema to stdout and nothing else; progress and diagnostics go to stderr; secrets never appear in list output
- [ ] **R1-31** `--yes` skips the interactive confirmation and does **not** skip justification or TOTP · [10 §2](../specs/10-cli.md#2-global-flags)
  - *deps:* R1-15, R1-16

## Quality gates

These are the only tasks in the tracker without a spec link, and the exception
is deliberate rather than an oversight. The rule exists so nobody invents scope;
these invent none — they are the machinery that decides whether the `done:`
criteria above are actually met. R0 owned its CI ([R0-16](R0-release.md)); R1
through R8 owned none, so nothing tracked them.

They land before the rest of R1 on purpose. Twenty-nine tasks written under the
gates cost nothing; twenty-nine retrofitted into them cost a great deal, and a
data race introduced in R1b's chain writer is far cheaper to catch on the commit
that adds it than in the quarter it first reproduces.

- [x] **R1-32** `go test -race` in `make check` and CI
  - *done:* the race detector runs on every pull request. R1-07 requires that concurrent writers cannot interleave; nothing currently tests the code that claim rests on, and the control plane, agent and audit writer are all concurrent
- [x] **R1-33** `staticcheck`, pinned, in CI
  - *done:* it runs green and its version is pinned in the `Makefile`. The pin is not optional: staticcheck 2025.1.1 cannot parse a Go 1.27 tree at all, so a floating version fails on somebody else's release schedule · [ADR 0002](../adr/0002-go-with-package-manager-wrappers.md)
- [x] **R1-34** `govulncheck` over the dependency tree in CI
  - *done:* a vulnerability nodary can actually reach fails the build. It is reachability-based, so it does not fire on a CVE in code we never call — which is what makes blocking on it safe rather than noisy
- [x] **R1-35** Nightly fuzzing for `internal/canonical`
  - *done:* the corpus runs as regression cases on every pull request, and a scheduled job searches for new inputs. Not per-pull-request: a fixed-time run either finds nothing or fails on an input unrelated to the change under review · [R1-01](#foundation)

**Not gated: a coverage threshold.** It measures whether a line ran, not whether
a test would fail if the behaviour were wrong, and R1a produced two arguments
against it. The differential test in `internal/canonical` had full coverage of
the encoder while comparing almost nothing, until it was checked for vacuity.
The concurrency test in `internal/store` had full coverage of `WriteTx` and
passed with the mechanism it existed to test deleted. A percentage would have
called both excellent. Coverage is worth reporting and worth reading; it is not
worth failing a build over.
