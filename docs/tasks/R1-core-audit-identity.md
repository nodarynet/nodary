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
  - **the encoder rejected its own output, and the nightly fuzz job caught it — three nights red before anybody looked.** `formatJSONNumber` splits on whether a literal contains `.eE`: `100000000000001000.0` went down the float path and canonicalized to `100000000000001000`, and feeding that back went down the integer path, where an exactness test refused it. `audit verify` and `config verify` re-hash stored records, so an encoder that cannot read its own bytes reports tampering in a chain nobody touched. The rule is now a round trip — refuse when canonicalizing would change the *digits* — which keeps 2^53+1 refused (it comes back `…992`) and accepts values whose digits do not move
  - *no hash moved.* Verified rather than asserted: 4,017 sampled numbers encoded under both versions, and every difference is an input that used to error and now succeeds. Nothing that encoded before encodes differently, which is the only property that matters for a chain a customer already holds ([mvp §2](../plans/mvp.md#2-the-rule-that-decides-what-gets-built))
  - *known and pinned, not fixed:* the float spelling of the same value still rounds — `9007199254740993.0` encodes to `9007199254740992`. The two spellings are different claims (an integer literal asserts an exact integer; a decimal literal asserts the nearest real, where rounding is JSON's defined semantics), and narrowing what the encoder accepts is a change to the preimage's domain rather than a bug fix. Idempotency holds either way
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

- [x] **R1-05** `audit` record type carrying every field in the table · [07 §3](../specs/07-identity-audit.md#3-the-audit-chain)
  - *done:* `v`, `install`, `seq`, `ts`, `actor`, `source`, `action`, `target`, `intent_hash`, `justification`, `outcome`, `detail`, `prev_hash`, `hash` all populated on write. `v` and `install` were added to [07 §3](../specs/07-identity-audit.md#v-and-install) during [R1b](../plans/R1b-audit-chain.md): both live inside the hash preimage, so neither could be added later
  - *deps:* R1-03
- [x] **R1-06** Record hashing: SHA-256 over canonical JSON of the record including `prev_hash`
  - *done:* re-hashing a stored record reproduces its stored `hash`
  - *deps:* R1-01, R1-05
- [x] **R1-07** Chain records by `prev_hash` on insert, under a monotonic `seq`
  - *done:* concurrent writers cannot interleave to produce two records claiming the same `seq` or the same predecessor
  - *deps:* R1-06
- [x] **R1-08** Configurable delivery of every record — a JSONL file by default, `stdout`, `stderr` or `none` · [07 §3](../specs/07-identity-audit.md#storage-and-delivery)
  - *done:* every committed record is delivered, the file survives loss of the database and verifies on a machine that never held it, and a destination that fell behind resynchronizes with `audit export --from-seq` · [11 §5](../specs/11-failure-modes.md#5-recovery)
  - *note:* the task previously specified the mirror as a fixed, mandatory path. [07 §3](../specs/07-identity-audit.md#storage-and-delivery) now makes the destination configuration and delivery post-commit, so a log destination can never block or roll back a change; the task follows the spec. A native SIEM exporter is [R2-41](R2-control-plane.md)
  - *deps:* R1-07
- [x] **R1-09** `nodary audit verify` walks the chain and reports the first break by sequence number
  - *done:* mutating record *k* in a chain of *N* makes verify name *k*, not "chain invalid", and nothing repairs the chain · [11 §3](../specs/11-failure-modes.md#3-security-controls)
  - *note:* the same row's "the server keeps running and raises a critical alert" is R2's half — R1 has no server to keep running. Tracked against R2-33
  - *deps:* R1-07
- [x] **R1-10** `nodary audit list` with `--from`, `--to`, `--actor`, `--action`, ordered by sequence descending · [10 §1](../specs/10-cli.md#1-verbs)
  - *done:* `--action` matches a family when it ends in a dot, and matches literally otherwise — a filter that quietly returns more than it was asked for is worse than one that errors
  - *deps:* R1-07
- [x] **R1-11** `nodary audit export --format jsonl|csv` · [09 §1](../specs/09-api.md#1-surface)
  - *done:* the JSONL output is byte-identical to what a sink delivered for the same records, so an export diffed against a copy shipped off-box is empty when nothing is wrong
  - *deps:* R1-07
- [x] **R1-12** The audit layer: one seam every mutating call passes through · [10 §1](../specs/10-cli.md#1-verbs)
  - *done:* a mutating core function cannot be reached without producing a record — enforced structurally, not by convention, because R2 through R8 all depend on this holding
  - *deps:* R1-07

## Attestation

- [x] **R1-13** Render a preview of exactly what a mutation will change, and hash it into `intent_hash` · [07 §2](../specs/07-identity-audit.md#2-attestation)
  - *done:* `--dry-run` prints the rendered change and its hash and applies nothing · [10 §2](../specs/10-cli.md#2-global-flags)
  - *note:* a verb supplies a *render function*, not a value. A value computed once would still match after the world moved, having never been recomputed, so the hash would bind nothing. What each verb renders is the state it depends on — the state a user is moving *from*, whether a name is free, the policy diff — rather than an echo of its arguments · [R1e](../plans/R1e-attestation.md)
  - *deps:* R1-01, R1-12
- [x] **R1-14** Re-render and re-hash at apply time; refuse when the hash no longer matches
  - *done:* moving state between preview and apply produces a refusal with exit code 4, not a silent apply of something the operator never saw · [11 §3](../specs/11-failure-modes.md#3-security-controls)
  - *deps:* R1-13
- [x] **R1-15** `--justify TEXT`, with `min_justification_length` enforced by the active profile
  - *done:* under `regulated` a 5-character justification is refused; under `default` the record is still written with actor and outcome
  - *note:* the floor applies to any justification supplied, required or not — a profile that sets a minimum without requiring the field means "optional, but say something real if you say anything". Length is counted in runes: a byte count would fail an accented justification that an ASCII one of the same length passes
  - *deps:* R1-12, R1-25
- [x] **R1-16** TOTP re-entry when `require_totp` is set
  - *done:* re-authentication is per-act, not per-session — a valid session cookie alone does not satisfy it, and a code is spent so it cannot authorize a second act
  - *note:* **local root is exempt**, and the record says so with `totp_exempt`. It has no user row and therefore no seed, and [R1c](../plans/R1c-identity.md)'s argument applies unchanged — anyone who can open the database can already do anything to it, so demanding a second factor stored in that same database buys nothing. Without the exemption, `regulated` would mean the local CLI cannot recover the appliance, which is what [07 §1](../specs/07-identity-audit.md#1-users-and-roles) argues against
  - *deps:* R1-19, R1-25
- [x] **R1-17** `--allow-unattended` tokens: an audited grant, refused when `allow_unattended_tokens = false`
  - *done:* non-interactive mutation is possible under `default` and impossible under `regulated`, and the grant itself appears in the chain. The grant is refused at the mint rather than at every later use, because it is the whole route around re-authentication and a profile that closes it must close it once
  - *deps:* R1-21, R1-25

- [x] **R1-37** `token_max_ttl_days` enforced at the mint, `never` refused under every profile · [07 §4](../specs/07-identity-audit.md#4-policy-profiles)
  - *done:* `token create` and `token join` both refuse a lifetime over the active profile's ceiling, naming the profile and the number, and a credential that never expires is refused by name rather than reported as exceeding a day count
  - *note:* opened by the [2026-09-11 review](../review-2026-09-11.md), which minted a ten-year service key and a never-expiring one against a `regulated` profile capping both at 365 days. The ceiling was specified in R1d and displayed by `policy show` from the day profiles landed; nothing read it. The check sits beside `AllowUnattendedMint` in `internal/attest` because that is where a profile meets an act, and the CLI is where a lifetime can still vary — the API mints a fixed 90 days and never could
  - *deps:* R1-25

- [x] **R1-38** `policy show` marks every setting nothing acts on, naming the task that will enforce it
  - *done:* the setting table in `internal/policy/diff.go` carries a fourth column, and a test pins the three standings and their counts — so a setting cannot be added without saying whether anything reads it, and a setting cannot start or stop being enforced without the count changing in the same commit. Both renderings carry it: the text form annotates the line, `--format json` carries a `standing` object, because the JSON is what gets scripted and pasted into a system security plan
  - *note:* the [2026-09-11 review](../review-2026-09-11.md) counted 11 of 16 settings with no enforcement site. Two of those are invariants rather than gaps — `require_signed_artifacts` and `egress_default` are refused at parse if set to anything else, and the mechanisms behind them run unconditionally, so nothing reads the field because nothing needs to. A third, `token_max_ttl_days`, is now enforced (R1-37). Eight remain, and they are marked rather than rushed: enforcing eight settings against a date is how docs/plans/mvp.md §5.2 says an approximately-right control gets written down
  - *deps:* R1-25

## Identity

- [x] **R1-18** `user` table, roles, and the states `active → suspended → deleted` · [07 §1](../specs/07-identity-audit.md#1-users-and-roles)
  - *done:* a deleted user keeps its row, so every audit record naming it still resolves to a name, and gives that name back for reuse
  - *note:* argon2id password hashing was part of this task and is now [R2-42](R2-control-plane.md). Nothing in R1 reads a password hash: the only consumer is `POST /auth/login` ([R2-25](R2-control-plane.md)), the CLI authenticates with a personal token, and [01 §9](../specs/01-install.md) has the first administrator set theirs through a one-time setup URL that does not exist until [R5](R5-install.md). Unlike the audit record's `v` and `install`, nothing hashes a `user` row, so the column is an ordinary forward-only migration · [R1c](../plans/R1c-identity.md)
  - *deps:* R1-03
- [x] **R1-19** TOTP enrollment and verification, seed encrypted at rest
  - *done:* the seed is displayed exactly once at enrollment and is never readable back · [10 §4](../specs/10-cli.md#4-output-discipline)
  - *note:* RFC 6238 is implemented here rather than depended on, and checked against the specification's own published vectors. Enrollment is one command that confirms before it commits, so a mis-scanned QR changes nothing; a code is spent when used, because one that survives its own thirty-second window can be replayed by anyone who watched it typed · [R1c](../plans/R1c-identity.md)
  - *deps:* R1-04, R1-18
- [x] **R1-36** Record the active key id, and refuse to start under a key that does not match it · [11 §5](../specs/11-failure-modes.md#5-recovery)
  - *done:* deleting `/etc/nodary/secret.key` and restarting is refused rather than silently minting a fresh key. Today the two are indistinguishable, so the recovery path and the unrecoverable one look identical — every TOTP seed, the LiteLLM key and the CA key become permanently unreadable, with a clean startup to say nothing is wrong. The id belongs in a table, so it lands with the schema rather than in R1a
  - **the binding was armed and the arming was not.** `BindKey` had one caller, the first TOTP seal, so a control plane that had enrolled nobody named no key at all — while `server install` had already sealed the agent CA under it. Measured on a fresh install: `SELECT secret_key_id FROM installation` returned no row, and swapping `secret.key` was accepted in silence. `server install` now binds before it seals anything, which is the order the property needs
  - the gap was anticipated in place: internal/identity/keybind.go says *"it moves when a second subsystem seals something -- R2-40's CA key is the first candidate"*. R2-40 landed and the binding did not follow it, which is worth remembering about notes that name their own successor
  - *deps:* R1-03, R1-04
- [x] **R1-20** Roles `viewer`, `user`, `operator`, `admin` and the permission checks between them · [07 §1](../specs/07-identity-audit.md#1-users-and-roles)
  - *done:* an `operator` can restart a model and cannot approve a node
  - *note:* the roles are ranked rather than enumerated per role, because [07 §1](../specs/07-identity-audit.md#1-users-and-roles) defines each as *the above, plus*. A permission with no minimum role is held by nobody, admin included: the other direction hands a newly named capability to whoever the table happens to omit
  - *deps:* R1-18
- [x] **R1-21** Token kinds `nodary_jt_`, `nodary_sk_`, `nodary_pt_`: SHA-256 at rest, plaintext shown once at creation · [02 §4](../specs/02-enrollment.md#4-token-types)
  - *done:* the distinct prefixes survive into logs so the kinds stay greppable; no plaintext appears in any list output or `--format json`
  - *deps:* R1-18
- [x] **R1-22** Personal-token credentials at `~/.nodary/credentials`, mode 0600 · [07 §1](../specs/07-identity-audit.md#1-users-and-roles)
  - *done:* a file others can read is refused rather than used, and `token create --save` writes one atomically at 0600 so an interrupted write cannot replace a working credential with a truncated one
  - *deps:* R1-21
- [x] **R1-23** `nodary user add|list|show|suspend|delete|passwd|totp` · [10 §1](../specs/10-cli.md#1-verbs)
  - *done:* every mutating verb goes through `audit.Act`, so R1-12's guarantee has its first production callers; a refusal is recorded and the command names the record. `passwd` reports that it is not in this release and points at `token create` — see [R2-42](R2-control-plane.md)
  - *deps:* R1-12, R1-18, R1-19, R1-20
- [x] **R1-24** `nodary token create|list|revoke` · [10 §1](../specs/10-cli.md#1-verbs)
  - *done:* revocation takes effect immediately and `last_used_at` is recorded, which is what makes stale-credential cleanup possible · [06 §2](../specs/06-gateway.md#2-authentication)
  - *note:* `last_used_at` is stamped inside the audited act a credential authorized, because nothing outside `internal/audit` may write to the database. A token used only for reads therefore looks unused; the read path that would change that is R2's · [R1c](../plans/R1c-identity.md)
  - *deps:* R1-12, R1-21

## Policy profiles

- [x] **R1-25** Parse and validate a policy profile from TOML · [07 §4](../specs/07-identity-audit.md#4-policy-profiles)
  - *done:* unknown keys are rejected rather than ignored; a profile is a reviewable object, and a silently dropped key defeats that
  - *deps:* R1-03
- [x] **R1-26** Embed the built-in `default` and `regulated` profiles; `default` is active on a fresh install
  - *done:* both profiles' values match [07 §4](../specs/07-identity-audit.md#4-policy-profiles) exactly — asserted against the specification's own TOML blocks rather than against a transcription, because the transcription is the thing that drifts
  - *note:* `default` is resolved on read from the absence of a row rather than seeded by the migration. A seeded row would claim somebody applied it while no audit record said who
  - *deps:* R1-25
- [x] **R1-27** Enforce the invariants no profile can turn off · [07 §4](../specs/07-identity-audit.md#4-policy-profiles)
  - *done:* a profile attempting to disable the audit chain, `intent_hash` binding, signature verification, digest pinning or egress isolation is rejected at apply. What a profile adjusts is ceremony and retention, never whether the record exists
  - *note:* the five invariants divide in two. `require_signed_artifacts = false` and `egress_default = "allow"` are valid keys a plausible profile could hold by accident, and are refused by name. The other three have no key at all, so they would fall through to "unknown key" — which reads as a typo to somebody who just tried to disable the audit chain, and they get named refusals instead · [R1d](../plans/R1d-policy.md)
  - *deps:* R1-25
- [x] **R1-28** `nodary policy show|apply|diff`
  - *done:* `diff` names exactly which constraints would loosen; loosening is permitted, doing it silently is not — `apply` reports the same lines on stderr before it acts, so the report survives `--format json` being parsed on stdout
  - *note:* one table drives `diff` and `show` both, so a setting cannot be visible in one and missing from the other, and a test fails if the table and the struct disagree
  - *deps:* R1-12, R1-26

## CLI surface

- [x] **R1-29** Exit codes 0–6 wired through every R1 verb · [10 §5](../specs/10-cli.md#5-exit-codes)
  - *done:* policy refusal exits 5, intent mismatch exits 4, authorization failure exits 3 — distinguishable without parsing stderr, and asserted as a table because the codes are a contract a script depends on. 6 is not reachable in R1, which has no control plane to be unable to reach
- [x] **R1-30** Output discipline across every R1 verb · [10 §4](../specs/10-cli.md#4-output-discipline)
  - *done:* `--format json` emits a stable schema to stdout and nothing else; progress and diagnostics go to stderr; secrets never appear in list output. Previews, prompts and the loosening report are diagnostics — a preview on stdout would corrupt every scripted caller. `--dry-run --format json` is the exception, because there the preview *is* the result
- [x] **R1-31** `--yes` skips the interactive confirmation and does **not** skip justification or TOTP · [10 §2](../specs/10-cli.md#2-global-flags)
  - *done:* it is the flag somebody reaches for to make a refusal go away, so the test is that the refusal still happens
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
a test would fail if the behavior were wrong, and R1a produced two arguments
against it. The differential test in `internal/canonical` had full coverage of
the encoder while comparing almost nothing, until it was checked for vacuity.
The concurrency test in `internal/store` had full coverage of `WriteTx` and
passed with the mechanism it existed to test deleted. A percentage would have
called both excellent. Coverage is worth reporting and worth reading; it is not
worth failing a build over.
