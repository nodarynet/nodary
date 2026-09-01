# R1c — Identity

**Slice of:** [R1](../tasks/R1-core-audit-identity.md) · **Tasks:** R1-18 – R1-24, R1-36 ·
**Status:** complete

The third of five slices of R1.

```
R1a foundation --> R1b audit chain --+--> R1c identity --+
                                     +--> R1d policy   --+--> R1e attestation
```

**R1c is the first slice with a production writer.** [R1b](R1b-audit-chain.md) built the
seam every mutating call passes through and had nothing to put through it; R1-12's
guarantee was proved structurally because there was no call site to survey. Every verb
here goes through `audit.Act`, so the seam stops being a claim about a mechanism nobody
calls.

It is also the first production caller of [R1a](R1a-storage-foundation.md)'s sealing. A
TOTP seed is the only thing encrypted at rest in R1, which is what makes R1-36 — bind the
database to the key that sealed it — belong in this slice rather than in the one that
wrote the helper.

## Scope

| Task | |
| :--- | :--- |
| **R1-18** | `user` table, roles, `active → suspended → deleted` |
| **R1-19** | TOTP enrollment and verification, seed sealed at rest |
| **R1-20** | The four roles and the permission checks between them |
| **R1-21** | `nodary_pt_`, `nodary_sk_`, `nodary_jt_` — SHA-256 at rest, plaintext shown once |
| **R1-22** | `~/.nodary/credentials`, mode 0600 |
| **R1-23** | `nodary user add\|list\|show\|suspend\|delete\|totp` |
| **R1-24** | `nodary token create\|list\|revoke\|join` |
| **R1-36** | Record the active key id; refuse to start under a key that does not match |

R1c adds **no dependencies**. Everything here is standard library.

### What this slice does not build: passwords

R1-18 as written included argon2id password hashing. It is deferred to
[R2-42](../tasks/R2-control-plane.md), and the task is narrowed to match.

Nothing in R1 reads a password hash. The only consumer is `POST /auth/login`
([R2-25](../tasks/R2-control-plane.md), gated by R2-16's session cookies), which exists to
issue a cookie for the web interface — [R7](../tasks/R7-ui-readonly.md) and
[R8](../tasks/R8-ui-mutating.md). The CLI authenticates with a personal token
([07 §1](../specs/07-identity-audit.md#1-users-and-roles)) and the per-act presence proof
is TOTP, so `user passwd` in R1 would write a column nothing verifies and no test could
exercise end to end.

[01 §9](../specs/01-install.md) settles it: the first administrator is created through a
**one-time setup URL**, and *no default password ever exists*. The first password anyone
sets is set through a browser flow that does not exist until [R5](../tasks/R5-install.md).
Building the hashing here means its first real call site is three milestones away, and the
parameters would be chosen against no measured login path.

**Deferring is safe because it is additive.** `v` and `install` had to be in the audit
record from record one because they sit inside the hash preimage; nothing hashes a `user`
row, so `password_hash` is an ordinary forward-only migration whenever R2 wants it. It
also drops the two dependencies this slice would otherwise have taken —
`golang.org/x/crypto/argon2` and `golang.org/x/term`, the second only to read a password
without echoing it.

**What is not deferred is TOTP.** Its consumer is in R1: R1-16's per-act re-entry, which
[R1e](../tasks/R1-core-audit-identity.md) needs and which names R1-19 as a dependency.

## Decisions

### Local root is `admin`

R1 has no login. The CLI opens a local database directly, and anyone who can open that
file can already do anything to it — the hash chain is what makes that detectable rather
than impossible ([07 §3](../specs/07-identity-audit.md#prev_hash)). Pretending otherwise
by demanding a credential the operator would have to mint with the same file access buys
nothing.

So the CLI resolves one principal, in order:

1. A personal token in `~/.nodary/credentials`, authenticated against the `token` table —
   which is what makes R1-22 and R1-24's `last_used_at` real rather than decorative.
2. Otherwise, local root: role `admin`, recorded as `{ID: "root", Method: "local"}`.
3. Neither — a non-root process with no credentials — exits 3.

The second is deliberate, and [07 §1](../specs/07-identity-audit.md#1-users-and-roles)
argues for it directly: an appliance that cannot authenticate its own administrator when
the network is degraded is an appliance that cannot be recovered. It reads better still
now that passwords are deferred, since there is no password login to recover with.

*Rejected:* requiring a bootstrap token minted at install. It moves the recovery problem
without solving it, and R5 has no install flow yet to mint one in.

### Roles are ranked, not enumerated per role

[07 §1](../specs/07-identity-audit.md#1-users-and-roles) defines each role as *the above,
plus* — so the roles are cumulative by construction. A permission names the lowest role
that holds it, and the check is one comparison.

*Rejected:* a set of permissions per role. It restates the three lower rows in the fourth,
and the duplication is exactly where a later edit grants something it did not mean to.

Every permission named maps to a phrase in that table and nothing else is invented. Two of
them — `model.restart` and `node.approve` — describe operations no milestone has built,
because R1-20's `done:` criterion is that an operator can do the first and not the second.
A permission vocabulary is the deliverable; the operations arrive later and find it.

### A deleted user keeps its row and gives back its name

`delete` moves the row to `deleted` and scrubs the sealed TOTP seed. The row itself stays,
because audit records name a user by id and evidence that cannot be resolved to a name is
worth less.

The name is released by a **partial unique index** — `UNIQUE(name) WHERE state <>
'deleted'` — so the name can be reused without rewriting anything.

*Rejected:* a hard `DELETE`. It breaks every audit record naming that id.
*Rejected:* holding the name forever. An operator who deletes `alice` by mistake cannot
recreate her, and the workaround is `alice2` forever.

### A TOTP code is spent, not merely valid

RFC 6238 codes are valid for a whole 30-second step, and accepting a skew window widens
that to ninety seconds. A code that stays valid after use is a code that can be replayed
by anyone who sees it once — over a shoulder, in a terminal recording, in a shell history
— which quietly undermines the thing TOTP is here for:
[07 §2](../specs/07-identity-audit.md#2-attestation)'s *proves a person was present for
this specific act*.

So the user row records the last step consumed, and verification requires a strictly
greater one. This needs a column [08](../specs/08-data-model.md#1-schema) does not have —
recorded below as a spec correction.

### Enrollment is one command that confirms before it commits

`nodary user totp NAME` generates a seed, prints it once with its `otpauth://` URI, reads
a code back, verifies it, and only then writes anything. Ctrl-C leaves the account exactly
as it was.

*Rejected:* an `enroll` / `confirm` pair. It needs a pending-seed state in the schema, and
an abandoned enrollment leaves a half-configured account that nothing cleans up.
*Rejected:* activating on display. A mis-scanned QR then locks the account out, and R1 has
no reset path that is not "an admin re-enrolls you".

The seed goes to stdout with no decoration and the prompt to stderr, per
[10 §4](../specs/10-cli.md#4-output-discipline), so a capture of stdout is exactly the
seed.

### Tokens are hashed with SHA-256, and that is not a downgrade

[02 §4](../specs/02-enrollment.md#4-token-types) says SHA-256, and it is right to. A
password is low-entropy and needs a slow hash to survive an offline attack on a stolen
database. A token is 256 bits from `crypto/rand`; there is no dictionary, and an attacker
who can enumerate SHA-256 preimages of a uniform 256-bit secret has already won
everywhere. Making token lookup deliberately slow would put a KDF on the hot path of every
authenticated request for nothing.

### One secret, one display, one verb

`user add` mints no secret at all — it creates the identity, and `token create` mints the
credential. Two verbs, one secret, one place that prints it once.

That fell out of deferring passwords, and it is a better shape than the one it replaced:
there is exactly one code path in the binary that writes a secret to stdout.

### The key id binds on first seal, not at install

R1-36's refusal has to distinguish two states that look identical today: a key that was
never needed, and a key that was deleted. Binding at install would refuse a database that
simply predates the key. Binding on the **first seal** — the first TOTP enrollment — is
the moment the database starts depending on that key, and from then on a mismatch is
reported rather than silently minting a fresh key that leaves every sealed seed
permanently unreadable, with a clean startup to say nothing is wrong.

Retired key ids are already carried by `secret.Load`, so rotation is a match against the
retired set rather than a failure.

### `--allow-unattended` is a column now and a flag later

[08](../specs/08-data-model.md#1-schema) puts `allow_unattended` on the token row, so the
column is created here. The flag is not exposed: the grant exists to be refused when
`allow_unattended_tokens = false` ([R1-17](../tasks/R1-core-audit-identity.md)), and there
is no policy to refuse it with until [R1d](README.md). Shipping the grant before the thing
that can deny it is the wrong order.

## Design

### Schema — `0003_identity.sql`

```sql
user(id PK, name, email, role, state, totp_secret_enc, totp_last_step,
     totp_enrolled_at, created_at)          -- UNIQUE(name) WHERE state <> 'deleted'
token(id PK, user_id, kind, hash, prefix, name, expires_at, revoked_at,
      last_used_at, allow_unattended, created_at)
join_token(id PK, hash, uses_left, expires_at, created_by, created_at)
installation += secret_key_id
```

`CHECK` constraints carry the same job they do in `0002_audit.sql`: `role` and `state`
against their vocabularies, `id` against its prefix, hash length against 64, and
`totp_secret_enc` paired with `totp_enrolled_at` so a half-enrolled row cannot be read
back ambiguously.

`join_token` is created here because `token join` mints one. Redeeming it is node
enrollment — [R2](../tasks/R2-control-plane.md) and [R4](../tasks/R4-agent.md).

### `internal/identity`

| File | |
| :--- | :--- |
| `role.go` | `Role`, `Permission`, the rank table, `Can` |
| `user.go` | `User`, `Add`, `List`, `Get`, `Suspend`, `Delete` |
| `totp.go` | RFC 6238 — `NewSeed`, `Code`, `Verify`, `URI`; and enrollment against the store |
| `token.go` | `Kind`, `Mint`, `Authenticate`, `Revoke`, `List` |
| `credentials.go` | Read and write `~/.nodary/credentials` at 0600 |
| `principal.go` | Resolving who is acting, and the `audit.Actor` it produces |

Every mutating function takes an `audit.Mutation` and does its work in that transaction,
so the change and its record commit together. Nothing in the package opens a database.

### TOTP

RFC 6238 with the parameters every authenticator app assumes: HMAC-SHA1, 6 digits, a
30-second step, a 160-bit seed. Skew is ±1 step, narrowed by the spent-step rule above.
Checked against RFC 6238's published test vectors, which is the whole reason for writing
it rather than depending on it — the specification ships its own proof.

### CLI

```
nodary user   add NAME --role R | list | show NAME | suspend NAME | delete NAME | totp NAME
nodary token  create --user NAME --kind pt|sk [--name N] [--expires D] | list | revoke ID
              | join --uses N --expires D
```

`user passwd` is recognised and reports that it is not in this release, the way the
top-level planned verbs already do.

## Testing

| Package | Cases |
| :--- | :--- |
| `identity` roles | Every permission resolves to exactly one minimum role; an `operator` can `model.restart` and cannot `node.approve`; a `viewer` holds nothing a `user` does not |
| `identity` users | The state machine refuses `suspended → active` shortcuts it should refuse and allows the ones it should; a deleted user's name is reusable and a live one's is not; deletion scrubs the sealed seed; every verb produces a record naming the user as target |
| `identity` TOTP | RFC 6238's published vectors; a code is accepted once and refused the second time; a code from the previous step is accepted and one from two steps back is not; a seed round-trips through `secret.Seal` and never appears in `show` or `--format json` |
| `identity` tokens | The three prefixes survive into the stored `prefix` and into log output; plaintext appears exactly once and in no list, `show` or JSON output; a revoked token authenticates as revoked rather than as unknown; an expired one likewise; `last_used_at` advances |
| `secret` binding | A database sealed under key A refuses key B, accepts A, and accepts A after A is retired in favour of B; an unbound database binds on first seal |
| `cli` | Exit 3 for a non-root caller with no credentials; the seed is the only thing on stdout during enrollment; `--format json` carries no secret; every mutating verb writes a record and a failed one still does |

The token test that matters most is the one asserting no secret reaches list output: it is
the only thing that catches a field being added to a display struct and quietly carrying a
credential into a log.

## Steps

One commit per step, citing its task ID.

- [x] **1.** Spec corrections to [08 §1](../specs/08-data-model.md#1-schema); narrow R1-18; add R2-42
- [x] **2.** `0003_identity.sql` · **R1-18**
- [x] **3.** `identity` roles and permissions · **R1-20**
- [x] **4.** `identity` users through the audit seam · **R1-18**
- [x] **5.** TOTP: RFC 6238, then enrollment against the sealed seed · **R1-19**
- [x] **6.** The key binding and its refusal · **R1-36** — landed with step 5, because
      the first seal is where a database starts depending on a key
- [x] **7.** Tokens: mint, authenticate, revoke · **R1-21**
- [x] **8.** `~/.nodary/credentials` and the principal · **R1-22**
- [x] **9.** `nodary user` · **R1-23**
- [x] **10.** `nodary token` · **R1-24**

### Arguments are permuted so a flag after a name still works

Go's `flag` package stops parsing at the first argument that is not a flag, so
`nodary user add alice --role admin` leaves the role at its default and reports
an argument-count error. That is a defensible rule and not the one anybody
types, and getting it wrong here creates an account with the wrong authority and
says it succeeded. Positional arguments are moved after the flags before
parsing, asking the `FlagSet` whether each flag consumes a value rather than
guessing, and `--` still ends the flags.

*Rejected:* living with the convention and improving the error message. The
failure it produces is silent in the one case that matters.

### A join token carries a display prefix too

[08](../specs/08-data-model.md#1-schema) gave `join_token` no `prefix` column.
It has one now, for the same reason the `token` row does: it is what lets a
credential found in a log or pasted into a chat window be matched to a row
without holding anything that authenticates as one. The spec is corrected.

### A key mismatch refuses a mutation and not a read

The binding is checked when a session opens, and a session is what a mutating
verb opens. A read-only command is how an operator diagnoses a key problem, so
blocking one would remove the tool at the moment it is needed. Refusing the
mutation is the half that carries the weight: it stops a new secret being sealed
under a key that cannot read the existing ones.

### `Code` and `DecodeSeed` are exported for the enrollment conversation

Enrollment displays a seed and accepts only a code computed from it, so nothing
can confirm an enrollment without standing in for the authenticator — including
a test of the command. The two functions are the public face of a public
standard; neither authorises anything, because verification goes through
`VerifyTOTP`, which spends the step.

## Open items

**The key binding lives in `identity`, and moves when a second subsystem seals
something.** It needs both the keyring and audit's installation row, and neither
`secret` nor `audit` can import the other without putting the crypto downstream
of the log or the log downstream of the crypto. This package imports both, and
in R1 the only sealed value is a TOTP seed. [R2-40](../tasks/R2-control-plane.md)'s
CA key is the first thing that would make a package of its own worth creating.

**Nothing reports a key mismatch until somebody mutates.** A read-only command
is deliberately not blocked by one, so an operator whose appliance is only read
from would not learn about a missing key until the next change.
`nodary doctor` ([R2](../tasks/R2-control-plane.md)) is where that belongs.

**`last_used_at` records mutating use only.** It is stamped by `Touch` inside
the act a credential authorised, because nothing outside `internal/audit` may
write to the database — the seam working as intended. A token used only for
reads therefore looks unused, which understates it for stale-credential cleanup.
R1 has no read path worth auditing and no server; when R2 puts an API in front,
where reads are the bulk of the traffic, the stamp belongs on the request path.

**Can a `user` mint their own personal token?**
[07 §1](../specs/07-identity-audit.md#1-users-and-roles) puts *user and token management*
in the `admin` row and says nothing about self-service, so R1c requires `token.manage` for
every mint. That means a new operator cannot obtain a CLI credential without an admin,
which is the safe reading and possibly the wrong one. It is a spec question, not an
implementation one.
