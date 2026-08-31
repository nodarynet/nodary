# R1a — Storage foundation

**Slice of:** [R1](../tasks/R1-core-audit-identity.md) · **Tasks:** R1-01 – R1-04 ·
**Status:** in progress

The first of five slices of R1. [R1](../tasks/R1-core-audit-identity.md) is 31 tasks
whose internal dependencies are forced rather than chosen — attestation cannot be
designed before the audit seam exists to hang it on — so it is built in order:

```
R1a foundation ──► R1b audit chain ──┬──► R1c identity ──┐
                                     └──► R1d policy   ──┴──► R1e attestation
```

R1a has no upstream. It is where the one contract that can never change lives: every
hash in nodary is taken over the bytes `canonical` produces, so a change to those bytes
after records exist invalidates history that was never tampered with.

R1a ships no CLI verbs. The first user-visible surface is R1b's `audit` verbs, so
[10 §4](../specs/10-cli.md#4-output-discipline) and
[10 §5](../specs/10-cli.md#5-exit-codes) have nothing to bind to here.

## Decisions

Recorded because the reasoning is what outlives the work; the alternatives were real.

### Canonical JSON is RFC 8785 with floating-point rejected

JCS key ordering and string escaping exactly, but a non-integer number is an error at
encode time rather than a serialised value.

*Why not full RFC 8785:* its number rule is ES6 `Number.prototype.toString` — shortest
round-trip form with specific exponent thresholds. Implementing that wrongly corrupts
hashes **silently, and only for some values**, which is the worst available failure
shape for a tamper-detector. Rejecting floats converts that risk into a loud,
deterministic, test-visible error.

*Why not a typed encoder over the record struct:* `detail` is free-form JSON and would
need canonicalising regardless, so the problem does not go away. It would also force an
external verifier to reimplement nodary's field order from prose, which undercuts
[07 §3](../specs/07-identity-audit.md#3-the-audit-chain)'s argument that shipping the
JSONL mirror off-box is what makes tampering hard to undo quietly.

*Cost accepted:* nothing may record a fraction. Durations are integer milliseconds.
`detail` is ours to shape, so this is a convention to hold, not a limitation to work
around.

### `encoding/json` cannot be the basis of a hash

Go 1.27 ships both `encoding/json` and `encoding/json/v2`, and they disagree on the
same input:

```
v1: {"detail":"a\u003cb \u0026\u0026 c\u003ed"}     HTML-escapes < > &
v2: {"detail":"a<b && c>d"}                          does not
same bytes: false
```

v1 also sorts map keys by UTF-8 byte order rather than the UTF-16 order JCS requires,
and encodes structs in declaration order rather than sorted order. Building hashes on
any of it would bind the audit chain to stdlib behaviour that is actively diverging.
This is why R1-01 is a task and not a call to `json.Marshal`.

### The first migration creates only the migration table

Each later slice ships its own numbered migration beside the code that reads it — audit
in R1b, `user`/`token` in R1c, `policy` in R1d.

*Why not lay down all of [08 §1](../specs/08-data-model.md#1-schema) now:* most of those
tables serve R2–R4 decisions R1 has not tested. Migrations are forward-only
([08 §5](../specs/08-data-model.md#5-migrations)), so a wrong column guess costs a
permanent `ALTER` migration rather than an edit. This is the same reasoning that keeps
R3–R8 at deliverable level in [the tracker](../tasks/README.md).

## Design

### Layout

```
internal/
  paths/         default locations, one place
  canonical/     R1-01  RFC 8785 encoder + SHA-256 helper
  store/         R1-02  Open, DSN pragmas, reader/writer pools
    migrate.go   R1-03  forward-only runner
    migrations/  0001_schema_migration.sql
  secret/        R1-04  key file + AEAD helper
```

Every constructor takes an explicit path. `paths` holds the defaults from
[08](../specs/08-data-model.md) and nothing mutable, so tests pass temporary directories
instead of fighting package-level state.

### `canonical` — R1-01

```go
func Encode(v any) ([]byte, error)          // Go value    → canonical bytes
func EncodeJSON(b []byte) ([]byte, error)   // existing JSON → canonical bytes
func Hash(v any) ([32]byte, error)
```

Two entry points because a record is a struct while `detail` arrives as JSON. Both
funnel through one encoder so they cannot drift.

| Rule | Behaviour |
| :--- | :--- |
| Numbers | Parsed as `json.Number`, never `float64`. Accepted only as an optionally-signed digit string with no `.`, `e` or `E`, fitting `int64`. `-0` normalises to `0`. Anything else is an error naming the JSON path |
| Keys | Sorted by UTF-16 code unit |
| Strings | The eight JSON escapes, plus `\u00xx` for remaining C0 controls. No HTML escaping, no `/`, no escaping of non-ASCII |
| Duplicate keys | Rejected |
| Invalid UTF-8 | Rejected |

Decoding into `float64` would silently mangle integers above 2^53 — precisely the bug
this task exists to prevent, which is why `json.Number` is not optional.

UTF-16 ordering is not UTF-8 byte ordering. Above U+FFFF, characters encode as
surrogates in 0xD800–0xDBFF and so sort *below* U+E000–U+FFFF, where UTF-8 sorts them
above. Only reachable through nested objects in `detail`, and it gets a test.

Rejecting duplicate keys and invalid UTF-8 rather than resolving them is deliberate:
either one makes "the" canonical form ambiguous, and an ambiguous canonical form is not
one.

**Golden vectors in `testdata`**, including the official JCS suite minus its float
cases. That file is the actual guarantee behind R1-01's *byte-identically across Go
versions*: the `go-floor` CI job runs the suite under the declared floor as well as the
release toolchain, so a stdlib behaviour change breaks a test rather than history.

### `store` — R1-02

`modernc.org/sqlite` v1.57.0 (SQLite 3.53.3) — the driver
[08](../specs/08-data-model.md) names, and the reason the `go` floor is 1.25. Verified
cgo-free on all four [ADR 0002](../adr/0002-go-with-package-manager-wrappers.md)
targets, and measured rather than estimated:

| | Size |
| :--- | ---: |
| Hello-world, no dependencies | 1.4 MB |
| Hello-world + `modernc.org/sqlite` | 6.1 MB |
| **Driver costs** | **4.7 MB** |
| `nodary` today | 6.7 MB |
| `nodary` projected | 11.4 MB |

Against [ADR 0002](../adr/0002-go-with-package-manager-wrappers.md)'s stated "roughly
20 MB", this is the first and largest dependency the project takes and it fits.

DSN pragmas `journal_mode(WAL)`, `foreign_keys(1)`, `busy_timeout(5000)`,
`synchronous(FULL)`.

FULL rather than NORMAL: WAL with NORMAL can lose the most recent commits on power
loss, and what would be lost here is evidence.

`Open` returns a handle holding **two pools** — a writer capped at `MaxOpenConns(1)` and
an unrestricted reader. This is what makes R1-07's *concurrent writers cannot interleave
to produce two records claiming the same `seq`* structural rather than hopeful, and
placing it here means R1b never retrofits it.

Directory `0700`, database `0600`.

### `migrate` — R1-03

Migrations are `NNNN_name.sql`, embedded, applied in version order, each in its own
transaction. The runner takes an `fs.FS`, so tests drive it with `fstest.MapFS` rather
than fixtures on disk.

`0001_schema_migration.sql` creates the table the runner records into:

```sql
schema_migration(version PK, name, checksum, applied_at)
```

The runner therefore holds no bootstrap DDL in Go. It reads the applied set, treats *no
such table* as the empty set, and applies. The migration system comes up through its own
mechanism, and 0001 is a real migration rather than a placeholder.

`checksum` is SHA-256 of the file bytes, hex. At startup every applied migration is
re-hashed against the embedded copy and a mismatch aborts, naming the migration and both
hashes — [08 §5](../specs/08-data-model.md#5-migrations) requires refusing to proceed
against an unexpected schema, not repairing it. An applied version the binary does not
know about is a downgrade and is refused; the documented recovery is restoring a backup.

### `secret` — R1-04

```go
func Load(path string) (*Key, error)
func (k *Key) Seal(context string, plaintext []byte) ([]byte, error)
func (k *Key) Open(context string, ciphertext []byte) ([]byte, error)
```

AES-256-GCM from the standard library, random 96-bit nonce prepended. 32 random bytes,
hex-encoded so `/etc/nodary/secret.key` stays greppable, created `O_EXCL` at `0400`.

`O_EXCL` is load-bearing: two processes racing to create the key would otherwise leave
one of them silently encrypting under a key that is about to be overwritten. `Load`
refuses any file carrying group or other bits.

`context` becomes GCM's additional authenticated data — `"totp:user:42"`. Without it, an
attacker able to write the database can move user A's encrypted TOTP seed into user B's
row and it decrypts cleanly. Binding costs one parameter now and a re-encryption of
every stored secret later.

## Testing

| Package | Cases |
| :--- | :--- |
| `canonical` | Golden vectors; JCS suite minus floats; `Encode` is idempotent through a decode round trip; float, duplicate-key and invalid-UTF-8 rejection; UTF-16 versus UTF-8 ordering divergence; integers beyond 2^53 |
| `store` | WAL asserted after `Open`; every pragma asserted; `-wal` and `-shm` sidecars present; concurrent writers serialise; file and directory modes |
| `migrate` | Fresh database applies all; re-run is a no-op; altered checksum aborts naming the migration; unknown applied version refused as a downgrade; a failing migration rolls back whole |
| `secret` | Creates `0400` when absent; refuses loose modes; `O_EXCL` race leaves one key; round trip; wrong context fails; wrong key fails; a database copied without the key yields no plaintext |

The last `secret` case is R1-04's stated done-criteria, and the last `migrate` case is
R1-03's.

## Steps

The in-flight record. A tracker checkbox in
[R1](../tasks/R1-core-audit-identity.md) flips only when the task's `done:` criteria
actually pass. One commit per step, citing its task ID.

- [ ] **1.** `internal/paths` — default locations from [08](../specs/08-data-model.md)
- [ ] **2.** `internal/canonical` — encoder, `Hash`, golden vectors · **R1-01**
- [ ] **3.** `modernc.org/sqlite` dependency; `internal/store` `Open`, pragmas, pools · **R1-02**
- [ ] **4.** `migrate.go`, `0001_schema_migration.sql`, checksum and downgrade refusal · **R1-03**
- [ ] **5.** `internal/secret` — key file, AEAD, context binding · **R1-04**
- [ ] **6.** Correct the backup claim in [08](../specs/08-data-model.md) (see below)

## Open items

**[08](../specs/08-data-model.md) overstates the backup story.** It opens with *"One
file; back it up by copying it."* WAL makes that false: the probe produces `nodary.db`,
`nodary.db-shm` and `nodary.db-wal`, and copying the first alone loses whatever sits
uncheckpointed — which includes audit records. The tracker's rule is that
[the spec wins and gets fixed](../tasks/README.md), so the line is corrected to require
a checkpoint or `VACUUM INTO` rather than the code working around it. This also touches
[08 §4](../specs/08-data-model.md#4-secrets-at-rest), which already warns that a
database backed up without `/etc/nodary/secret.key` is useless.
