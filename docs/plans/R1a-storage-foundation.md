# R1a — Storage foundation

**Slice of:** [R1](../tasks/R1-core-audit-identity.md) · **Tasks:** R1-01 – R1-04 ·
**Status:** in progress

The first of five slices of R1. [R1](../tasks/R1-core-audit-identity.md) is 31 tasks
whose internal dependencies are forced rather than chosen — attestation cannot be
designed before the audit seam exists to hang it on — so it is built in order:

```
R1a foundation --> R1b audit chain --+--> R1c identity --+
                                     +--> R1d policy   --+--> R1e attestation
```

R1a has no upstream. It is where the contracts that can never change live: every hash in
nodary is taken over the bytes `canonical` produces, so altering those bytes after
records exist invalidates history that was never tampered with.

R1a ships no CLI verbs. The first user-visible surface is R1b's `audit` verbs, so
[10 §4](../specs/10-cli.md#4-output-discipline) and
[10 §5](../specs/10-cli.md#5-exit-codes) have nothing to bind to here.

## Decisions

Recorded because the reasoning is what outlives the work; the alternatives were real.

### Canonical JSON is RFC 8785 in full

Including ES6 number serialisation (§3.2.2.3), UTF-16 key ordering (§3.2.3) and JCS
string escaping (§3.2.2.2).

**This reverses an earlier decision, and the reversal is the point.** The plan first
specified JCS with floating-point rejected, on the stated premise that nodary records
contain no fractions. Review disproved the premise:

| Where | Value | Reaches |
| :--- | :--- | :--- |
| [03 §2](../specs/03-agent.md#2-desired-state-document) | `"gpu_memory_fraction": 0.92` | `deployment.params_json`, then `revision.snapshot_json`, hash-chained ([08 §2](../specs/08-data-model.md#2-revisions-replace-version-control)) |
| [12 §2](../specs/12-node-guardrails.md#2-the-file) | `max_vram_fraction = 0.90` | a refusal "written to the audit chain" ([12 §1](../specs/12-node-guardrails.md#1-where-they-apply)) |

An encoder that rejects fractions would hard-fail on records R2 and R4 are *specified*
to write, and a guardrail refusal that cannot name 0.92 against 0.90 is not a refusal.

The original objection to full JCS was that a wrong ES6 float implementation corrupts
hashes silently and only for some values — the worst failure shape available to a
tamper-detector. That objection assumed no reference to test against. There is one:
`github.com/gowebpki/jcs` v1.0.1 as a **test-only** dependency, plus the official
[cyberphone/json-canonicalization](https://github.com/cyberphone/json-canonicalization)
vectors, whose number suite exists precisely for this. A differential test converts the
risk into a test failure, which is the guard the rest of this plan already relies on.

*Why not decimal strings at the boundary* (`"gpu_memory_fraction": "0.92"`): it works,
and it removes float code entirely, but it amends two user-visible payload shapes and
makes every producer and consumer parse a string that JSON can already represent.

*Why not hashing the free-form fields as opaque text:* also works, and the `_json`
column suffix in [08 §1](../specs/08-data-model.md#1-schema) hints at it. But the JSONL
mirror then shows escaped JSON inside a string, and two semantically equal records hash
differently — a weaker property than the one
[07 §3](../specs/07-identity-audit.md#3-the-audit-chain) argues for.

### `encoding/json` cannot be the basis of a hash

Go 1.27 ships both `encoding/json` and `encoding/json/v2`, and they disagree on the same
input:

```
v1: {"detail":"a<b && c>d"}     HTML-escapes < > &
v2: {"detail":"a<b && c>d"}                          does not
same bytes: false
```

v1 also sorts map keys by UTF-8 byte order rather than the UTF-16 order JCS requires,
encodes structs in declaration order rather than sorted order, and **silently replaces
invalid UTF-8 in a Go string with U+FFFD instead of erroring**. Building hashes on any of
it would bind the audit chain to stdlib behaviour that is actively diverging. This is why
R1-01 is a task and not a call to `json.Marshal`.

### Serialisation order comes from SQL, not from Go pool configuration

An earlier draft claimed a writer pool capped at `MaxOpenConns(1)` made R1-07's *two
records cannot claim the same `seq`* structural. It does not, for three reasons:

- `database/sql` returns the connection to the pool between calls, so two goroutines
  running `SELECT max(seq)` then `INSERT` interleave freely on that one connection.
- [R1](../tasks/R1-core-audit-identity.md) states the CLI "operates on a local database
  directly", so a CLI process and a server process are two writers against one file. WAL
  serialises *writes*, not read-then-write across processes.
- The reflex fix is worse than the bug. With the default `deferred` transaction, a WAL
  reader that later attempts to write returns `SQLITE_BUSY_SNAPSHOT` **without invoking
  the busy handler**, so `busy_timeout` does not help and it surfaces as a spurious
  failure under exactly the concurrency the design claimed to have solved.

The guarantee therefore comes from `_txlock=immediate` on the writer DSN plus a single
`WriteTx` seam, with `seq` assigned inside that transaction rather than read before it.
`MaxOpenConns(1)` stays as a cheap in-process guard and is no longer described as the
mechanism.

### The first migration creates only the migration table

Each later slice ships its own numbered migration beside the code that reads it — audit
in R1b, `user` and `token` in R1c, `policy` in R1d.

*Why not lay down all of [08 §1](../specs/08-data-model.md#1-schema) now:* most of those
tables serve R2 through R4 decisions R1 has not tested. Migrations are forward-only
([08 §5](../specs/08-data-model.md#5-migrations)), so a wrong column guess costs a
permanent `ALTER` migration rather than an edit. Same reasoning that keeps R3 through R8
at deliverable level in [the tracker](../tasks/README.md).

## Design

### Layout

```
internal/
  paths/         default locations, one place
  canonical/     R1-01  RFC 8785 encoder + SHA-256 helpers
  store/         R1-02  Open, DSN pragmas, WriteTx
    migrate.go   R1-03  forward-only runner
    migrations/  0001_schema_migration.sql
  secret/        R1-04  key file + AEAD helper
```

Every constructor takes an explicit path and a `context.Context`, matching
`internal/components/verify.go`. `paths` holds the defaults and nothing mutable, so tests
pass temporary directories instead of fighting package-level state. It covers all four
locations the specs name, not just the database:

| Path | Mode | Source |
| :--- | :--- | :--- |
| `/var/lib/nodary/nodary.db` | 0600, dir 0700 | [08](../specs/08-data-model.md) |
| `/etc/nodary/secret.key` | 0400 root | [08 §4](../specs/08-data-model.md#4-secrets-at-rest) |
| `/var/log/nodary/audit.jsonl` | 0600 | [07 §3](../specs/07-identity-audit.md#3-the-audit-chain) |
| `~/.nodary/credentials` | 0600 | [07 §1](../specs/07-identity-audit.md#1-users-and-roles) |

### `canonical` — R1-01

```go
func Encode(v any) ([]byte, error)          // Go value      -> canonical bytes
func EncodeJSON(b []byte) ([]byte, error)   // existing JSON -> canonical bytes
func Hash(v any) ([32]byte, error)
func HashHex(v any) (string, error)         // lowercase hex, what the schema stores
```

`Encode` does **not** route through `json.Marshal`. Doing so would inherit v1's
struct-tag, `omitempty`, `json.Marshaler`, `time.Time` and `[]byte`-to-base64 behaviour
wholesale, and would make the invalid-UTF-8 rule unreachable — v1 substitutes U+FFFD
rather than erroring. Instead `Encode` reflects over a **closed value domain**:

```
string, bool, nil, int, int64, uint64, float64, json.Number,
map[string]any, []any, and structs with plain `json:"name"` tags
```

Anything else — a channel, a `json.Marshaler`, a `time.Time`, a `float32`, an
`omitempty` tag — is an error at encode time rather than a silent reinterpretation. A
golden test asserts `Encode(x)` and `EncodeJSON(json.Marshal(x))` agree byte-for-byte
over the domain, so the two entry points genuinely cannot drift.

| Rule | Behaviour | JCS |
| :--- | :--- | :--- |
| Numbers | ES6 `Number::toString` over the IEEE-754 double | §3.2.2.3 |
| Integers | Rejected when no double holds them exactly — an exactness test, not a magnitude one | see below |
| Keys | Sorted by UTF-16 code unit, on the **decoded** string, not its escaped form | §3.2.3 |
| Escapes | The seven JCS escapes — backspace, tab, newline, formfeed, return, backslash, quote. A forward slash is emitted literally | §3.2.2.2 |
| Other C0 | Four-digit hex escape in **lowercase**; an uppercase hex digit changes the hash of every record containing a control character | §3.2.2.2 |
| Non-ASCII | Emitted literally as UTF-8, never escaped | §3.2.2.2 |
| Lone surrogates | Rejected, naming the path | §3.2.2.2 |
| Duplicate keys | Rejected | ambiguous otherwise |
| Invalid UTF-8 | Rejected | ambiguous otherwise |

On integers: JCS requires every number be expressible as an IEEE-754 double, so a
conforming implementation given 2^53+1 emits `9007199254740992` — it rounds. nodary
**refuses** such input instead. That is a restriction of the accepted domain, not a
different number rule: on every input we accept, our output is byte-identical to any
conforming JCS implementation. Refusing beats silently losing precision, and it is what
RFC 7493 §2.2 recommends for interoperable JSON. `seq` will not approach 2^53.

The test is exactness, **not** magnitude, and an earlier draft of this plan got it
wrong. 2^53 is only the point below which *every* integer is representable; plenty of
larger ones still are, and 10^17 is one of them. A magnitude check therefore made the
encoder emit `100000000000000000` for the input `1e17` and then refuse to read its own
output back — `FuzzEncodeJSON` found it in under a second, and the failing input is kept
as a corpus seed. Producing a canonical form that cannot be re-canonicalised would have
broken `audit verify`, which re-hashes stored records to walk the chain.

Lone surrogates need their own rule because a UTF-8 check does not catch them: a string
containing only the escape `\udead` is valid ASCII, valid RFC 8259, and `encoding/json`
decodes it silently to U+FFFD. JCS §3.2.2.2 requires terminating with an error, because
the alternative is "broken signatures".

**Golden vectors in `testdata`**: the official
[cyberphone](https://github.com/cyberphone/json-canonicalization) suite in full — now
that floats are supported its number vectors are usable rather than excluded — plus a
differential test against `github.com/gowebpki/jcs` (test-only), a `go test -fuzz` target
over `EncodeJSON` asserting idempotence and no panic, and a case for each rejection rule.
Those files are the actual guarantee behind R1-01's *byte-identically across Go
versions*, and the `go-floor` CI job runs the suite under the declared floor as well as
the release toolchain, so a stdlib change breaks a test rather than history.

#### What R1a freezes for R1b

The encoder fixes these whether or not it means to, so they are decided here:

- **Record shape is fixed.** Every record carries all twelve fields of
  [07 §3](../specs/07-identity-audit.md#3-the-audit-chain); an unset optional is JSON
  `null`, never absent and never an empty string. `omitempty` is banned outright —
  absent, `null` and empty are three different hashes, and `omitempty` semantics differ
  between `encoding/json` v1 and v2.
- **`ts` is `2006-01-02T15:04:05.000Z`** — RFC3339, always `Z`, exactly three fractional
  digits. Go's `time.Time` marshalling trims trailing zeros, so two records written in
  the same second would otherwise hash under different formats. A `Clock` seam makes
  R1b's chain tests deterministic.
- **Genesis `prev_hash` is 64 `0` characters**, not empty and not `null`, so the field is
  a 64-character lowercase hex string in every record and `audit verify` needs no special
  case at seq 1.
- **A record's own `hash` is excluded** from the bytes it hashes. Everything else,
  including `prev_hash`, is included.

### `store` — R1-02

`modernc.org/sqlite` v1.57.0 (SQLite 3.53.3) — the driver
[08](../specs/08-data-model.md) names, and the reason the `go` floor is 1.25. Verified
cgo-free on all four [ADR 0002](../adr/0002-go-with-package-manager-wrappers.md) targets,
and measured rather than estimated:

| | Size |
| :--- | ---: |
| Hello-world, no dependencies | 1.4 MB |
| Hello-world + `modernc.org/sqlite` | 6.1 MB |
| **Driver costs** | **4.7 MB** |
| `nodary` today | 6.7 MB |
| `nodary` projected | 11.4 MB |

Against ADR 0002's stated "roughly 20 MB", the first and largest dependency the project
takes fits.

Two DSNs, differing in the one parameter that carries the whole concurrency argument:

```
writer  file:PATH?_txlock=immediate&_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)
                 &_pragma=busy_timeout(5000)&_pragma=synchronous(FULL)

reader  file:PATH?_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)
                 &_pragma=busy_timeout(5000)&_pragma=synchronous(FULL)
```

`synchronous(FULL)` rather than NORMAL: WAL with NORMAL can lose the most recent commits
on power loss, and what would be lost is evidence.

`_txlock=immediate` takes the write lock at `BEGIN` rather than at first write, so the
busy handler applies and `busy_timeout` works. Without it a read-then-write transaction
returns `SQLITE_BUSY_SNAPSHOT` immediately and bypasses the timeout entirely.

```go
func Open(ctx context.Context, path string) (*DB, error)
func (db *DB) WriteTx(ctx context.Context, fn func(*sql.Tx) error) error
func (db *DB) Read() *sql.DB
```

`WriteTx` is the **only** write path, which is what lets R1b assign `seq` and `prev_hash`
inside one immediate transaction and makes R1-07's guarantee real across processes.

`Open` sets and verifies `PRAGMA application_id`, so pointing at an unrelated SQLite file
is an error rather than a migration run against someone else's data. Directory 0700,
database 0600, and the `-wal` and `-shm` sidecars 0600 too — the WAL holds uncommitted
audit records and encrypted secrets, and
[08 §4](../specs/08-data-model.md#4-secrets-at-rest)'s posture makes a 0644 sidecar a
real leak.

`Close` runs a `TRUNCATE` checkpoint. An unrestricted reader pool holding open read
transactions prevents WAL truncation, so without a policy the WAL grows without bound,
which makes the backup problem in Open items strictly worse.

### `migrate` — R1-03

Migrations are `NNNN_name.sql`, embedded, applied in version order. The runner takes an
`fs.FS`, so tests drive it with `fstest.MapFS` rather than fixtures on disk.

The whole run happens inside one `WriteTx`, and the applied set is re-read *after* the
write lock is acquired. Without that, two processes — and
[R1](../tasks/R1-core-audit-identity.md) guarantees two, since the CLI opens the database
directly — race to apply the same migration.

`0001_schema_migration.sql` creates the table the runner records into:

```sql
schema_migration(version PK, name, checksum, applied_at)
```

so the runner holds no bootstrap DDL in Go. Presence is probed with
`SELECT count(*) FROM sqlite_master WHERE type='table' AND name='schema_migration'`,
**not** by matching a "no such table" error string: the driver returns `SQLITE_ERROR`
with different messages for many failures, and string-matching would read a corrupt
database as a fresh one.

Each migration's DDL and its `schema_migration` row are written in the *same*
transaction. Otherwise a crash between them leaves 0001's table present with an empty
applied set, 0001 re-runs, `CREATE TABLE` fails, and startup is permanently dead.

`checksum` is SHA-256 of the file bytes, hex. At startup every applied migration is
re-hashed against the embedded copy and a mismatch aborts, naming the migration and both
hashes — [08 §5](../specs/08-data-model.md#5-migrations) requires refusing to proceed
against an unexpected schema, not repairing it. `.gitattributes` pins `*.sql` to LF so a
CRLF checkout cannot produce a mismatch that reports as tampering.

Two further refusals, both aborting:

- an applied version the binary does not know about — a **downgrade**, whose documented
  recovery is restoring a backup;
- an embedded version *below* the maximum applied but absent from the applied set, which
  is what two branches numbering independently produces.

Migration files containing `PRAGMA` or `VACUUM` are rejected at load. SQLite does give
transactional DDL, so a failing migration rolls back whole — but `PRAGMA foreign_keys` is
silently a no-op inside a transaction, which would break the standard twelve-step table
rebuild a future `ALTER` needs.

### `secret` — R1-04

```go
func Load(path string) (*Key, error)
func (k *Key) Seal(context string, plaintext []byte) ([]byte, error)
func (k *Key) Open(context string, ciphertext []byte) ([]byte, error)
```

AES-256-GCM from the standard library. Ciphertext is
`version(1) || keyID(4) || nonce(12) || ciphertext`, where `keyID` is the first four
bytes of SHA-256 over the key material. Five bytes of overhead buys incremental rotation:
`Load` accepts a primary key plus retired ones, `Open` selects by id and reports an
unknown id clearly. Without an id, rotation is a flag day — decrypt and re-encrypt
everything in one transaction, with no resumability and no way to verify afterwards which
rows moved.

The key is 32 random bytes, hex-encoded so `/etc/nodary/secret.key` stays greppable.
Creation is **not** a bare `O_EXCL` create: a crash between create and write leaves a
truncated file that `O_EXCL` then refuses to replace, and per
[11 §5](../specs/11-failure-modes.md#5-recovery) that is unrecoverable for encrypted
material — every TOTP enrollment redone and every agent re-enrolled, caused by a power
cut during first install. Instead: write a temporary file in the same directory, `fsync`
it, `fsync` the directory, then `link` it to the final path. `link` is atomic and still
fails if the target exists, so it keeps the race protection.

`Load` opens `O_NOFOLLOW` and refuses a file that carries group or other bits, is not
owned by root, or is not exactly 64 lowercase hex characters with an optional trailing
newline.

`context` becomes GCM's additional authenticated data — `"totp:user:42"`. Without it an
attacker able to write the database can move user A's encrypted TOTP seed into user B's
row and it decrypts cleanly.

**A constraint this places on R1c:** any id used in an AAD context must never be reused.
SQLite reuses the rowid of a deleted row under a plain `INTEGER PRIMARY KEY`, and
[07 §1](../specs/07-identity-audit.md#1-users-and-roles) has a `deleted` state — so
deleting user 42 and creating another that lands on 42 would let the old ciphertext
authenticate under the new user. `user.id` must be `AUTOINCREMENT` or an opaque `usr_`
string. Recorded here because R1a is where the rule originates.

## Testing

| Package | Cases |
| :--- | :--- |
| `canonical` | Official cyberphone vectors in full; differential test against `gowebpki/jcs`; `go test -fuzz` over `EncodeJSON` for idempotence and no panic; `Encode(x)` equals `EncodeJSON(json.Marshal(x))` over the closed domain; rejection of non-finite floats, integers past 2^53, lone surrogates, duplicate keys and invalid UTF-8; UTF-16 versus UTF-8 key-order divergence; lowercase hex escapes |
| `store` | WAL asserted after `Open`; every pragma asserted; sidecars present **and 0600**; `application_id` mismatch refused; file and directory modes; `WriteTx` serialises across **N forked processes**, not just goroutines; `Close` truncates the WAL |
| `migrate` | Fresh database applies all; re-run is a no-op; altered checksum aborts naming the migration; unknown applied version refused as downgrade; missing lower version refused; a failing migration rolls back whole; concurrent runners in separate processes apply once; `PRAGMA` in a migration file rejected |
| `secret` | Creates 0400 when absent; refuses loose modes, non-root owner, symlink and malformed contents; a crash between create and link leaves no unusable key; round trip; wrong context fails; unknown key id reported; a database copied without the key yields no plaintext |
| CI | All four ADR 0002 targets cross-build with `CGO_ENABLED=0`, and the host binary is asserted to carry no dynamic linkage |

The last `secret` row is R1-04's stated `done:` criterion, the checksum row is R1-03's,
and the CI row is R1-02's — which nothing in the tree currently asserts, since `make
check` never builds and `go-floor` builds with the runner's default `CGO_ENABLED=1`.

## Steps

The in-flight record. A tracker checkbox in
[R1](../tasks/R1-core-audit-identity.md) flips only when the task's `done:` criteria
actually pass. One commit per step, citing its task ID.

- [x] **1.** `internal/paths` — the four locations above
- [x] **2.** `internal/canonical` — encoder, ES6 numbers, `Hash` and `HashHex`, vectors, fuzz · **R1-01**
- [x] **3.** `modernc.org/sqlite`; `internal/store` `Open`, DSNs, `WriteTx`, `application_id` · **R1-02**
- [ ] **4.** CI: cross-build all four targets with `CGO_ENABLED=0` and assert static · **R1-02**
- [ ] **5.** `migrate.go`, `0001_schema_migration.sql`, checksum, downgrade and gap refusal · **R1-03**
- [ ] **6.** `internal/secret` — atomic creation, validation, versioned ciphertext, AAD · **R1-04**
- [ ] **7.** Correct [08](../specs/08-data-model.md) on backup and on who migrates (below)

## Open items

**[08](../specs/08-data-model.md) overstates the backup story.** It opens with *"One
file; back it up by copying it."* WAL makes that false: the probe produces `nodary.db`,
`nodary.db-shm` and `nodary.db-wal`, and copying the first alone loses whatever sits
uncheckpointed — which includes audit records. The tracker's rule is that
[the spec wins and gets fixed](../tasks/README.md), so the line is corrected to require a
checkpoint or `VACUUM INTO`. This also touches
[08 §4](../specs/08-data-model.md#4-secrets-at-rest), which already warns that a database
backed up without `/etc/nodary/secret.key` is useless.

**[08 §5](../specs/08-data-model.md#5-migrations) says migrations are applied "at server
start", but [R1](../tasks/R1-core-audit-identity.md) has no server and states the CLI
"operates on a local database directly".** As built, any *writable* open migrates,
guarded by the immediate transaction described above; a read-only open refuses when the
schema is behind rather than migrating underneath a reader. 08 §5 is widened to say so.
