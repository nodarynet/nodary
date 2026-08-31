# R1b — Audit chain

**Slice of:** [R1](../tasks/R1-core-audit-identity.md) · **Tasks:** R1-05 – R1-12 ·
**Status:** in progress

The second of five slices of R1.

```
R1a foundation --> R1b audit chain --+--> R1c identity --+
                                     +--> R1d policy   --+--> R1e attestation
```

R1b inherits four contracts [R1a](R1a-storage-foundation.md) froze — the fixed record
shape with `null` for unset optionals, `ts` as `2006-01-02T15:04:05.000Z`, a genesis
`prev_hash` of 64 zeros, and `hash` excluded from its own preimage — and adds no new
freedom to reinterpret them.

It ships the first user-visible verbs, so [10 §4](../specs/10-cli.md#4-output-discipline)
and [10 §5](../specs/10-cli.md#5-exit-codes) bind here for the first time.

**R1b has no production writer.** Nothing in R1 mutates state yet; `user add` in
[R1c](../tasks/R1-core-audit-identity.md) is the first real caller of the seam. That is
the right order — R1-12 requires that a mutating function *cannot be written* without a
record, which has to be true before the first one exists — and it is why R1-12's proof is
structural rather than a survey of call sites.

## Scope

Two things are easy to conflate and are kept apart throughout:

| | Configurable? | Cost |
| :--- | :--- | :--- |
| **The chain** — record, hash, `prev_hash`, `verify` | No | One SHA-256 per operator action |
| **Delivery** — where records go afterwards | Yes: file, stdout, stderr, none, later a SIEM endpoint | Whatever the destination costs |

The chain is not configurable because
[07 §4](../specs/07-identity-audit.md#4-policy-profiles) already settled it: it is on the
short list of properties no profile turns off, on the grounds that they cost nothing at run
time and what a profile adjusts is ceremony and retention. A homelab operator never sees
it. A site under CMMC needs exactly it —
[NIST SP 800-171](https://csrc.nist.gov/pubs/sp/800/171/r2/upd1/final) 3.3.8 requires audit
information be protected from *modification and deletion*, and a hash chain is the cheapest
credible answer, which is why [07 §5](../specs/07-identity-audit.md#5-control-mapping)
already maps AU-9 to it.

Delivery is configurable because the destinations genuinely differ: a container wants
stdout, an appliance wants a file for a shipper to tail, a regulated site wants both plus a
SIEM with WORM retention, and a laptop running tests wants nothing at all.

**What this slice does not build:** a direct Elastic or Splunk client. Shipping to a SIEM
with WORM retention is what a CMMC deployment needs and no MVP install does, and the URL,
credentials and TLS settings such a sink requires have nowhere to live until
[R2-35](../tasks/R2-control-plane.md) brings `server.toml`. Guessing that shape now freezes
the wrong guess. Tracked as [R2-41](../tasks/R2-control-plane.md).

### What makes that deferral safe

Deferring is only legitimate if the later work is additive, so the three things that could
*not* be added later are done here:

| | Why it cannot wait |
| :--- | :--- |
| `Sink` — one interface, `Act` writes a list of them | A network sink becomes a new implementation; nothing in the write path changes |
| `install` and `v` in the record | Both sit inside the hash preimage. Adding either later changes the bytes every existing record hashed, so it is now or never |
| `audit export --from-seq N` | The re-sync path for a destination that fell behind, which is what lets a sink be at-least-once instead of transactional |

Everything else a network sink needs — retry policy, batching, credentials, TLS — is
internal to that sink and touches nothing here.

## Decisions

### Sinks run after the commit, and the database is the authoritative record

An earlier draft of this plan appended to the JSONL file *inside* the write transaction,
before the commit, so the file was guaranteed to be a superset of the database. That is the
right design only if the file is mandatory. It is not, so it is gone, and with it the
ordering argument, the crash-window fork case, and the fork detection `verify` needed to
explain it.

The record is written to `audit` inside the same transaction as the change it describes.
That commit is the moment the record exists. Sinks are written afterwards, outside the
transaction, and a sink failure cannot roll back a change that already happened or block a
change that has not.

The cost is that a sink can fall behind the database: a crash between commit and delivery
leaves the file missing a record. That is detectable — every line carries `seq`, so a gap
is visible — and recoverable, because `audit export --from-seq N` replays from the
authoritative copy. A destination that must not miss anything is re-synced from the
database, which is the only place that never misses anything.

The window is small: the file sink emits synchronously as `Act` returns, not from a
background queue, so only a crash between the commit and the next few microseconds loses a
line. That matters because R1-08 owns
[11 §5](../specs/11-failure-modes.md#5-recovery)'s *database corrupt* row, whose recovery is
the JSONL file being independent of the database. It still is; the honest statement is that
it can trail by at most the record being written when the process died, rather than that it
can never trail at all.

### Delivery posture is configuration, not law

```
NODARY_AUDIT_SINKS=file:/var/log/nodary/audit.jsonl
NODARY_AUDIT_ON_SINK_FAILURE=warn        # or: block
```

`warn` reports the failure on stderr, marks delivery degraded, and carries on. `block`
refuses the *next* mutation while a sink is failing, and says which sink. It cannot refuse
the current one — the record is already committed — and describing it as anything stronger
would be a lie about what a post-commit sink can do.

`warn` is the default, including for compliance deployments.
[NIST SP 800-171](https://csrc.nist.gov/pubs/sp/800/171/r2/upd1/final) 3.3.4 asks for an
*alert* on an audit logging process failure, not a halt; NIST SP 800-53 AU-5 offers the
halt as an enhancement rather than the baseline. A full `/var/log` should not stop an
operator restarting a model. `block` exists for the site that has decided otherwise, and
[07 §4](../specs/07-identity-audit.md#4-policy-profiles) is where that decision belongs
once profiles exist.

The environment variables are the temporary carrier. The **sink specification string** is
the durable part — `file:PATH`, `stdout`, `stderr`, `none`, and later `elastic:URL` or
`splunk-hec:URL` — because it is what a config file, a flag and an environment variable
will all end up parsing.

*Why a string spec rather than a struct now:* R1b has no config file to put a struct in,
and the parser is forty testable lines that R1d reuses rather than replaces.

### `stdout` is for the server, and the CLI refuses it

[10 §4](../specs/10-cli.md#4-output-discipline) reserves stdout for the command's own
output, and `--format json` promises a stable document and *nothing else*. An audit record
emitted onto stdout by a one-shot CLI command corrupts that document.

So: the `stdout` sink is legitimate for `nodary server`, whose stdout *is* the log stream
and which is how a container expects to be read. A CLI command that would write a document
to stdout refuses to start with a `stdout` sink configured, naming the conflict, rather
than producing output that parses as neither one thing nor the other. The CLI default is
the file sink; `stderr` is available for anyone who wants records on a terminal.

### Two fields have to exist now for a stream to be usable

Both sit inside the hash preimage, so neither can be added once records exist.

**`install`** — a SIEM aggregates several nodary installations, and every one of them
starts at `seq` 1 with the same 64-zero `prev_hash`. Without an installation identity their
records interleave into one indistinguishable stream. A shipper can tag by host, but a tag
added outside the record is one that whoever controls the shipper can change; inside the
preimage it is bound to the hash. An opaque `ins_` string, minted on first write, held in a
one-row table.

**`v`** — the record schema version. A field set that can never grow will eventually be
wrong; one that grows without a version is unverifiable, because re-encoding an old record
under a new shape changes its hash and reports tampering that never happened. `v` is `1`,
costs three bytes, and is what lets a later slice add a field —
[07 §3](../specs/07-identity-audit.md#3-the-audit-chain)'s forwarded agent records need a
per-node sequence number, so the next one is already visible — while every existing record
still verifies under the builder that made it.

Both push [07 §3](../specs/07-identity-audit.md#3-the-audit-chain)'s table from twelve
fields to fourteen, so the spec is corrected rather than quietly exceeded.

### The record is nested; the row is flat

```json
{"v":1,
 "install":"ins_9c1d0f4a7b28e5364d0a1f77b3c2e590",
 "seq":1,
 "ts":"2026-08-31T09:14:02.371Z",
 "actor":{"id":"root","method":"local","session":null},
 "source":{"ip":null,"version":"0.0.1-rc1"},
 "action":"user.add",
 "target":{"kind":"user","id":"usr_01J8Z..."},
 "intent_hash":null,
 "justification":null,
 "outcome":"success",
 "detail":{},
 "prev_hash":"0000000000000000000000000000000000000000000000000000000000000000",
 "hash":"9f2c..."}
```

[07 §3](../specs/07-identity-audit.md#3-the-audit-chain) gives `actor` three contents,
`source` two, and `target` a kind plus an identity. They are objects because that is what
they are.

The **row is the same record decomposed into flat columns**, which corrects
[08 §1](../specs/08-data-model.md#1-schema): its sketch shows `actor`, `source` and
`target` as single columns while naming `detail_json` with the suffix it uses everywhere
else for JSON. R1-10 filters on `--actor`, and a filter wants an indexed column rather than
`json_extract` over a blob.

*Why not flatten the record too*, to sixteen scalar fields: it contradicts
[07 §3](../specs/07-identity-audit.md#3-the-audit-chain)'s field list, which R1-05's
`done:` criterion names one by one, and it makes the line that leaves the machine a wall of
`actor_`-prefixed columns for whoever reads it in a SIEM.

*Why not also store the canonical record verbatim in an extra column*, so verification
never reassembles: the duplicate is authoritative in neither direction — if the columns and
the blob disagree, nothing says which is the record. The reassembly path is instead
exercised by every `audit verify` over every record.

Reassembly must be lossless, because a lossy field reports tampering that never happened —
the one failure a tamper-detector must not have. Two `CHECK` constraints make the ambiguous
cases unrepresentable rather than merely tested: `(target_kind IS NULL) = (target_id IS
NULL)`, so a half-null target cannot decide between `null` and an object; and a `ts` shape
check, so a malformed timestamp cannot enter and then re-encode differently.

### Field names exist in exactly one place

`Record` is a Go struct, but the bytes that get hashed come from a single `members()`
method returning `map[string]any`. The preimage is that map minus `hash`; the sink line and
the JSONL export are that map whole.

The alternative — a `Record` struct plus a near-identical `preimage` struct — puts fourteen
field names in two places, and the failure mode of them drifting is that hashes silently
stop matching for records carrying one particular field.

### The schema refuses a chain fork independently of the transaction

R1-07 requires that concurrent writers cannot produce two records claiming the same `seq`
or the same predecessor. The mechanism is R1a's: read the tail, compute, insert, all inside
one `_txlock=immediate` transaction, which serialises across processes and not merely
across goroutines.

On top of that, `prev_hash` and `hash` are both `UNIQUE`. That moves R1-07's second clause
out of transaction discipline and into the schema, where it holds even for a writer that
ignores `WriteTx`, a future migration that gets the locking wrong, or a hand-run `sqlite3`.
A chain fork becomes a constraint violation, and a second genesis record is impossible since
64 zeros can only appear once.

### The seam is a capability, not a convention

R1-12 requires that a mutating core function cannot be reached without producing a record,
*enforced structurally*. The enforcement is an interface no other package can implement:

```go
type Mutation interface {
    Tx() *sql.Tx
    Detail(key string, value any)
    mutation()          // unexported: unimplementable outside this package
}

func (l *Log) Act(ctx context.Context, req Request, fn func(Mutation) error) (Record, error)
```

A core function that changes state takes a `Mutation`. Go has no way to satisfy that
parameter outside `internal/audit`, and `Act` is the only thing that produces one. This is
less code than threading a logger through every call site, and it cannot be forgotten.

**What it does not do**, stated because a half-true guarantee is worse than none: a caller
holding a `Mutation` has the raw transaction and could write to the `audit` table itself,
or delete from it. So could anyone holding the file. That is what the chain is for — it
makes tampering detectable rather than impossible, exactly as
[07 §3](../specs/07-identity-audit.md#3-the-audit-chain) says.

The remaining hole is a package bypassing the seam by calling `store.WriteTx` directly.
Types cannot close it, because `Migrate` needs `WriteTx` and is not a mutation. A test
fails if any package other than `store` or `audit` names `WriteTx` — a CI gate rather than
a property of the language, and described here as such.

### An outcome of `failure` is recorded after the rollback, not with it

`success` and `partial` records are written in the same transaction as their effect, so the
record and the change commit together or not at all.

`failure` cannot be: the record would be rolled back along with the failed mutation. It is
written afterwards, in its own transaction. A crash in that window loses the record — and
loses nothing else, because a failed mutation changed nothing. The asymmetry is inherent
rather than chosen, and it is the right way round.

`partial` is for a mutation whose effect reached somewhere the transaction does not cover —
a node, a systemd unit — and so is recorded like a success.

### Timestamps are recorded true, not monotonic

`ts` is fixed-width UTC with three fractional digits, so lexicographic order is
chronological order and `--from`/`--to` are string comparisons on an indexed column.

A backward clock step therefore produces a record whose `ts` precedes its predecessor's.
Clamping was rejected: a record reporting a time the machine was not at is a worse defect
than one reporting the truth about a machine whose clock moved. `verify` reports
non-monotonic timestamps as a **warning naming both sequence numbers**, separately from
chain breaks, because the causes are unrelated and only one of them is tampering.
[NIST SP 800-171](https://csrc.nist.gov/pubs/sp/800/171/r2/upd1/final) 3.3.7 asks for clock
synchronisation against an authoritative source, which is an operating-system concern; what
nodary owes is not hiding it when it fails.

### `audit export --format` takes `jsonl|csv`, not `text|json`

[10 §2](../specs/10-cli.md#2-global-flags) makes `--format text|json|yaml` global;
[09 §1](../specs/09-api.md#1-surface) specifies `GET /audit/export?format=jsonl|csv`. On
this one verb the value set is the export encoding, so `audit export` documents its own
values and rejects the global ones with a message naming what it accepts. Recorded because
it is the first place the global flag table is not literally true, and
[10](../specs/10-cli.md) is corrected to say so.

The JSONL export is **byte-identical to the sink lines** for the same records — asserted by
a test, because it is what lets an operator diff an export against a shipped copy and get
an empty result when nothing is wrong.

## Design

```
internal/
  audit/
    record.go    R1-05  Record, members(), the fourteen fields in one place
    hash.go      R1-06  preimage and hash over canonical bytes
    chain.go     R1-07  Append inside WriteTx; seq and prev_hash
    sink.go      R1-08  Sink, the spec parser, failure posture
    file.go      R1-08  file sink; console.go: stdout and stderr
    log.go       R1-12  Log, Request, Mutation, Act
    query.go     R1-10  List and Walk, seq descending
    verify.go    R1-09  chain walk, first break by seq
    export.go    R1-11  JSONL and CSV writers
  store/
    migrations/0002_audit.sql
  cli/
    audit.go     R1-09, R1-10, R1-11  the three verbs
```

### Schema — `0002_audit.sql`

```sql
CREATE TABLE audit (
  seq            INTEGER PRIMARY KEY,
  v              INTEGER NOT NULL,
  install        TEXT    NOT NULL,
  ts             TEXT    NOT NULL,
  actor_id       TEXT,
  actor_method   TEXT    NOT NULL,
  actor_session  TEXT,
  source_ip      TEXT,
  source_version TEXT,
  action         TEXT    NOT NULL,
  target_kind    TEXT,
  target_id      TEXT,
  intent_hash    TEXT,
  justification  TEXT,
  outcome        TEXT    NOT NULL,
  detail_json    TEXT    NOT NULL,
  prev_hash      TEXT    NOT NULL UNIQUE,
  hash           TEXT    NOT NULL UNIQUE,

  CHECK (seq > 0),
  CHECK (v > 0),
  CHECK (outcome IN ('success','failure','partial')),
  CHECK (length(hash) = 64 AND length(prev_hash) = 64),
  CHECK (ts LIKE '____-__-__T__:__:__.___Z'),
  CHECK ((target_kind IS NULL) = (target_id IS NULL))
) STRICT;

CREATE INDEX audit_ts     ON audit(ts);
CREATE INDEX audit_actor  ON audit(actor_id);
CREATE INDEX audit_action ON audit(action);

CREATE TABLE installation (
  singleton  INTEGER PRIMARY KEY CHECK (singleton = 1),
  id         TEXT    NOT NULL,
  created_at TEXT    NOT NULL
) STRICT;
```

`seq` is the rowid and is assigned explicitly, never by SQLite, so ordering by sequence
descending is free — which is what [09 §2](../specs/09-api.md#2-conventions) requires of
every audit listing.

`installation` holds one row and the `CHECK` keeps it that way; the id is minted on first
write, because a migration is static SQL and cannot generate one. It is also where
[R1-36](../tasks/R1-core-audit-identity.md) — record the active key id, so a deleted
`secret.key` is refused rather than silently re-minted — belongs when R1c reaches it.

### `store.OpenReadOnly` — a gap R1a left

[08 §5](../specs/08-data-model.md#5-migrations) says a read-only open refuses when the
schema is behind rather than migrating underneath a reader. R1a implemented the writable
half and nothing needed the other until now: `audit list`, `verify` and `export` are all
read-only, and an operator inspecting a chain should not change the file they are
inspecting.

```go
func OpenReadOnly(ctx context.Context, path string) (*DB, error)
```

Refuses a missing file rather than creating one, opens `mode=rw&_query_only=1`, verifies
`application_id`, and runs the migrator's own reconciliation so a downgrade, a checksum
mismatch and an outstanding migration are reported in the migrator's words rather than as
*no such column* three queries later.

`mode=rw` is the mechanism and matters more than it looks: `_query_only=1` alone still
**creates** the database, so `audit verify` against a mistyped path would report an empty
chain over a file it had just invented — the most misleading answer an evidence tool can
give. `mode=ro` was measured and rejected: SQLite needs the `-shm` index to read a WAL
database at all, so the sidecars appear either way and it buys nothing, while it cannot
recover a `-wal` left by a writer that crashed — which would break `verify` at exactly the
moment someone needs it. The honest guarantee is *no create, no migrate, no journal_mode
conversion, no write*, not *no file touched*.

### `audit` — the record and its hash

```go
func (r Record) members() map[string]any   // the fourteen fields; the only place they are named
func (r Record) Preimage() ([]byte, error) // members minus hash, canonical
func (r Record) Compute() (string, error)  // sha256 of Preimage, lowercase hex
func (r Record) Line() ([]byte, error)     // members whole, canonical — sinks and export
```

`detail` is decoded from `detail_json` with `UseNumber`, so a number survives the round trip
as the digits it was written with rather than as a float64 approximation of them.

`Compute` rather than `Hash`, because a field called `Hash` and a method called `Hash` on
one type is a collision waiting to be resolved in the wrong direction.

### `Log.Act`

```go
type Log struct { db *store.DB; sinks []Sink; onFailure Posture; clock func() time.Time }

func New(db *store.DB, sinks []Sink, opts ...Option) *Log
func (l *Log) Act(ctx context.Context, req Request, fn func(Mutation) error) (Record, error)
```

1. under `block`, refuse up front if delivery is currently degraded, naming the sink;
2. one `WriteTx`: run `fn` collecting detail; on error return it so the transaction rolls
   back, then write the `failure` record in its own transaction; otherwise read the tail
   (`SELECT seq, hash FROM audit ORDER BY seq DESC LIMIT 1`), build the record, compute its
   hash, `INSERT`, commit;
3. after the commit, emit the line to each sink in order. A failure marks delivery degraded
   and is reported on stderr; it does not fail `Act`, because the record already exists.

The clock is injectable so chain tests are deterministic, per R1a's note.

### Sinks

```go
type Sink interface {
    Emit(ctx context.Context, seq int64, line []byte) error
    Name() string
    Close() error
}

func ParseSinks(spec string) ([]Sink, error)   // "file:/var/log/nodary/audit.jsonl,stderr"
```

The file sink opens per record with `O_WRONLY|O_APPEND|O_CREATE` at 0600 under a 0700
directory, writes, `fsync`s and closes. Holding the descriptor open across a process
lifetime was rejected: an append-only log is the thing most likely to be rotated by
something outside nodary, and a held descriptor keeps writing into the unlinked inode.
Reopening by path also makes rename-and-create rotation safe; `copytruncate` is unsafe for
any appender and belongs in the operations documentation as a constraint. The directory is
`fsync`ed on creation so the entry survives a power cut.

`Name` exists so a degraded-delivery message can say which sink and where.

### `verify` — R1-09

Streams the chain in ascending sequence and reports the **first** break, by sequence:

| Check | Reported as |
| :--- | :--- |
| recomputed hash ≠ stored hash | record *k* altered |
| `prev_hash` ≠ predecessor's `hash` | chain broken at *k* |
| gap in `seq` | records missing between *j* and *k* |
| seq 1 `prev_hash` ≠ 64 zeros | chain does not start at genesis |
| `ts` earlier than its predecessor's | warning, not a break |

`nodary audit verify --mirror PATH` verifies a JSONL file the same way, **with or without a
database present**, so a copy retrieved from a SIEM or cold storage can be checked months
later on a machine that has never seen the original. With both, it also reports the first
sequence at which they disagree; a file merely *behind* the database is reported as such
and is not an error, since post-commit delivery makes that ordinary.

Exit `1` on a break, `0` with warnings otherwise.
[11 §3](../specs/11-failure-modes.md#3-security-controls) is explicit that a broken chain
does not stop the server and is never repaired, so `verify` reports and nothing more.

### `list` and `export` — R1-10, R1-11

```
nodary audit list   [--from TS] [--to TS] [--actor ID] [--action A] [--limit N] [--format text|json]
nodary audit verify [--mirror PATH] [--format text|json]
nodary audit export [--from TS] [--to TS] [--from-seq N] --format jsonl|csv
```

`--from`/`--to` accept `2006-01-02` or a full RFC3339 instant and compare as strings against
the indexed `ts`. `--action` matches exactly, or as a prefix when it ends in `.`, so
`--action model.` selects the family. `--limit` defaults to 50, capped at 500, matching
[09 §2](../specs/09-api.md#2-conventions). `--from-seq` is what re-syncs a destination that
fell behind.

All three take `--db PATH`, defaulting to [08](../specs/08-data-model.md)'s location. It
should become a global flag when a second command group needs one; putting it there now
would be guessing at R1c's shape.

CSV is the eighteen columns of the row in schema order with a header and RFC 4180 quoting.
The columns being the table's columns is deliberate: an export a spreadsheet opens is worth
more than one that re-nests, and JSONL is there for anything that needs structure.

## Testing

| Package | Cases |
| :--- | :--- |
| `audit` record | A frozen golden record and its hash in `testdata`, so a change to the encoder or the field set fails here rather than in production; `members()` has exactly fourteen keys and the preimage thirteen; `v` and `install` are inside the preimage; every optional encodes as `null`, never absent and never `""` |
| `audit` chain | Genesis `prev_hash` is 64 zeros; N records verify; mutating record *k* of N makes verify name *k* — **for a mutation of each field in turn**; deleting a record is reported as a gap, not a break |
| `audit` concurrency | N **separate processes** each appending M records: `seq` is 1..N·M with no gaps or duplicates, every `prev_hash` is unique, and the whole chain verifies |
| `audit` sinks | `ParseSinks` round-trips every form and rejects unknown ones; a failing sink does not fail `Act` under `warn` and refuses the *next* `Act` under `block`, naming the sink; the file sink's line is byte-identical to the JSONL export; `verify --mirror` verifies a file with no database present; a record committed but undelivered is recovered by `--from-seq` |
| `audit` seam | `Act` records `success`, `failure` and `partial` with the error tail in `detail`; a failed mutation leaves no state change and still leaves a record; no package outside `store` and `audit` names `WriteTx` |
| `store` | `OpenReadOnly` refuses a missing file, a directory, a foreign or absent `application_id`, a schema behind the binary and a downgrade; the refusal does not migrate the database it refused; `Read().Exec`, `WriteTx` and `Migrate` are all refused; it opens while a writer holds the lock; and the DSN itself is tested, so removing `mode=rw` cannot hide behind the `os.Stat` |
| `cli` | `list` filters and orders descending; `verify` exits 1 naming the first bad sequence; `export --format text` is rejected naming `jsonl` and `csv`; a `stdout` sink plus a document-producing command is refused; `--format json` writes nothing to stdout but the document |

The chain test that mutates *each field in turn* is the one that matters most: it is the
only thing that catches a field being added to the record and not to the preimage, which
would leave that field unprotected while everything still verified.

## Steps

One commit per step, citing its task ID.

- [x] **1.** `store.OpenReadOnly` — read-only open that refuses rather than migrates
- [ ] **2.** `internal/audit` record, `members()`, preimage and hash, golden vector · **R1-05**, **R1-06**
- [ ] **3.** `0002_audit.sql`; `Append` assigning `seq` and `prev_hash` inside `WriteTx` · **R1-07**
- [ ] **4.** `sink.go`, file and console sinks, spec parser, failure posture · **R1-08**
- [ ] **5.** `log.go` — `Log`, `Request`, `Mutation`, `Act`, and the bypass test · **R1-12**
- [ ] **6.** `nodary audit verify`, standalone and against a file · **R1-09**
- [ ] **7.** `nodary audit list` · **R1-10**
- [ ] **8.** `nodary audit export --format jsonl|csv` · **R1-11**
- [ ] **9.** Correct [07 §3](../specs/07-identity-audit.md#3-the-audit-chain),
      [08 §1](../specs/08-data-model.md#1-schema) and
      [10 §2](../specs/10-cli.md#2-global-flags) (below)

## Open items

**[07 §3](../specs/07-identity-audit.md#3-the-audit-chain) lists twelve record fields.**
The record carries fourteen: `v` and `install`, both inside the hash preimage, so this is
the last moment either could be added. Corrected in step 9.

**[08 §1](../specs/08-data-model.md#1-schema) shows `audit` with composite columns.**
`actor`, `source` and `target` each hold more than one value. Flattened above; corrected in
step 9.

**[10 §2](../specs/10-cli.md#2-global-flags) presents `--format text|json|yaml` as global.**
`audit export` takes `jsonl|csv`. The flag table gains the exception.

**A network sink for Elastic, Splunk HEC or a generic NDJSON endpoint.** The `Sink` seam
makes it additive, and the case for it is real — CMMC deployments ship to a SIEM with WORM
retention, and the record already carries `seq` and `hash` so an at-least-once destination
can dedupe and detect gaps without trusting nodary. It is not in this slice because its
URL, credentials and TLS settings have nowhere to live until R1d, and its credentials want
[R1-04](../tasks/R1-core-audit-identity.md)'s sealing. Needs a task.

**Rotation of the file sink.** Rename-and-create is safe against this implementation and
`copytruncate` is not, so the choice cannot be left to whoever writes the packaging: either
a `logrotate` fragment in the correct mode ships with the package, or nodary rotates on
size itself. Not in this slice — R1b has no packaging work — but written down so it is
decided deliberately rather than by a distribution default.

**Retention will have to teach `verify` about a pruned prefix.**
[08 §3](../specs/08-data-model.md#3-retention) prunes `audit` past
`audit_retention_days`, which deletes the genesis record and leaves a chain whose first
record has a `prev_hash` naming something no longer present. As specified here that reads as
*chain does not start at genesis*. The prune writes a record naming the range removed, so
the information to distinguish the two exists; wiring it up belongs with retention.

**`yaml` appears in [10 §2](../specs/10-cli.md#2-global-flags) and nothing implements it.**
Out of scope; noted because `audit list --format yaml` is where an operator finds out.
