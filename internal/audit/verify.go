package audit

import (
	"bufio"
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"iter"
	"os"
	"time"

	"github.com/nodarynet/nodary/internal/canonical"
	"github.com/nodarynet/nodary/internal/store"
)

// Kind classifies what verification found.
type Kind string

const (
	// KindAltered: the record does not hash to the hash it carries. Some field
	// of it was changed after it was written.
	KindAltered Kind = "record altered"
	// KindBroken: the record does not chain to its predecessor.
	KindBroken Kind = "chain broken"
	// KindGap: sequence numbers skip. Records were deleted.
	KindGap Kind = "records missing"
	// KindOutOfOrder: a sequence number repeats or goes backwards. Two records
	// claim one position, or the source was concatenated out of order — not a
	// deletion, which is what makes it worth a name of its own.
	KindOutOfOrder Kind = "records out of order"
	// KindNotGenesis: the chain does not start at seq 1 with 64 zeros.
	KindNotGenesis Kind = "chain does not start at genesis"
	// KindMixedInstalls: the source holds records from more than one
	// installation, so it is an aggregate rather than one chain.
	KindMixedInstalls Kind = "records from more than one installation"
	// KindClockWentBack: a record is timestamped before its predecessor. A
	// warning, not a break: the cause is a clock, not tampering.
	KindClockWentBack Kind = "clock went backwards"
	// KindUnreadable: a line or row could not be read as a record at all.
	KindUnreadable Kind = "record unreadable"
)

// Problem is one thing verification found, named by sequence number.
type Problem struct {
	Seq    int64
	Kind   Kind
	Detail string
}

func (p Problem) String() string {
	if p.Detail == "" {
		return fmt.Sprintf("seq %d: %s", p.Seq, p.Kind)
	}
	return fmt.Sprintf("seq %d: %s — %s", p.Seq, p.Kind, p.Detail)
}

// Result is what a verification pass concluded.
type Result struct {
	Records  int64
	FirstSeq int64
	LastSeq  int64
	// Break is the first thing that means the chain cannot be trusted, or nil.
	// Verification stops there: everything after a break is unverifiable, and
	// listing consequences as if they were causes buries the one that matters.
	Break *Problem
	// Warnings are things worth saying that are not breaks.
	Warnings []Problem
}

// OK reports whether the chain verified.
func (r Result) OK() bool { return r.Break == nil }

// verify walks records in ascending sequence and stops at the first break.
func verify(records iter.Seq2[Record, error]) Result {
	var (
		res     Result
		prev    Record
		install string
		started bool
	)

	for r, err := range records {
		if err != nil {
			res.Break = &Problem{Seq: prev.Seq + 1, Kind: KindUnreadable, Detail: err.Error()}
			return res
		}

		switch {
		case !started:
			res.FirstSeq, install, started = r.Seq, r.Install, true
			if r.Seq != 1 || r.PrevHash != GenesisPrevHash {
				res.Break = &Problem{Seq: r.Seq, Kind: KindNotGenesis, Detail: fmt.Sprintf(
					"the first record is seq %d with prev_hash %s", r.Seq, r.PrevHash)}
				return res
			}
		case r.Install != install:
			res.Break = &Problem{Seq: r.Seq, Kind: KindMixedInstalls, Detail: fmt.Sprintf(
				"%s appears after %s", r.Install, install)}
			return res
		case r.Seq <= prev.Seq:
			res.Break = &Problem{Seq: r.Seq, Kind: KindOutOfOrder, Detail: fmt.Sprintf(
				"seq %d is followed by seq %d", prev.Seq, r.Seq)}
			return res
		case r.Seq != prev.Seq+1:
			res.Break = &Problem{Seq: prev.Seq + 1, Kind: KindGap, Detail: fmt.Sprintf(
				"seq %d is followed by seq %d", prev.Seq, r.Seq)}
			return res
		case r.PrevHash != prev.Hash:
			res.Break = &Problem{Seq: r.Seq, Kind: KindBroken, Detail: fmt.Sprintf(
				"it chains to %s but seq %d hashes to %s", r.PrevHash, prev.Seq, prev.Hash)}
			return res
		}

		computed, err := r.Compute()
		switch {
		case err != nil:
			res.Break = &Problem{Seq: r.Seq, Kind: KindUnreadable, Detail: err.Error()}
			return res
		case computed != r.Hash:
			res.Break = &Problem{Seq: r.Seq, Kind: KindAltered, Detail: fmt.Sprintf(
				"it carries %s and hashes to %s", r.Hash, computed)}
			return res
		}

		// A clock that moved backwards is reported and stepped over. An audit
		// record that reports a time the machine was not at would be a worse
		// defect than one that reports the truth about a machine whose clock
		// moved, so nothing here clamps it.
		if res.Records > 0 && r.TS.Before(prev.TS) {
			res.Warnings = append(res.Warnings, Problem{Seq: r.Seq, Kind: KindClockWentBack,
				Detail: fmt.Sprintf("%s precedes seq %d at %s",
					r.TS.Format(TimeFormat), prev.Seq, prev.TS.Format(TimeFormat))})
		}

		res.Records++
		res.LastSeq = r.Seq
		prev = r
	}
	return res
}

// VerifyDB walks the chain in the database.
func VerifyDB(ctx context.Context, db *store.DB) (Result, error) {
	rows, err := db.Read().QueryContext(ctx, `SELECT `+columns+` FROM audit ORDER BY seq`)
	if err != nil {
		return Result{}, fmt.Errorf("reading the chain: %w", err)
	}
	defer rows.Close()

	res := verify(func(yield func(Record, error) bool) {
		for rows.Next() {
			if !yield(scanRecord(rows)) {
				return
			}
		}
		if err := rows.Err(); err != nil {
			yield(Record{}, err)
		}
	})
	if res.Break == nil && res.Records == 0 {
		if err := emptyChainIsGenuine(ctx, db, &res); err != nil {
			return Result{}, err
		}
	}
	return res, nil
}

// emptyChainIsGenuine tells a chain that never held a record from one that was
// emptied.
//
// The installation row is minted by the first record's own transaction, so its
// presence proves records existed. Without this, `DELETE FROM audit` verified
// as a sound empty chain and exited 0 — so the cheapest move available to
// anyone holding the file was the one move the verifier could not name, while
// deleting any *prefix* of the chain was caught as KindNotGenesis. The
// schema's UNIQUE(prev_hash) stops being a second-genesis guard for the same
// reason once the genesis row is gone.
func emptyChainIsGenuine(ctx context.Context, db *store.DB, res *Result) error {
	var minted string
	err := db.Read().QueryRowContext(ctx,
		`SELECT created_at FROM installation WHERE singleton = 1`).Scan(&minted)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return nil
	case err != nil:
		return fmt.Errorf("reading the installation record: %w", err)
	}
	res.Break = &Problem{Seq: 1, Kind: KindGap, Detail: fmt.Sprintf(
		"the chain is empty, but this installation was recorded at %s, which only the first record does: every record has been deleted",
		minted)}
	return nil
}

// VerifyFile walks a JSONL file — a sink's output, or a copy retrieved from a
// SIEM or cold storage months later on a machine that has never seen the
// database it came from. That is what makes the off-box copy evidence rather
// than a backup.
func VerifyFile(path string) (Result, error) {
	records, close, err := fileRecords(path)
	if err != nil {
		return Result{}, err
	}
	defer close()
	return verify(records), nil
}

// maxLineBytes bounds one mirror line. A record with a long detail can exceed
// bufio's default 64 KiB, and maxDetailValue bounds the write path so a record
// this package produced cannot reach this cap.
const maxLineBytes = 8 * 1024 * 1024

// fileRecords reads a JSONL mirror as a sequence of records.
//
// One reader, because VerifyFile and Compare both need it and the two hand-
// rolled copies had already drifted: only VerifyFile named the file and the
// line number in a parse error, so a damaged mirror reported through Compare
// said "not a JSON object: unexpected EOF" about nothing in particular. The
// buffer size is load-bearing rather than incidental, and raising it in one
// copy would have made one command give two verdicts about one file.
func fileRecords(path string) (iter.Seq2[Record, error], func(), error) {
	fh, err := os.Open(path)
	if err != nil {
		return nil, nil, fmt.Errorf("opening %s: %w", path, err)
	}
	sc := bufio.NewScanner(fh)
	sc.Buffer(make([]byte, 0, 64*1024), maxLineBytes)

	return func(yield func(Record, error) bool) {
		line := 0
		for sc.Scan() {
			line++
			raw := bytes.TrimSpace(sc.Bytes())
			if len(raw) == 0 {
				continue
			}
			r, err := ParseLine(raw)
			if err != nil {
				err = fmt.Errorf("%s line %d: %w", path, line, err)
			}
			if !yield(r, err) {
				return
			}
		}
		if err := sc.Err(); err != nil {
			yield(Record{}, fmt.Errorf("reading %s: %w", path, err))
		}
	}, func() { fh.Close() }, nil
}

// ParseLine reads one canonical JSON record.
//
// It is self-checking: after building the Record it re-encodes it and requires
// the bytes to match the input. A field this parser forgot would otherwise
// travel unverified — the record would hash without it and still appear sound.
// This makes forgetting one a parse error instead, which is why the field names
// can appear here as well as in members without the two being able to drift.
func ParseLine(line []byte) (Record, error) {
	var raw map[string]any
	dec := json.NewDecoder(bytes.NewReader(line))
	dec.UseNumber()
	if err := dec.Decode(&raw); err != nil {
		return Record{}, fmt.Errorf("not a JSON object: %w", err)
	}

	var r Record
	var err error
	if r.V, err = intField(raw, "v"); err != nil {
		return Record{}, err
	}
	if r.Seq, err = int64Field(raw, "seq"); err != nil {
		return Record{}, err
	}
	if r.Install, err = stringField(raw, "install", true); err != nil {
		return Record{}, err
	}
	ts, err := stringField(raw, "ts", true)
	if err != nil {
		return Record{}, err
	}
	if r.TS, err = time.Parse(TimeFormat, ts); err != nil {
		return Record{}, fmt.Errorf("field \"ts\" is %q: %w", ts, err)
	}
	if r.Action, err = stringField(raw, "action", true); err != nil {
		return Record{}, err
	}
	outcome, err := stringField(raw, "outcome", true)
	if err != nil {
		return Record{}, err
	}
	r.Outcome = Outcome(outcome)
	if r.PrevHash, err = stringField(raw, "prev_hash", true); err != nil {
		return Record{}, err
	}
	if r.Hash, err = stringField(raw, "hash", true); err != nil {
		return Record{}, err
	}
	if r.IntentHash, err = stringField(raw, "intent_hash", false); err != nil {
		return Record{}, err
	}
	if r.Justification, err = stringField(raw, "justification", false); err != nil {
		return Record{}, err
	}

	actor, err := objectField(raw, "actor", true)
	if err != nil {
		return Record{}, err
	}
	if r.Actor.ID, err = stringField(actor, "id", false); err != nil {
		return Record{}, err
	}
	if r.Actor.Method, err = stringField(actor, "method", false); err != nil {
		return Record{}, err
	}
	if r.Actor.Session, err = stringField(actor, "session", false); err != nil {
		return Record{}, err
	}

	source, err := objectField(raw, "source", true)
	if err != nil {
		return Record{}, err
	}
	if r.Source.IP, err = stringField(source, "ip", false); err != nil {
		return Record{}, err
	}
	if r.Source.Version, err = stringField(source, "version", false); err != nil {
		return Record{}, err
	}

	target, err := objectField(raw, "target", false)
	if err != nil {
		return Record{}, err
	}
	if target != nil {
		var t Target
		if t.Kind, err = stringField(target, "kind", false); err != nil {
			return Record{}, err
		}
		if t.ID, err = stringField(target, "id", false); err != nil {
			return Record{}, err
		}
		r.Target = &t
	}

	detail, err := objectField(raw, "detail", true)
	if err != nil {
		return Record{}, err
	}
	r.Detail = detail

	// The self-check. Anything this parser dropped, misread or invented shows
	// up as a difference here.
	want, err := canonical.EncodeJSON(line)
	if err != nil {
		return Record{}, fmt.Errorf("record %d is not canonical JSON: %w", r.Seq, err)
	}
	got, err := r.Line()
	if err != nil {
		return Record{}, err
	}
	if !bytes.Equal(got, want) {
		return Record{}, fmt.Errorf(
			"record %d does not round-trip; the line holds something this version does not read\n  read: %s\n  line: %s",
			r.Seq, got, want)
	}

	// Held to the same shape the table holds a row to. The round-trip check
	// above proves the line was read faithfully, not that what it says is
	// well formed — so a mirror line with outcome "redacted", v 0, no actor
	// method or a half-set target parsed cleanly and `verify --mirror` called
	// it verified, about a record the database's CHECK constraints could never
	// have held. The mirror is the copy that outlives the database, so
	// "verified" has to mean at least as much there.
	if err := r.Validate(); err != nil {
		return Record{}, err
	}
	return r, nil
}

func stringField(m map[string]any, key string, required bool) (string, error) {
	v, present := m[key]
	if !present {
		return "", fmt.Errorf("field %q is absent", key)
	}
	if v == nil {
		if required {
			return "", fmt.Errorf("field %q is null", key)
		}
		return "", nil
	}
	s, ok := v.(string)
	if !ok {
		return "", fmt.Errorf("field %q is %T, want a string", key, v)
	}
	return s, nil
}

func objectField(m map[string]any, key string, required bool) (map[string]any, error) {
	v, present := m[key]
	if !present {
		return nil, fmt.Errorf("field %q is absent", key)
	}
	if v == nil {
		if required {
			return nil, fmt.Errorf("field %q is null", key)
		}
		return nil, nil
	}
	o, ok := v.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("field %q is %T, want an object", key, v)
	}
	return o, nil
}

func intField(m map[string]any, key string) (int, error) {
	n, err := int64Field(m, key)
	return int(n), err
}

func int64Field(m map[string]any, key string) (int64, error) {
	v, present := m[key]
	if !present {
		return 0, fmt.Errorf("field %q is absent", key)
	}
	num, ok := v.(json.Number)
	if !ok {
		return 0, fmt.Errorf("field %q is %T, want a number", key, v)
	}
	n, err := num.Int64()
	if err != nil {
		return 0, fmt.Errorf("field %q is %s, want an integer", key, num)
	}
	return n, nil
}

// Compare reports how a file's chain relates to the database's.
type Comparison struct {
	// Installs is set when the file and the database name different
	// installations, and it makes every other field here meaningless: the two
	// are not one chain, so a differing hash at seq 1 is not divergence. Every
	// chain starts at seq 1 with the same genesis prev_hash, which is why the
	// records carry an install id at all — and why matching them by sequence
	// alone reported a reinstall, a restore or a mirror from another appliance
	// as tampering.
	Installs *InstallMismatch
	// Diverged is the first sequence at which both hold a record and the two
	// disagree, or 0.
	Diverged int64
	// Behind is how many records the database holds that the file does not.
	// Ordinary rather than wrong: delivery happens after the commit.
	Behind int64
	// Ahead is how many the file holds that the database does not, which is
	// not ordinary — it means the two are not a pair.
	Ahead int64
}

// InstallMismatch names the two installations a comparison found.
type InstallMismatch struct {
	Database string
	File     string
}

func (m InstallMismatch) String() string {
	return fmt.Sprintf("the database holds %s and the file holds %s", m.Database, m.File)
}

// Compare walks both chains by sequence.
func Compare(ctx context.Context, db *store.DB, path string) (Comparison, error) {
	stored := map[int64]string{}
	var dbInstall string
	rows, err := db.Read().QueryContext(ctx, `SELECT seq, hash, install FROM audit ORDER BY seq`)
	if err != nil {
		return Comparison{}, fmt.Errorf("reading the chain: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var seq int64
		var hash, install string
		if err := rows.Scan(&seq, &hash, &install); err != nil {
			return Comparison{}, err
		}
		stored[seq] = hash
		dbInstall = install
	}
	if err := rows.Err(); err != nil {
		return Comparison{}, err
	}

	records, close, err := fileRecords(path)
	if err != nil {
		return Comparison{}, err
	}
	defer close()

	var cmp Comparison
	seen := map[int64]bool{}
	for r, err := range records {
		if err != nil {
			return Comparison{}, err
		}
		if dbInstall != "" && r.Install != dbInstall {
			// Not a pair at all. Reporting the seq-1 hashes as divergence here
			// would say "tampered" about an ordinary reinstall or a mirror
			// pulled from another appliance, and the wording and exit code were
			// indistinguishable from the real thing.
			return Comparison{Installs: &InstallMismatch{Database: dbInstall, File: r.Install}}, nil
		}
		seen[r.Seq] = true
		switch hash, ok := stored[r.Seq]; {
		case !ok:
			cmp.Ahead++
		case hash != r.Hash && (cmp.Diverged == 0 || r.Seq < cmp.Diverged):
			cmp.Diverged = r.Seq
		}
	}
	for seq := range stored {
		if !seen[seq] {
			cmp.Behind++
		}
	}
	return cmp, nil
}
