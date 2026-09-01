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
	// KindNotAnchored: a fragment does not join the record the caller said it
	// should follow.
	KindNotAnchored Kind = "fragment does not join its anchor"
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
	// Fragment reports that the source does not begin at genesis: its records
	// verify among themselves, and nothing in them proves the records before
	// them ever existed.
	//
	// This is an ordinary state, not a defect. `audit export --from-seq` and a
	// rotated sink file are both fragments by design, and a verifier that
	// called its own documented recovery artefacts tampered would be worse than
	// useless.
	Fragment bool
	// Anchored reports that a fragment was checked against a caller-supplied
	// predecessor and joins it. A fragment that is anchored proves as much as a
	// whole chain from the anchor onwards.
	Anchored bool
	// FirstPrevHash is what the first record claims to follow. For a fragment
	// it is the only handle on where the fragment belongs, which is what lets a
	// caller anchor it after the fact instead of reading the source twice.
	FirstPrevHash string
}

// OK reports whether the chain verified.
func (r Result) OK() bool { return r.Break == nil }

// verify walks records in ascending sequence and stops at the first break.
// Anchor names the record immediately before a source's first one.
//
// It is what turns "these records are consistent with each other" into "these
// records continue the chain I already know", which is the whole difference
// between a fragment and evidence.
type Anchor struct {
	Seq  int64
	Hash string
}

// reorderWindow bounds how far out of sequence a record may arrive before
// verification calls it missing.
//
// Delivery happens after the commit and several processes append to one path,
// so a concurrently written file interleaves. Measured: twelve processes
// writing 480 records produced an inversion in one run of six, and reading the
// file in file order then reported "records missing — seq 165 is followed by
// seq 167" while Compare proved every record present and byte-exact. That is
// the worst false positive a tamper detector can have, so verification
// reconstructs the chain by sequence and holds early arrivals until their
// predecessor turns up.
//
// The bound is what stops that from meaning "read the whole file into memory".
// Reordering is limited in practice by how many writers can be in flight at
// once; a thousand records is far past that.
const reorderWindow = 1024

// verifyOpts says what the source is expected to be.
type verifyOpts struct {
	// requireGenesis rejects a source that does not begin at seq 1. A database
	// holds the whole chain, so a partial one there means records were deleted.
	requireGenesis bool
	// anchor is the record the first one must follow. Nil means a fragment is
	// accepted and reported as one.
	anchor *Anchor
}

func verify(records iter.Seq2[Record, error], opts verifyOpts) Result {
	var (
		res     Result
		prev    Record
		install string
		started bool
		next    int64
		// sourceErr is held rather than raised. Read-ahead means an unreadable
		// line is met before the records in front of it have been checked, and
		// a truncated final append is the ordinary way a copy pulled from a
		// SIEM is damaged — so stop reading, verify everything that did arrive,
		// and report the damage at the sequence the source failed to supply.
		sourceErr error
	)
	pull, stop := iter.Pull2(records)
	defer stop()

	pending := make(map[int64]Record, reorderWindow)

	// fill reads until pending holds n records or the source is exhausted. It
	// returns false once a problem has been recorded.
	fill := func(n int) bool {
		for len(pending) < n {
			r, err, ok := pull()
			if !ok {
				return true
			}
			if err != nil {
				sourceErr = err
				return true
			}
			// Delivery is at-least-once, so the same record arriving twice is
			// ordinary. Two *different* records claiming one sequence is not.
			if held, dup := pending[r.Seq]; dup {
				// Two appliances' files concatenated collide at seq 1, and
				// naming that is far more use than "two records claim seq 1".
				if held.Install != r.Install {
					res.Break = &Problem{Seq: r.Seq, Kind: KindMixedInstalls, Detail: fmt.Sprintf(
						"%s and %s both claim seq %d", held.Install, r.Install, r.Seq)}
					return false
				}
				same, problem := sameRecord(held, r)
				if problem != nil {
					res.Break = problem
					return false
				}
				if same {
					continue
				}
				res.Break = &Problem{Seq: r.Seq, Kind: KindOutOfOrder, Detail: fmt.Sprintf(
					"two records claim seq %d: %s and %s", r.Seq, held.Hash, r.Hash)}
				return false
			}
			if started && r.Seq < next {
				if r.Seq == prev.Seq {
					same, problem := sameRecord(prev, r)
					if problem != nil {
						res.Break = problem
						return false
					}
					if same {
						continue // the same record again, just late
					}
				}
				res.Break = &Problem{Seq: r.Seq, Kind: KindOutOfOrder, Detail: fmt.Sprintf(
					"seq %d arrived after seq %d, further back than %d records",
					r.Seq, prev.Seq, reorderWindow)}
				return false
			}
			pending[r.Seq] = r
		}
		return true
	}

	if !fill(reorderWindow) {
		return res
	}
	if len(pending) == 0 {
		if sourceErr != nil {
			res.Break = &Problem{Seq: 1, Kind: KindUnreadable, Detail: sourceErr.Error()}
		}
		return res // an empty source; the caller decides what that means
	}

	// The lowest sequence in the window is the start: a file written by
	// concurrent processes need not begin with its own first record.
	start := int64(0)
	for seq := range pending {
		if start == 0 || seq < start {
			start = seq
		}
	}
	first := pending[start]

	switch {
	case opts.anchor != nil:
		if first.Seq != opts.anchor.Seq+1 || first.PrevHash != opts.anchor.Hash {
			res.Break = &Problem{Seq: first.Seq, Kind: KindNotAnchored, Detail: fmt.Sprintf(
				"it starts at seq %d after %s, and the anchor is seq %d with hash %s",
				first.Seq, first.PrevHash, opts.anchor.Seq, opts.anchor.Hash)}
			return res
		}
		res.Anchored = true
		res.Fragment = first.Seq != 1
	case first.Seq == 1 || opts.requireGenesis:
		// A source claiming to start at the beginning must actually do so, and
		// a forged genesis is a break rather than a fragment.
		if first.Seq != 1 || first.PrevHash != GenesisPrevHash {
			res.Break = &Problem{Seq: first.Seq, Kind: KindNotGenesis, Detail: fmt.Sprintf(
				"the first record is seq %d with prev_hash %s", first.Seq, first.PrevHash)}
			return res
		}
	default:
		res.Fragment = true
	}

	next = start
	res.FirstSeq = start
	res.FirstPrevHash = first.PrevHash

	for {
		r, ok := pending[next]
		if !ok {
			switch {
			case sourceErr != nil:
				res.Break = &Problem{Seq: next, Kind: KindUnreadable, Detail: sourceErr.Error()}
			case len(pending) > 0:
				res.Break = &Problem{Seq: next, Kind: KindGap, Detail: fmt.Sprintf(
					"seq %d is followed by seq %d", prev.Seq, lowest(pending))}
			}
			return res // every record accounted for, or the first thing missing
		}
		delete(pending, next)

		if started {
			switch {
			case r.Install != install:
				res.Break = &Problem{Seq: r.Seq, Kind: KindMixedInstalls, Detail: fmt.Sprintf(
					"%s appears after %s", r.Install, install)}
				return res
			case r.PrevHash != prev.Hash:
				res.Break = &Problem{Seq: r.Seq, Kind: KindBroken, Detail: fmt.Sprintf(
					"it chains to %s but seq %d hashes to %s", r.PrevHash, prev.Seq, prev.Hash)}
				return res
			}
		} else {
			install, started = r.Install, true
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
		next++

		if !fill(reorderWindow) {
			return res
		}
	}
}

// sameRecord reports whether b is a redelivery of a rather than a second
// record claiming a's sequence.
//
// Comparing the two carried hashes is not enough, and that gap was real: a line
// that keeps a genuine record's seq and hash while changing a field is accepted
// as a repeat and silently dropped, so verification passes over a forgery
// without naming it. Delivery is at-least-once, and a redelivery is the same
// bytes — so it hashes to the hash it carries, exactly as the original did. A
// line that does not is a forgery whatever it claims.
func sameRecord(a, b Record) (bool, *Problem) {
	computed, err := b.Compute()
	switch {
	case err != nil:
		return false, &Problem{Seq: b.Seq, Kind: KindUnreadable, Detail: err.Error()}
	case computed != b.Hash:
		return false, &Problem{Seq: b.Seq, Kind: KindAltered, Detail: fmt.Sprintf(
			"a second line claims seq %d, carries %s and hashes to %s",
			b.Seq, b.Hash, computed)}
	}
	return a.Hash == b.Hash, nil
}

// lowest is the smallest sequence still held, for naming what a gap runs to.
func lowest(pending map[int64]Record) int64 {
	var out int64
	for seq := range pending {
		if out == 0 || seq < out {
			out = seq
		}
	}
	return out
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
	}, verifyOpts{requireGenesis: true})
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
// VerifyMirror verifies a JSONL file and, when it turns out to be a fragment,
// anchors it to the database that should hold its predecessor.
//
// This is the ordinary case: a rotated sink file or an `export --from-seq`
// catch-up file is a fragment, and the appliance it came from can say whether
// it joins. An auditor with no database uses VerifyFile with an anchor they
// supply, or accepts the weaker claim a bare fragment makes.
func VerifyMirror(ctx context.Context, db *store.DB, path string) (Result, error) {
	res, err := VerifyFile(path, nil)
	if err != nil || db == nil || res.Break != nil || !res.Fragment {
		return res, err
	}
	hash, ok, err := hashAt(ctx, db, res.FirstSeq-1)
	switch {
	case err != nil:
		return res, err
	case !ok:
		// The database does not hold the predecessor either, so there is
		// nothing here to anchor against. The fragment stands on its own.
		return res, nil
	case hash != res.FirstPrevHash:
		res.Break = &Problem{Seq: res.FirstSeq, Kind: KindNotAnchored, Detail: fmt.Sprintf(
			"it follows %s, and seq %d in the database hashes to %s",
			res.FirstPrevHash, res.FirstSeq-1, hash)}
		return res, nil
	}
	res.Anchored = true
	return res, nil
}

// hashAt reads one record's hash.
func hashAt(ctx context.Context, db *store.DB, seq int64) (string, bool, error) {
	if seq < 1 {
		return "", false, nil
	}
	var hash string
	err := db.Read().QueryRowContext(ctx, `SELECT hash FROM audit WHERE seq = ?`, seq).Scan(&hash)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return "", false, nil
	case err != nil:
		return "", false, fmt.Errorf("reading seq %d: %w", seq, err)
	}
	return hash, true, nil
}

// A file may be a fragment. `audit export --from-seq` and a rotated sink file
// both are, by design, so a fragment is reported as one rather than refused.
// Pass an anchor to check that it joins the chain you already know; without
// one, the records are proved consistent with each other and nothing more.
func VerifyFile(path string, anchor *Anchor) (Result, error) {
	records, close, err := fileRecords(path)
	if err != nil {
		return Result{}, err
	}
	defer close()
	return verify(records, verifyOpts{anchor: anchor}), nil
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
	rows, err := db.Read().QueryContext(ctx, `SELECT seq, hash, install FROM audit ORDER BY seq`)
	if err != nil {
		return Comparison{}, fmt.Errorf("reading the chain: %w", err)
	}
	defer rows.Close()

	records, closeFile, err := fileRecords(path)
	if err != nil {
		return Comparison{}, err
	}
	defer closeFile()

	// Both sides are walked in sequence order and neither is held in memory.
	// The earlier version built a map of every seq to every hash and a second
	// set of every seq seen, so comparing a chain cost memory proportional to
	// the whole chain — in a tool whose whole job is to be usable against
	// evidence of any size, on a machine that is not necessarily the one that
	// produced it.
	file, stopFile := iter.Pull2(bySequence(records, reorderWindow))
	defer stopFile()

	var (
		cmp       Comparison
		dbInstall string
		fileSeq   int64
		fileHash  string
		haveFile  bool
		lastFile  int64
	)

	nextFile := func() error {
		for {
			r, err, ok := file()
			if err != nil {
				return err
			}
			if !ok {
				haveFile = false
				return nil
			}
			if dbInstall != "" && r.Install != dbInstall {
				// Not a pair at all. Reporting the hashes as divergence would
				// say "tampered" about an ordinary reinstall or a mirror pulled
				// from another appliance, in the same words and with the same
				// exit code as the real thing.
				return &installMismatch{db: dbInstall, file: r.Install}
			}
			if r.Seq <= lastFile {
				continue // a repeat; bySequence already dropped the identical ones
			}
			fileSeq, fileHash, haveFile, lastFile = r.Seq, r.Hash, true, r.Seq
			return nil
		}
	}

	var (
		dbSeq  int64
		dbHash string
		haveDB bool
	)
	nextDB := func() error {
		if !rows.Next() {
			haveDB = false
			return rows.Err()
		}
		var install string
		if err := rows.Scan(&dbSeq, &dbHash, &install); err != nil {
			return err
		}
		dbInstall, haveDB = install, true
		return nil
	}

	if err := nextDB(); err != nil {
		return Comparison{}, err
	}
	if err := nextFile(); err != nil {
		return mismatchOrError(err)
	}

	for haveDB && haveFile {
		switch {
		case dbSeq < fileSeq:
			cmp.Behind++
			if err := nextDB(); err != nil {
				return Comparison{}, err
			}
		case dbSeq > fileSeq:
			cmp.Ahead++
			if err := nextFile(); err != nil {
				return mismatchOrError(err)
			}
		default:
			if dbHash != fileHash && cmp.Diverged == 0 {
				cmp.Diverged = dbSeq
			}
			if err := nextDB(); err != nil {
				return Comparison{}, err
			}
			if err := nextFile(); err != nil {
				return mismatchOrError(err)
			}
		}
	}
	for haveDB {
		cmp.Behind++
		if err := nextDB(); err != nil {
			return Comparison{}, err
		}
	}
	for haveFile {
		cmp.Ahead++
		if err := nextFile(); err != nil {
			return mismatchOrError(err)
		}
	}
	return cmp, nil
}

// installMismatch is carried as an error so it can unwind the merge, and is
// turned back into an outcome rather than a failure at the boundary.
type installMismatch struct{ db, file string }

func (m *installMismatch) Error() string {
	return fmt.Sprintf("the file was written by %s and the database is %s", m.file, m.db)
}

func mismatchOrError(err error) (Comparison, error) {
	var m *installMismatch
	if errors.As(err, &m) {
		return Comparison{Installs: &InstallMismatch{Database: m.db, File: m.file}}, nil
	}
	return Comparison{}, err
}

// bySequence yields records in ascending sequence, absorbing with a bounded
// buffer the local disorder that concurrent delivery produces. Identical
// repeats — at-least-once delivery — are dropped.
func bySequence(records iter.Seq2[Record, error], window int) iter.Seq2[Record, error] {
	return func(yield func(Record, error) bool) {
		pull, stop := iter.Pull2(records)
		defer stop()

		pending := make(map[int64]Record, window)
		for {
			for len(pending) < window {
				r, err, ok := pull()
				if err != nil {
					yield(Record{}, err)
					return
				}
				if !ok {
					break
				}
				if held, dup := pending[r.Seq]; dup && held.Hash == r.Hash {
					continue
				}
				pending[r.Seq] = r
			}
			if len(pending) == 0 {
				return
			}
			next := lowest(pending)
			r := pending[next]
			delete(pending, next)
			if !yield(r, nil) {
				return
			}
		}
	}
}

// Assessment is the whole outcome of a verification run: the authoritative
// chain, an optional file, and how the two relate.
//
// It lives here rather than in the CLI because it is the answer, not the
// rendering of one. docs/tasks/README.md requires the CLI and the HTTP API to
// call the same core functions and neither to hold business logic, and "did
// this verify" is exactly the judgement GET /audit/verify has to reach by the
// same route `nodary audit verify` does. Either may be nil: verifying only a
// file, or only a database, is an ordinary thing to ask for.
type Assessment struct {
	Chain      *Result
	Mirror     *Result
	Comparison *Comparison
}

// OK reports whether everything examined verified and the two sources agree.
//
// A mirror that is merely *behind* is not a failure — delivery happens after
// the commit, so trailing the database is its ordinary state. A mirror that is
// *ahead*, that diverges, or that names another installation is: in each case
// the two are not the pair they are being treated as.
func (a Assessment) OK() bool {
	for _, r := range []*Result{a.Chain, a.Mirror} {
		if r != nil && !r.OK() {
			return false
		}
	}
	if c := a.Comparison; c != nil && (c.Installs != nil || c.Diverged != 0 || c.Ahead != 0) {
		return false
	}
	return true
}

// Comparable reports whether comparing the two sources says anything.
//
// It does not once either has failed to verify: "the mirror matches the
// database" printed underneath "record altered at seq 3" reads as a
// contradiction, and is one — what matched was the hash each side recorded at
// that sequence, not the record the mirror actually holds.
func (a Assessment) Comparable() bool {
	return a.Chain != nil && a.Chain.OK() && a.Mirror != nil && a.Mirror.OK()
}
