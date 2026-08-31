package audit

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nodarynet/nodary/internal/canonical"
	"github.com/nodarynet/nodary/internal/store"
)

func openDB(t *testing.T) *store.DB {
	t.Helper()
	return openAt(t, filepath.Join(t.TempDir(), "nodary.db"))
}

func openAt(t *testing.T, path string) *store.DB {
	t.Helper()
	db, err := store.Open(context.Background(), path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := db.Migrate(context.Background()); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

// entry is a valid minimum: the fields a caller must supply.
func entry(action string) Entry {
	return Entry{
		TS:      time.Date(2026, 8, 31, 9, 14, 2, 371_000_000, time.UTC),
		Actor:   Actor{ID: "root", Method: "local"},
		Source:  Source{Version: "0.0.1-rc1"},
		Action:  action,
		Outcome: OutcomeSuccess,
	}
}

func TestFirstRecordIsGenesis(t *testing.T) {
	db := openDB(t)
	r, err := Append(context.Background(), db, entry("model.enable"))
	if err != nil {
		t.Fatal(err)
	}
	if r.Seq != 1 {
		t.Errorf("seq = %d, want 1", r.Seq)
	}
	if r.PrevHash != GenesisPrevHash {
		t.Errorf("prev_hash = %q, want 64 zeros", r.PrevHash)
	}
	if r.V != Version {
		t.Errorf("v = %d, want %d", r.V, Version)
	}
	if !strings.HasPrefix(r.Install, "ins_") {
		t.Errorf("install = %q, want an ins_ identifier", r.Install)
	}
	want, err := r.Compute()
	if err != nil {
		t.Fatal(err)
	}
	if r.Hash != want {
		t.Errorf("hash = %s, want %s", r.Hash, want)
	}
}

func TestRecordsChainAndSequence(t *testing.T) {
	db := openDB(t)
	ctx := context.Background()

	const n = 25
	var written []Record
	for i := range n {
		r, err := Append(ctx, db, entry(fmt.Sprintf("model.enable.%d", i)))
		if err != nil {
			t.Fatal(err)
		}
		written = append(written, r)
	}

	for i, r := range written {
		if want := int64(i + 1); r.Seq != want {
			t.Errorf("record %d has seq %d, want %d", i, r.Seq, want)
		}
		want := GenesisPrevHash
		if i > 0 {
			want = written[i-1].Hash
		}
		if r.PrevHash != want {
			t.Errorf("record %d prev_hash = %s, want %s", r.Seq, r.PrevHash, want)
		}
	}
}

// The installation identifier is minted once and then reused, so records from
// one appliance carry one identity.
func TestInstallIDIsMintedOnceAndReused(t *testing.T) {
	db := openDB(t)
	ctx := context.Background()

	first, err := Append(ctx, db, entry("a"))
	if err != nil {
		t.Fatal(err)
	}
	second, err := Append(ctx, db, entry("b"))
	if err != nil {
		t.Fatal(err)
	}
	if first.Install != second.Install {
		t.Errorf("install changed between records: %s then %s", first.Install, second.Install)
	}

	var rows int
	if err := db.Read().QueryRow(`SELECT count(*) FROM installation`).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if rows != 1 {
		t.Errorf("installation has %d rows, want 1", rows)
	}
}

// The row must reproduce the record exactly. A field that does not survive the
// round trip re-hashes differently and reports tampering that never happened.
func TestRowRoundTripsLosslessly(t *testing.T) {
	db := openDB(t)
	ctx := context.Background()

	full := entry("model.enable")
	full.Target = &Target{Kind: "model", ID: "mdl_llama3"}
	full.IntentHash = strings.Repeat("a1", 32)
	full.Justification = "enabling chat for the pilot group"
	full.Actor.Session = "ses_4b1"
	full.Source.IP = "10.0.0.7"
	full.Detail = map[string]any{"gpus": []any{0, 1}, "restarted": true, "ratio": 0.92}

	sparse := Entry{
		TS:      full.TS.Add(time.Second),
		Actor:   Actor{Method: "system"},
		Action:  "audit.prune",
		Outcome: OutcomePartial,
	}

	for _, e := range []Entry{full, sparse} {
		want, err := Append(ctx, db, e)
		if err != nil {
			t.Fatalf("Append(%s): %v", e.Action, err)
		}

		row := db.Read().QueryRow(`SELECT `+columns+` FROM audit WHERE seq = ?`, want.Seq)
		got, err := scanRecord(row)
		if err != nil {
			t.Fatalf("scanRecord(%s): %v", e.Action, err)
		}

		recomputed, err := got.Compute()
		if err != nil {
			t.Fatal(err)
		}
		if recomputed != want.Hash {
			t.Errorf("%s: the stored row re-hashes to %s, want %s", e.Action, recomputed, want.Hash)
		}
		if got.Hash != want.Hash {
			t.Errorf("%s: stored hash %s, want %s", e.Action, got.Hash, want.Hash)
		}
		if (got.Target == nil) != (want.Target == nil) {
			t.Errorf("%s: target survived as %v, want %v", e.Action, got.Target, want.Target)
		}
		if !got.TS.Equal(want.TS) {
			t.Errorf("%s: ts survived as %v, want %v", e.Action, got.TS, want.TS)
		}
	}
}

// A detail value that no double holds exactly cannot have been written by this
// package — canonical refuses it — so finding one means the column was edited
// underneath us. It must be refused by name rather than silently rounded into a
// different number whose only symptom is a hash that does not match.
func TestTamperedDetailIsRefusedRatherThanRounded(t *testing.T) {
	db := openDB(t)
	ctx := context.Background()
	r, err := Append(ctx, db, entry("model.enable"))
	if err != nil {
		t.Fatal(err)
	}

	if err := db.WriteTx(ctx, func(tx *sql.Tx) error {
		_, err := tx.Exec(`UPDATE audit SET detail_json = ? WHERE seq = ?`,
			`{"n":9007199254740993}`, r.Seq)
		return err
	}); err != nil {
		t.Fatal(err)
	}

	row := db.Read().QueryRow(`SELECT `+columns+` FROM audit WHERE seq = ?`, r.Seq)
	got, err := scanRecord(row)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := got.Compute(); !errors.Is(err, canonical.ErrIntegerTooLarge) {
		t.Errorf("Compute() error = %v, want ErrIntegerTooLarge", err)
	}
}

// UNIQUE(prev_hash) is the schema's own refusal of a chain fork: it holds even
// against a writer that never goes through Append.
func TestSchemaRefusesTwoRecordsWithOnePredecessor(t *testing.T) {
	db := openDB(t)
	ctx := context.Background()
	first, err := Append(ctx, db, entry("first"))
	if err != nil {
		t.Fatal(err)
	}

	err = db.WriteTx(ctx, func(tx *sql.Tx) error {
		for _, seq := range []int64{2, 3} {
			_, err := tx.Exec(`
				INSERT INTO audit (seq, v, install, ts, actor_method, action, outcome,
				                   detail_json, prev_hash, hash)
				VALUES (?, 1, 'ins_x', '2026-08-31T09:14:02.371Z', 'local', 'forged',
				        'success', '{}', ?, ?)`,
				seq, first.Hash, strings.Repeat(strconv.FormatInt(seq, 10), 64))
			if err != nil {
				return err
			}
		}
		return nil
	})
	if err == nil {
		t.Fatal("the schema accepted two records claiming the same predecessor")
	}
	if !strings.Contains(err.Error(), "UNIQUE") && !strings.Contains(err.Error(), "unique") {
		t.Errorf("error = %v, want a uniqueness violation", err)
	}
}

func TestSchemaRefusesMalformedRows(t *testing.T) {
	for name, values := range map[string][]any{
		"half-set target": {"2026-08-31T09:14:02.371Z", "success", "model", nil},
		"unknown outcome": {"2026-08-31T09:14:02.371Z", "maybe", nil, nil},
		"loose timestamp": {"2026-08-31T09:14:02Z", "success", nil, nil},
	} {
		t.Run(name, func(t *testing.T) {
			db := openDB(t)
			err := db.WriteTx(context.Background(), func(tx *sql.Tx) error {
				_, err := tx.Exec(`
					INSERT INTO audit (seq, v, install, ts, actor_method, action, outcome,
					                   detail_json, target_kind, target_id, prev_hash, hash)
					VALUES (1, 1, 'ins_x', ?, 'local', 'forged', ?, '{}', ?, ?, ?, ?)`,
					values[0], values[1], values[2], values[3],
					GenesisPrevHash, strings.Repeat("a", 64))
				return err
			})
			if err == nil {
				t.Error("the schema accepted a malformed row")
			}
		})
	}
}

func TestAppendValidatesBeforeWriting(t *testing.T) {
	db := openDB(t)
	e := entry("model.enable")
	e.Outcome = "maybe"

	if _, err := Append(context.Background(), db, e); !errors.Is(err, ErrInvalidRecord) {
		t.Errorf("error = %v, want ErrInvalidRecord", err)
	}
	var rows int
	if err := db.Read().QueryRow(`SELECT count(*) FROM audit`).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if rows != 0 {
		t.Errorf("a rejected record left %d rows behind", rows)
	}
}

// R1-07: concurrent writers cannot interleave to produce two records claiming
// the same seq or the same predecessor. Goroutines are not enough to show this,
// because the CLI and the server are separate processes against one file, so
// the writers here are real processes.
func TestConcurrentProcessesCannotForkTheChain(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nodary.db")
	openAt(t, path).Close() // migrate once so the children only write

	const procs, each = 4, 15
	startAt := time.Now().Add(2 * time.Second).Format(time.RFC3339Nano)

	var wg sync.WaitGroup
	fails := make(chan string, procs)
	for p := range procs {
		wg.Add(1)
		go func(p int) {
			defer wg.Done()
			cmd := exec.Command(os.Args[0], "-test.run=TestChildAppender", "-test.timeout=120s")
			cmd.Env = append(os.Environ(),
				"NODARY_AUDIT_CHILD=1",
				"NODARY_AUDIT_PATH="+path,
				"NODARY_AUDIT_WHO="+strconv.Itoa(p),
				"NODARY_AUDIT_EACH="+strconv.Itoa(each),
				"NODARY_AUDIT_START="+startAt,
			)
			if b, err := cmd.CombinedOutput(); err != nil {
				fails <- fmt.Sprintf("child %d: %v\n%s", p, err, b)
			}
		}(p)
	}
	wg.Wait()
	close(fails)
	for msg := range fails {
		t.Fatal(msg)
	}

	db, err := store.OpenReadOnly(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	rows, err := db.Read().Query(`SELECT ` + columns + ` FROM audit ORDER BY seq`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()

	var n int64
	prev := GenesisPrevHash
	for rows.Next() {
		r, err := scanRecord(rows)
		if err != nil {
			t.Fatal(err)
		}
		n++
		if r.Seq != n {
			t.Fatalf("sequence jumped: got %d, want %d", r.Seq, n)
		}
		if r.PrevHash != prev {
			t.Fatalf("record %d chains to %s, want %s", r.Seq, r.PrevHash, prev)
		}
		got, err := r.Compute()
		if err != nil {
			t.Fatal(err)
		}
		if got != r.Hash {
			t.Fatalf("record %d re-hashes to %s, stored %s", r.Seq, got, r.Hash)
		}
		prev = r.Hash
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if want := int64(procs * each); n != want {
		t.Errorf("%d records, want %d", n, want)
	}
}

// TestChildAppender is the other half of TestConcurrentProcessesCannotForkTheChain.
func TestChildAppender(t *testing.T) {
	path := os.Getenv("NODARY_AUDIT_PATH")
	if os.Getenv("NODARY_AUDIT_CHILD") == "" || path == "" {
		t.Skip("not invoked as a child appender")
	}
	each, err := strconv.Atoi(os.Getenv("NODARY_AUDIT_EACH"))
	if err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(context.Background(), path)
	if err != nil {
		t.Fatalf("child Open: %v", err)
	}
	defer db.Close()

	// The window a second writer can slip through is microseconds wide, so the
	// children are given one absolute start instant and spin until it passes.
	// Without it the parent's process-spawn cost dominates and they never
	// overlap at all.
	if at := os.Getenv("NODARY_AUDIT_START"); at != "" {
		when, err := time.Parse(time.RFC3339Nano, at)
		if err != nil {
			t.Fatal(err)
		}
		for time.Now().Before(when) {
		}
	}

	who := os.Getenv("NODARY_AUDIT_WHO")
	for i := range each {
		e := entry(fmt.Sprintf("child.%s.%d", who, i))
		e.TS = time.Now()
		if _, err := Append(context.Background(), db, e); err != nil {
			t.Fatalf("child %s append %d: %v", who, i, err)
		}
	}
}
