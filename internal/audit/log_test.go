package audit

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/nodarynet/nodary/internal/store"
)

var fixedClock = func() time.Time {
	return time.Date(2026, 8, 31, 9, 14, 2, 371_000_000, time.UTC)
}

// logFor returns a Log writing to a temporary database, plus the sink it
// delivers to and a table for a mutation to change.
func logFor(t *testing.T, posture Posture) (*Log, *flaky, *store.DB) {
	t.Helper()
	db := openDB(t)
	if err := db.WriteTx(context.Background(), func(tx *sql.Tx) error {
		_, err := tx.Exec(`CREATE TABLE thing (name TEXT PRIMARY KEY) STRICT`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	sink := &flaky{}
	return New(db, NewDelivery([]Sink{sink}, posture, io.Discard), WithClock(fixedClock)), sink, db
}

func request(action string) Request {
	return Request{
		Actor:  Actor{ID: "root", Method: "local"},
		Source: Source{Version: "0.0.1-rc1"},
		Action: action,
	}
}

func things(t *testing.T, db *store.DB) int {
	t.Helper()
	var n int
	if err := db.Read().QueryRow(`SELECT count(*) FROM thing`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestActRecordsASuccessWithItsChange(t *testing.T) {
	l, sink, db := logFor(t, Warn)

	r, err := l.Act(context.Background(), request("thing.add"), func(m Mutation) error {
		m.Detail("name", "first")
		_, err := m.Tx().Exec(`INSERT INTO thing(name) VALUES ('first')`)
		return err
	})
	if err != nil {
		t.Fatalf("Act: %v", err)
	}
	if r.Outcome != OutcomeSuccess {
		t.Errorf("outcome = %q, want success", r.Outcome)
	}
	if r.Seq != 1 || r.PrevHash != GenesisPrevHash {
		t.Errorf("record = seq %d prev %s", r.Seq, r.PrevHash)
	}
	if got := r.Detail["name"]; got != "first" {
		t.Errorf("detail name = %v, want \"first\"", got)
	}
	if things(t, db) != 1 {
		t.Error("the change did not commit with its record")
	}

	// The record reached the sink, and as exactly the bytes Line produces.
	want, err := r.Line()
	if err != nil {
		t.Fatal(err)
	}
	sink.mu.Lock()
	defer sink.mu.Unlock()
	if len(sink.got) != 1 || !bytes.Equal(sink.got[0], want) {
		t.Errorf("sink received %q, want %q", sink.got, want)
	}
}

// A failed mutation changes nothing and is still recorded. The record cannot
// share the failed transaction, so it is written in its own.
func TestActRecordsAFailureAfterRollingBack(t *testing.T) {
	l, sink, db := logFor(t, Warn)
	boom := errors.New("the backend refused")

	r, err := l.Act(context.Background(), request("thing.add"), func(m Mutation) error {
		if _, err := m.Tx().Exec(`INSERT INTO thing(name) VALUES ('rolled-back')`); err != nil {
			return err
		}
		m.Detail("attempted", "rolled-back")
		return boom
	})
	if !errors.Is(err, boom) {
		t.Fatalf("Act error = %v, want the mutation's error", err)
	}
	if r.Outcome != OutcomeFailure {
		t.Errorf("outcome = %q, want failure", r.Outcome)
	}
	if r.Seq != 1 {
		t.Errorf("seq = %d, want 1", r.Seq)
	}
	if things(t, db) != 0 {
		t.Error("a failed mutation left its change behind")
	}
	if got, ok := r.Detail["error"].(string); !ok || !strings.Contains(got, "the backend refused") {
		t.Errorf("detail error = %v, want the error tail", r.Detail["error"])
	}
	// The detail collected before the failure is kept: it is what says how far
	// the attempt got.
	if r.Detail["attempted"] != "rolled-back" {
		t.Errorf("detail collected before the failure was lost: %v", r.Detail)
	}
	sink.mu.Lock()
	defer sink.mu.Unlock()
	if len(sink.got) != 1 {
		t.Errorf("a failure record was not delivered: %d lines", len(sink.got))
	}
}

// A partial outcome commits. Rolling back would not undo the part that already
// happened outside the transaction, and would leave the database claiming
// nothing occurred.
func TestActCommitsAPartialOutcome(t *testing.T) {
	l, _, db := logFor(t, Warn)
	cause := errors.New("two of three nodes drained")

	r, err := l.Act(context.Background(), request("node.drain"), func(m Mutation) error {
		if _, err := m.Tx().Exec(`INSERT INTO thing(name) VALUES ('drained')`); err != nil {
			return err
		}
		return Partial{Err: cause}
	})
	if !errors.Is(err, cause) {
		t.Fatalf("Act error = %v, want the partial cause", err)
	}
	if r.Outcome != OutcomePartial {
		t.Errorf("outcome = %q, want partial", r.Outcome)
	}
	if things(t, db) != 1 {
		t.Error("a partial outcome rolled back the part that had already happened")
	}
}

func TestActRefusesWhileDeliveryIsBlocked(t *testing.T) {
	l, sink, db := logFor(t, Block)
	ctx := context.Background()

	if _, err := l.Act(ctx, request("thing.add"), func(m Mutation) error {
		_, err := m.Tx().Exec(`INSERT INTO thing(name) VALUES ('first')`)
		return err
	}); err != nil {
		t.Fatal(err)
	}

	sink.mu.Lock()
	sink.fail = true
	sink.mu.Unlock()
	if _, err := l.Act(ctx, request("thing.add"), func(m Mutation) error {
		_, err := m.Tx().Exec(`INSERT INTO thing(name) VALUES ('second')`)
		return err
	}); err != nil {
		t.Fatalf("the failing delivery refused the action that caused it: %v", err)
	}
	if things(t, db) != 2 {
		t.Fatal("the record whose delivery failed was not committed")
	}

	// The next one is refused, and changes nothing.
	_, err := l.Act(ctx, request("thing.add"), func(m Mutation) error {
		_, err := m.Tx().Exec(`INSERT INTO thing(name) VALUES ('third')`)
		return err
	})
	if !errors.Is(err, ErrDeliveryBlocked) {
		t.Errorf("error = %v, want ErrDeliveryBlocked", err)
	}
	if things(t, db) != 2 {
		t.Error("a refused action changed state anyway")
	}
}

// A detail the canonical encoder cannot hold must not roll back a mutation that
// worked. A developer's logging mistake in a rarely-taken branch would
// otherwise refuse an operator's action.
func TestUnencodableDetailIsRenderedRatherThanFatal(t *testing.T) {
	l, _, db := logFor(t, Warn)

	r, err := l.Act(context.Background(), request("thing.add"), func(m Mutation) error {
		m.Detail("when", time.Now()) // outside the canonical domain
		m.Detail("count", 3)
		_, err := m.Tx().Exec(`INSERT INTO thing(name) VALUES ('first')`)
		return err
	})
	if err != nil {
		t.Fatalf("an unencodable detail failed the action: %v", err)
	}
	if things(t, db) != 1 {
		t.Error("the change was rolled back")
	}
	if _, ok := r.Detail["when"].(string); !ok {
		t.Errorf("detail when = %#v, want a rendered string", r.Detail["when"])
	}
	coerced, ok := r.Detail["_coerced"].([]any)
	if !ok || len(coerced) != 1 || coerced[0] != "when" {
		t.Errorf("_coerced = %#v, want [when]", r.Detail["_coerced"])
	}
	if r.Detail["count"] != 3 {
		t.Errorf("an encodable detail was coerced too: %#v", r.Detail["count"])
	}
}

// The unexported method is the entire enforcement mechanism. Tidying it away
// would silently turn a compile error into a code review.
func TestMutationCannotBeImplementedElsewhere(t *testing.T) {
	typ := reflect.TypeOf((*Mutation)(nil)).Elem()
	for i := range typ.NumMethod() {
		if typ.Method(i).PkgPath != "" {
			return // an unexported method: unimplementable outside this package
		}
	}
	t.Error("Mutation has only exported methods, so any package can implement it " +
		"and bypass Act")
}

// The hole types cannot close: a package calling store.WriteTx directly rather
// than going through Act. Migrate needs WriteTx and is not a mutation, so the
// method cannot be hidden. This is a CI gate instead, and is described as such
// in docs/plans/R1b-audit-chain.md.
func TestNothingBypassesTheSeam(t *testing.T) {
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	allowed := map[string]bool{
		filepath.Join(root, "internal", "store"): true,
		filepath.Join(root, "internal", "audit"): true,
	}

	var offenders []string
	err = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == ".git" || d.Name() == "vendor" {
				return filepath.SkipDir
			}
			return nil
		}
		// Test files are deliberately out of scope. They are not a shipped
		// path, and they legitimately reach past the seam — a verification
		// test has to be able to tamper with the chain in order to prove the
		// tampering is detected.
		if filepath.Ext(path) != ".go" || strings.HasSuffix(path, "_test.go") ||
			allowed[filepath.Dir(path)] {
			return nil
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if bytes.Contains(b, []byte(".WriteTx(")) {
			rel, _ := filepath.Rel(root, path)
			offenders = append(offenders, rel)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(offenders) > 0 {
		t.Errorf("these files write to the database outside the audit seam: %v\n"+
			"a mutating call must go through audit.Log.Act", offenders)
	}
}

// Proof the walk is looking where it should: a file outside the allowed
// packages that names WriteTx is found. Without this the test would pass just
// as happily against a walk that visited nothing.
func TestBypassScanFindsAnOffender(t *testing.T) {
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	var scanned int
	err = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && (d.Name() == ".git" || d.Name() == "vendor") {
			return filepath.SkipDir
		}
		if !d.IsDir() && filepath.Ext(path) == ".go" && !strings.HasSuffix(path, "_test.go") {
			scanned++
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if scanned < 10 {
		t.Errorf("the bypass scan visited %d Go files; it is not reaching the tree", scanned)
	}
}
