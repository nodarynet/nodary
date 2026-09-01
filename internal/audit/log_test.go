package audit

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/nodarynet/nodary/internal/canonical"
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

// A detail this package cannot encode must never cost the operator their
// change. The coercion exists for exactly that, and rendering with %v is not
// enough on its own: the rendering of an invalid-UTF-8 string is still invalid
// UTF-8, so the record failed to hash and the successful mutation rolled back.
func TestAHostileDetailDoesNotRollBackTheMutation(t *testing.T) {
	l, _, db := logFor(t, Warn)

	r, err := l.Act(context.Background(), request("thing.add"), func(m Mutation) error {
		m.Detail("raw", string([]byte{0xff, 0xfe}))
		m.Detail("nested", map[string]any{"also": string([]byte{0x80})})
		_, err := m.Tx().Exec(`INSERT INTO thing(name) VALUES ('first')`)
		return err
	})
	if err != nil {
		t.Fatalf("a detail the encoder cannot hold failed the action: %v", err)
	}
	if things(t, db) != 1 {
		t.Error("the change was rolled back by a logging value")
	}
	if r.Seq != 1 {
		t.Errorf("no record was written: seq %d", r.Seq)
	}

	// Repaired, not discarded. Falling back to a placeholder would also keep
	// the mutation, and would throw away what the detail was trying to say.
	// strings.ToValidUTF8 replaces each *run* of invalid bytes with one
	// replacement character, so two bad bytes in a row become one.
	raw, _ := r.Detail["raw"].(string)
	if raw != "\uFFFD" {
		t.Errorf("detail raw = %q, want the invalid run replaced", raw)
	}
	nested, _ := r.Detail["nested"].(string)
	if !utf8.ValidString(nested) || !strings.Contains(nested, "also") {
		t.Errorf("detail nested = %q, want a repaired rendering that kept its content", nested)
	}
	for _, v := range []string{raw, nested} {
		if strings.Contains(v, "unrepresentable") {
			t.Errorf("a repairable value fell back to the placeholder: %q", v)
		}
	}
}

// A key is a map key in the record, so it has to be encodable too — and a
// hostile one fails the whole record, not just its own entry.
func TestAHostileDetailKeyDoesNotRollBackTheMutation(t *testing.T) {
	l, _, db := logFor(t, Warn)

	r, err := l.Act(context.Background(), request("thing.add"), func(m Mutation) error {
		m.Detail(string([]byte{0xff}), "fine")
		_, err := m.Tx().Exec(`INSERT INTO thing(name) VALUES ('first')`)
		return err
	})
	if err != nil {
		t.Fatalf("a detail key the encoder cannot hold failed the action: %v", err)
	}
	if things(t, db) != 1 || r.Seq != 1 {
		t.Errorf("things=%d seq=%d", things(t, db), r.Seq)
	}
	if got, ok := r.Detail["\uFFFD"]; !ok || got != "fine" {
		t.Errorf("detail = %#v, want the key repaired and the value kept", r.Detail)
	}
}

// Whatever a caller passes, the result must encode. This is the invariant the
// repair exists for, asserted directly rather than only through Act.
func TestEncodableAlwaysProducesSomethingTheEncoderAccepts(t *testing.T) {
	for name, v := range map[string]any{
		"invalid utf-8":     string([]byte{0xff, 0xfe}),
		"lone surrogate":    string([]byte{0xed, 0xa0, 0x80}),
		"map with raw byte": map[string]any{"k": string([]byte{0x80})},
		"slice with raw":    []any{string([]byte{0xc3})},
		"a time":            time.Now(),
		"a channel":         make(chan int),
		"an error":          errors.New("disk full"),
		"a func":            func() {},
		"nil":               nil,
		"fine":              "ordinary",
	} {
		t.Run(name, func(t *testing.T) {
			got, _ := encodable(v)
			if _, err := canonical.Encode(got); err != nil {
				t.Errorf("encodable(%v) produced %#v, which the encoder refuses: %v", name, got, err)
			}
		})
	}
}

// The error tail is cut to a byte length. Cutting a multi-byte rune in half
// leaves invalid UTF-8, the record cannot be hashed, and a failed mutation
// produces no audit record at all — which is the one thing R1-12 promises
// cannot happen.
func TestAFailureWithALongNonASCIIErrorIsStillRecorded(t *testing.T) {
	l, _, db := logFor(t, Warn)
	boom := errors.New(strings.Repeat("日", 700) + " — 停止")

	r, err := l.Act(context.Background(), request("thing.add"), func(m Mutation) error {
		return boom
	})
	if !errors.Is(err, boom) {
		t.Fatalf("Act error = %v, want the mutation error", err)
	}
	if r.Seq == 0 {
		t.Fatal("a failure with a long non-ASCII error produced no record")
	}
	if r.Outcome != OutcomeFailure {
		t.Errorf("outcome = %q", r.Outcome)
	}
	tail, _ := r.Detail["error"].(string)
	if !utf8.ValidString(tail) {
		t.Errorf("the recorded error tail is not valid UTF-8: %q", tail)
	}
	if !strings.HasPrefix(tail, "日") {
		t.Errorf("the error tail lost its start: %q", tail)
	}
	if len(tail) > maxErrorTail+len("… (truncated)") {
		t.Errorf("the error tail is %d bytes, past the bound", len(tail))
	}
	if things(t, db) != 0 {
		t.Error("a failed mutation left its change behind")
	}
}

// An error's text can carry raw bytes from a subprocess, and the encoder
// refuses invalid UTF-8. Unrepaired, that is again a failed mutation with no
// record — the same hole as the rune split, reached a different way.
func TestAFailureWithAnUnprintableErrorIsStillRecorded(t *testing.T) {
	l, _, _ := logFor(t, Warn)
	boom := errors.New("backend said: " + string([]byte{0xff, 0xfe, 0x80}))

	r, err := l.Act(context.Background(), request("thing.add"), func(m Mutation) error {
		return boom
	})
	if !errors.Is(err, boom) {
		t.Fatalf("Act error = %v", err)
	}
	if r.Seq == 0 {
		t.Fatal("a failure with an unprintable error produced no record")
	}
	tail, _ := r.Detail["error"].(string)
	if !utf8.ValidString(tail) {
		t.Errorf("recorded tail is not valid UTF-8: %q", tail)
	}
	if !strings.HasPrefix(tail, "backend said: ") {
		t.Errorf("tail = %q, want the readable part kept", tail)
	}
}

// An error is the most natural thing to put in a detail — the field is
// specified as "exit status, error tail, objects changed". It used to encode as
// {} and say nothing: errors.errorString has one unexported field, so the
// canonical encoder produced an empty object and reported no problem.
func TestAnErrorInADetailKeepsItsText(t *testing.T) {
	l, _, _ := logFor(t, Warn)

	r, err := l.Act(context.Background(), request("thing.add"), func(m Mutation) error {
		m.Detail("reason", errors.New("disk full"))
		m.Detail("wrapped", fmt.Errorf("staging %s: %w", "mdl_1", errors.New("disk full")))
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := r.Detail["reason"]; got != "disk full" {
		t.Errorf("detail reason = %#v, want the error text", got)
	}
	if got := r.Detail["wrapped"]; got != "staging mdl_1: disk full" {
		t.Errorf("detail wrapped = %#v, want the error text", got)
	}
	// An error is rendered, not coerced: nothing was lost, so nothing is flagged.
	if _, flagged := r.Detail["_coerced"]; flagged {
		t.Errorf("an error was reported as coerced: %#v", r.Detail["_coerced"])
	}
}
