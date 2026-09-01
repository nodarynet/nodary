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
	coerced, ok := r.Detail["_coerced"].([]string)
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
// bypassOffenders returns the non-test Go files under root, outside the allowed
// directories, that name WriteTx. One function, so the canary below exercises
// the scan the invariant actually depends on rather than a second copy of it.
func bypassOffenders(root string, allowed map[string]bool) ([]string, error) {
	var offenders []string
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
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
	return offenders, err
}

func TestNothingBypassesTheSeam(t *testing.T) {
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	offenders, err := bypassOffenders(root, map[string]bool{
		filepath.Join(root, "internal", "store"): true,
		filepath.Join(root, "internal", "audit"): true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(offenders) > 0 {
		t.Errorf("these files write to the database outside the audit seam: %v\n"+
			"a mutating call must go through audit.Log.Act", offenders)
	}
}

// Proof the scan is looking where it should. The invariant it guards is one
// docs/tasks/README.md makes non-negotiable, so the canary has to run the same
// function — an earlier version walked the tree a second time and only counted
// files, which would have passed just as happily against a scan whose needle
// was mistyped or whose allow list had swallowed the repository root.
func TestBypassScanFindsAnOffender(t *testing.T) {
	root := t.TempDir()
	tree := map[string]string{
		"caught.go":            "package p\n\nfunc f(db *D) { db.WriteTx(nil, nil) }\n",
		"allowed/exempt.go":    "package p\n\nfunc g(db *D) { db.WriteTx(nil, nil) }\n",
		"innocent.go":          "package p\n\nfunc h() {}\n",
		"caught_test.go":       "package p\n\nfunc i(db *D) { db.WriteTx(nil, nil) }\n",
		"notgo.txt":            "db.WriteTx(",
		"vendor/dependency.go": "package v\n\nfunc j(db *D) { db.WriteTx(nil, nil) }\n",
	}
	for name, body := range tree {
		path := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	offenders, err := bypassOffenders(root, map[string]bool{filepath.Join(root, "allowed"): true})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(offenders, []string{"caught.go"}) {
		t.Errorf("offenders = %v, want exactly [caught.go]", offenders)
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
	// Repaired in place, so the value keeps its shape: a caller who recorded a
	// map still has a map to read, not a %v rendering of one.
	nested, ok := r.Detail["nested"].(map[string]any)
	if !ok {
		t.Fatalf("detail nested = %#v, want the map with its bad string repaired", r.Detail["nested"])
	}
	also, _ := nested["also"].(string)
	if !utf8.ValidString(also) || also == "" {
		t.Errorf("detail nested.also = %q, want the invalid run replaced", also)
	}
	if strings.Contains(raw, "unrepresentable") || strings.Contains(also, "unrepresentable") {
		t.Error("a repairable value fell back to the placeholder")
	}
	// Repairing a string does lose something, so it is flagged.
	coerced, _ := r.Detail["_coerced"].([]string)
	if len(coerced) != 2 {
		t.Errorf("_coerced = %#v, want both repaired keys", r.Detail["_coerced"])
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

// A Partial commits, so its record is written inside the transaction. If the
// COMMIT then fails, nothing is in the database — and the record must not reach
// a sink regardless, because a mirror holding a record the database does not is
// the "these two are not a pair" alarm `audit verify --mirror` exists to raise.
func TestAFailedCommitDeliversNoRecordAndReportsItself(t *testing.T) {
	l, sink, db := logFor(t, Warn)
	ctx := context.Background()

	// A deferred foreign key fails at COMMIT rather than at INSERT, which is
	// the shape of every commit-time failure: nothing has told the callback
	// anything is wrong.
	if err := db.WriteTx(ctx, func(tx *sql.Tx) error {
		_, err := tx.Exec(`CREATE TABLE child (
			parent TEXT NOT NULL REFERENCES thing(name) DEFERRABLE INITIALLY DEFERRED
		) STRICT`)
		return err
	}); err != nil {
		t.Fatal(err)
	}

	rec, err := l.Act(ctx, request("node.drain"), func(m Mutation) error {
		if _, err := m.Tx().Exec(`INSERT INTO child(parent) VALUES ('absent')`); err != nil {
			return err
		}
		return Partial{Err: errors.New("the node was drained")}
	})
	if err == nil {
		t.Fatal("a failed commit was reported as success")
	}
	if !strings.Contains(err.Error(), "FOREIGN KEY") {
		t.Errorf("the commit failure was dropped from %v", err)
	}

	// Whatever was recorded, it is a real row and the sink saw only real rows.
	var stored int64
	if err := db.Read().QueryRow(`SELECT count(*) FROM audit`).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	sink.mu.Lock()
	delivered := len(sink.got)
	sink.mu.Unlock()
	if int64(delivered) != stored {
		t.Errorf("delivered %d records, database holds %d", delivered, stored)
	}
	if rec.Seq != 0 && rec.Seq > stored {
		t.Errorf("Act returned seq %d, beyond the %d records that exist", rec.Seq, stored)
	}
}

// Both Partial and *Partial compile at a call site and mean the same thing, so
// the pointer form must not be read as an ordinary failure — that rolls back a
// change the caller has just said cannot be rolled back, and records "nothing
// changed" about a node that was drained.
func TestAPartialPointerIsStillPartial(t *testing.T) {
	l, _, db := logFor(t, Warn)

	rec, err := l.Act(context.Background(), request("node.drain"), func(m Mutation) error {
		_, err := m.Tx().Exec(`INSERT INTO thing(name) VALUES ('drained')`)
		if err != nil {
			return err
		}
		return &Partial{Err: errors.New("the node restarted")}
	})
	if err == nil {
		t.Fatal("a partial application was reported as success")
	}
	if rec.Outcome != OutcomePartial {
		t.Errorf("outcome = %q, want %q", rec.Outcome, OutcomePartial)
	}
	if things(t, db) != 1 {
		t.Error("the change was rolled back even though it reached a node")
	}
}

// docs/specs/07-identity-audit.md §3: the posture decides whether the next
// mutation proceeds, never whether the record is written. A refusal that left no
// trace would let anyone who can break a sink act without appearing in the
// chain — and it would also wedge the appliance, because delivery is the only
// thing that observes a sink recovering.
func TestARefusedMutationIsItselfRecordedAndLetsDeliveryRecover(t *testing.T) {
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
		t.Fatal(err)
	}

	refusal, err := l.Act(ctx, request("thing.add"), func(m Mutation) error {
		_, err := m.Tx().Exec(`INSERT INTO thing(name) VALUES ('third')`)
		return err
	})
	if !errors.Is(err, ErrDeliveryBlocked) {
		t.Fatalf("error = %v, want ErrDeliveryBlocked", err)
	}
	if things(t, db) != 2 {
		t.Error("a refused action changed state anyway")
	}
	if refusal.Seq == 0 {
		t.Fatal("the refusal was not recorded")
	}
	if refusal.Outcome != OutcomeFailure {
		t.Errorf("outcome = %q, want %q", refusal.Outcome, OutcomeFailure)
	}
	if got, _ := refusal.Detail["error"].(string); !strings.Contains(got, "delivery is failing") {
		t.Errorf("the record does not say why it was refused: %q", got)
	}

	// The refusal's own delivery attempt is what notices the sink is back.
	// Nothing else delivers, so without it a single sink failure refused every
	// mutation until the process was restarted — and restarting is a mutating
	// operation the CLI would have refused.
	sink.mu.Lock()
	sink.fail = false
	sink.mu.Unlock()
	if _, err := l.Act(ctx, request("thing.add"), func(m Mutation) error {
		_, err := m.Tx().Exec(`INSERT INTO thing(name) VALUES ('fourth')`)
		return err
	}); !errors.Is(err, ErrDeliveryBlocked) {
		t.Fatalf("error = %v, want the attempt that re-tests delivery to still be refused", err)
	}
	if _, err := l.Act(ctx, request("thing.add"), func(m Mutation) error {
		_, err := m.Tx().Exec(`INSERT INTO thing(name) VALUES ('fifth')`)
		return err
	}); err != nil {
		t.Fatalf("delivery recovered but the appliance stayed blocked: %v", err)
	}
	if things(t, db) != 3 {
		t.Error("the mutation after recovery did not apply")
	}
}

// Every string a Request carries is hashed into the record, and the encoder
// refuses invalid UTF-8 inside AppendTx — after the mutation has run. These
// fields arrive from an HTTP body or a CLI flag, so a raw byte in one used to
// roll back an operator's change and leave no record of it at all.
func TestAHostileRequestFieldDoesNotCostTheMutation(t *testing.T) {
	bad := "ticket " + string([]byte{0xff, 0xfe})
	for _, tc := range []struct {
		name  string
		apply func(*Request)
	}{
		{"justification", func(r *Request) { r.Justification = bad }},
		{"actor id", func(r *Request) { r.Actor.ID = bad }},
		{"actor method", func(r *Request) { r.Actor.Method = bad }},
		{"actor session", func(r *Request) { r.Actor.Session = bad }},
		{"action", func(r *Request) { r.Action = bad }},
		{"intent hash", func(r *Request) { r.IntentHash = bad }},
		{"source ip", func(r *Request) { r.Source.IP = bad }},
		{"source version", func(r *Request) { r.Source.Version = bad }},
		{"target", func(r *Request) { r.Target = &Target{Kind: "node", ID: bad} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			l, _, db := logFor(t, Warn)
			req := request("thing.add")
			tc.apply(&req)

			rec, err := l.Act(context.Background(), req, func(m Mutation) error {
				_, err := m.Tx().Exec(`INSERT INTO thing(name) VALUES ('kept')`)
				return err
			})
			if err != nil {
				t.Fatalf("a bad byte in %s cost the mutation: %v", tc.name, err)
			}
			if things(t, db) != 1 {
				t.Error("the change was rolled back")
			}
			if rec.Seq == 0 {
				t.Error("no record was written")
			}
			if !utf8.ValidString(rec.Justification) || !utf8.ValidString(rec.Action) {
				t.Error("the record kept invalid UTF-8")
			}
		})
	}
}

// The encoder takes an error for an ordinary struct with no exported fields and
// emits {} without complaint, so a nested error is not caught by the
// "unencodable" path at all — it just silently loses the reason.
func TestAnErrorNestedInADetailKeepsItsText(t *testing.T) {
	l, _, db := logFor(t, Warn)

	rec, err := l.Act(context.Background(), request("node.drain"), func(m Mutation) error {
		m.Detail("nodes", map[string]any{"a": errors.New("disk is full")})
		m.Detail("all", []any{fmt.Errorf("wrapped: %w", errors.New("unreachable"))})
		_, err := m.Tx().Exec(`INSERT INTO thing(name) VALUES ('drained')`)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	_ = db

	line, lerr := rec.Line()
	if lerr != nil {
		t.Fatal(lerr)
	}
	for _, want := range []string{"disk is full", "wrapped: unreachable"} {
		if !strings.Contains(string(line), want) {
			t.Errorf("record does not carry %q: %s", want, line)
		}
	}
}

// A typed-nil error is a non-nil interface whose Error method dereferences nil.
// Calling it panicked out of Act, rolling back the mutation and writing no
// record — the one outcome Detail's doc promises is impossible.
func TestATypedNilErrorInADetailDoesNotPanic(t *testing.T) {
	l, _, db := logFor(t, Warn)

	var missing *os.PathError
	rec, err := l.Act(context.Background(), request("thing.add"), func(m Mutation) error {
		m.Detail("cleanup", missing)
		_, err := m.Tx().Exec(`INSERT INTO thing(name) VALUES ('kept')`)
		return err
	})
	if err != nil {
		t.Fatalf("a typed-nil error cost the mutation: %v", err)
	}
	if things(t, db) != 1 || rec.Seq == 0 {
		t.Error("the change or its record was lost")
	}
}
