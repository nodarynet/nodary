package audit

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/nodarynet/nodary/internal/canonical"
	"github.com/nodarynet/nodary/internal/store"
)

// Request is what a caller declares about an action before performing it.
//
// It carries no outcome: the outcome is observed, not declared. Nothing here
// can be set after the fact either, which is the point — an operator's
// attestation is fixed before the change is attempted, not written to match
// whatever happened.
type Request struct {
	Actor         Actor
	Source        Source
	Action        string
	Target        *Target
	IntentHash    string
	Justification string
}

// Mutation is the capability an audited call needs in order to change state.
//
// docs/tasks/README.md makes "every mutating call passes through the audit
// layer" a constraint no milestone may violate, and requires it be structural
// rather than conventional. This is the structure: the interface has an
// unexported method, so no package outside internal/audit can implement it, and
// Act is the only thing that produces one. A core function that takes a
// Mutation cannot be called without an audit record existing, and Go will not
// compile an attempt to work around that.
//
// What it does not do, said plainly because a half-true guarantee is worse than
// none: a holder has the raw transaction and could write to the audit table
// itself, or delete from it. So could anyone holding the database file. That is
// what the hash chain is for — tampering is made detectable, not impossible
// (docs/specs/07-identity-audit.md §3).
type Mutation interface {
	// Tx is the transaction the change must be made in, so the change and the
	// record it produces commit together or not at all.
	Tx() *sql.Tx
	// Detail records something worth keeping about what happened: exit status,
	// objects changed, a reason.
	Detail(key string, value any)
	// mutation is unexported and therefore unimplementable outside this
	// package. It is the whole mechanism.
	mutation()
}

// Partial wraps an error from a mutation whose effect reached somewhere the
// transaction does not cover — a node, a systemd unit, a running process.
//
// The transaction still commits, because rolling it back would not undo the
// part that already happened and would leave the database claiming nothing
// occurred. The record says `partial`, which is the honest answer.
type Partial struct{ Err error }

func (p Partial) Error() string { return "partially applied: " + p.Err.Error() }
func (p Partial) Unwrap() error { return p.Err }

// ErrDeliveryBlocked is returned by Act when the posture is Block and a sink is
// failing. It maps to docs/specs/10-cli.md §5's exit code 5.
var ErrDeliveryBlocked = errors.New("refused: audit delivery is failing")

// maxErrorTail bounds what a failure puts in the record. An error tail is
// evidence; a megabyte of one is a denial of service against the chain.
const maxErrorTail = 2048

// Log is the seam every mutating call passes through.
type Log struct {
	db       *store.DB
	delivery *Delivery
	clock    func() time.Time
}

// Option configures a Log.
type Option func(*Log)

// WithClock replaces the source of record timestamps, so chain tests are
// deterministic rather than dependent on when they run.
func WithClock(now func() time.Time) Option {
	return func(l *Log) { l.clock = now }
}

// New returns a Log writing to db and delivering through d.
func New(db *store.DB, d *Delivery, opts ...Option) *Log {
	l := &Log{db: db, delivery: d, clock: time.Now}
	for _, o := range opts {
		o(l)
	}
	return l
}

// Act performs one audited mutation.
//
// On success the change and its record commit in a single transaction. On
// failure the transaction rolls back and the record is written afterwards, in
// its own: a record cannot be committed alongside a change that did not happen,
// and the asymmetry is the right way round, because the case that can lose a
// record to a crash is the case where nothing changed for it to be inconsistent
// with.
//
// The record is returned whether the mutation succeeded or not, so a caller can
// report the sequence number it will be held to.
func (l *Log) Act(ctx context.Context, req Request, fn func(Mutation) error) (Record, error) {
	if err := l.delivery.Blocked(); err != nil {
		return Record{}, fmt.Errorf("%w: %w", ErrDeliveryBlocked, err)
	}

	now := l.clock()
	m := &mutation{detail: map[string]any{}}

	var (
		record  Record
		actErr  error
		partial Partial
	)
	txErr := l.db.WriteTx(ctx, func(tx *sql.Tx) error {
		// Reset per attempt: WriteTx runs the callback once, but a detail
		// accumulated by a previous call must never leak into this record.
		m.reset(tx)

		err := fn(m)
		switch {
		case err == nil:
		case errors.As(err, &partial):
			// Committed deliberately. See Partial.
			actErr = err
		default:
			actErr = err
			return err
		}

		outcome := OutcomeSuccess
		if actErr != nil {
			outcome = OutcomePartial
		}
		record, err = AppendTx(tx, l.entry(now, req, outcome, m, actErr))
		return err
	})

	switch {
	case txErr != nil && actErr == nil:
		// The mutation was fine; the chain write or the commit was not. There
		// is no record to write about it, because writing one would need the
		// same machinery that just failed.
		return Record{}, txErr
	case actErr != nil && record.Seq == 0:
		// A rolled-back failure. Its record goes in a transaction of its own.
		failure, err := Append(ctx, l.db, l.entry(now, req, OutcomeFailure, m, actErr))
		if err != nil {
			return Record{}, errors.Join(actErr, fmt.Errorf("recording the failure: %w", err))
		}
		l.emit(ctx, failure)
		return failure, actErr
	}

	l.emit(ctx, record)
	return record, actErr
}

// entry assembles what the chain needs from a request and an outcome.
func (l *Log) entry(now time.Time, req Request, outcome Outcome, m *mutation, actErr error) Entry {
	detail := m.snapshot()
	if actErr != nil {
		detail["error"] = truncate(actErr.Error(), maxErrorTail)
	}
	return Entry{
		TS:            now,
		Actor:         req.Actor,
		Source:        req.Source,
		Action:        req.Action,
		Target:        req.Target,
		IntentHash:    req.IntentHash,
		Justification: req.Justification,
		Outcome:       outcome,
		Detail:        detail,
	}
}

// emit hands a committed record to the sinks. It is deliberately after the
// commit and deliberately returns nothing: see Delivery.Emit.
func (l *Log) emit(ctx context.Context, r Record) {
	if r.Seq == 0 {
		return
	}
	line, err := r.Line()
	if err != nil {
		// The record is in the database and verifiable there; only delivery is
		// affected, so this is reported the same way any delivery failure is.
		fmt.Fprintf(l.delivery.warn, "nodary: audit record %d cannot be serialised: %v\n", r.Seq, err)
		return
	}
	l.delivery.Emit(ctx, r.Seq, line)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "… (truncated)"
}

// mutation is the only implementation of Mutation.
type mutation struct {
	mu      sync.Mutex
	tx      *sql.Tx
	detail  map[string]any
	coerced []string
}

func (m *mutation) mutation()   {}
func (m *mutation) Tx() *sql.Tx { return m.tx }

func (m *mutation) reset(tx *sql.Tx) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.tx = tx
	m.detail = map[string]any{}
	m.coerced = nil
}

// Detail records a value, rendering anything the canonical encoder cannot hold.
//
// A detail is diagnostic; the change is the point. Letting an unencodable value
// — a time.Time, a struct, a channel — fail the encode would roll back a
// mutation that had already succeeded, so a developer's logging mistake in a
// rarely-taken branch would refuse an operator's action. Instead the value is
// rendered and the coercion is recorded in the record itself, under
// "_coerced", so nothing is lost quietly.
func (m *mutation) Detail(key string, value any) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, err := canonical.Encode(value); err != nil {
		m.detail[key] = fmt.Sprintf("%v", value)
		m.coerced = append(m.coerced, key)
		return
	}
	m.detail[key] = value
}

func (m *mutation) snapshot() map[string]any {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make(map[string]any, len(m.detail)+1)
	for k, v := range m.detail {
		out[k] = v
	}
	if len(m.coerced) > 0 {
		keys := append([]string(nil), m.coerced...)
		sort.Strings(keys)
		rendered := make([]any, len(keys))
		for i, k := range keys {
			rendered[i] = k
		}
		out["_coerced"] = rendered
	}
	return out
}
