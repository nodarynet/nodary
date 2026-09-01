package audit

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

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

// maxDetailValue bounds one caller-supplied detail string, for the same reason
// and one the reader makes concrete: VerifyFile and Compare cap a mirror line
// at 8 MiB, and nothing bounded a record. A single Detail("stdout", buildLog)
// of nine megabytes committed happily, was written to the mirror in full, and
// left every record after it in that file permanently unverifiable — the
// database and its off-box evidence copy disagreeing about whether the chain
// can be checked at all, with no way to retract the line.
const maxDetailValue = 64 * 1024

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
	now := l.clock()
	m := &mutation{detail: map[string]any{}}

	if err := l.delivery.Blocked(); err != nil {
		blocked := fmt.Errorf("%w: %w", ErrDeliveryBlocked, err)
		// The refusal is itself an action, and it is recorded. The posture
		// decides whether the next mutation proceeds, never whether a record is
		// written — docs/specs/07-identity-audit.md §3 says so in as many
		// words. Nothing is wrong with the write path here; only delivery is
		// failing. A refusal that left no trace would let anyone who can break
		// a sink attempt mutations that never appear in the chain.
		record, err := Append(ctx, l.db, l.entry(now, req, OutcomeFailure, m, blocked))
		if err != nil {
			return Record{}, errors.Join(blocked, fmt.Errorf("recording the refusal: %w", err))
		}
		// Delivering it is also the probe. A sink is cleared from the failing
		// set by a delivery that succeeds, and Act is the only thing that
		// delivers — so returning here without emitting meant that once a sink
		// failed under Block, nothing could ever observe it recover and every
		// mutation was refused until the process was restarted. Which is itself
		// a mutating operation the CLI would have refused. Each refused attempt
		// now re-tests delivery, so the appliance comes back on the attempt
		// after the sink does rather than never.
		l.emit(ctx, record)
		return record, blocked
	}

	var (
		record Record
		actErr error
	)
	txErr := l.db.WriteTx(ctx, func(tx *sql.Tx) error {
		// Reset per attempt: WriteTx runs the callback once, but a detail
		// accumulated by a previous call must never leak into this record.
		m.reset(tx)
		record = Record{}

		err := fn(m)
		switch {
		case err == nil:
		case isPartial(err):
			// Committed deliberately. See Partial.
			actErr = err
		default:
			actErr = err
			return err
		}

		record, err = AppendTx(tx, l.entry(now, req, outcomeOf(actErr), m, actErr))
		return err
	})

	if txErr == nil {
		l.emit(ctx, record)
		return record, actErr
	}

	// Nothing committed. Whatever the closure managed to assign to record
	// before the failure describes a transaction that was rolled back, so the
	// record does not exist and must not reach a sink as if it did: a Partial
	// whose COMMIT failed used to fall past both arms below and deliver a
	// phantom seq to every destination, leaving the mirror permanently ahead of
	// the database and the commit error unreported.
	record = Record{}

	if actErr == nil {
		// The mutation was fine; the chain write or the commit was not. There
		// is no record to write about it, because writing one would need the
		// same machinery that just failed.
		return Record{}, txErr
	}

	// A rolled-back failure. Its record goes in a transaction of its own, and
	// carries the outcome the mutation actually had: a Partial recorded as
	// "failure" would positively assert that nothing changed on a node that
	// was, in fact, drained.
	cause := actErr
	if !errors.Is(txErr, actErr) {
		// The transaction failed for a reason of its own — the chain write, or
		// the commit — on top of the mutation's, and dropping it would tell the
		// caller their change was recorded when it was not.
		cause = errors.Join(actErr, txErr)
	}
	failure, err := Append(ctx, l.db, l.entry(now, req, outcomeOf(actErr), m, cause))
	if err != nil {
		return Record{}, errors.Join(cause, fmt.Errorf("recording the failure: %w", err))
	}
	l.emit(ctx, failure)
	return failure, cause
}

// isPartial reports whether err declares a change that reached outside the
// transaction.
//
// Both Partial and *Partial satisfy error, because Error has a value receiver,
// so both spellings compile at a call site and both mean the same thing. Only
// the value form used to match, and a caller who wrote `return &Partial{...}`
// silently had the mutation rolled back and recorded as "nothing changed".
func isPartial(err error) bool {
	var v Partial
	var p *Partial
	return errors.As(err, &v) || errors.As(err, &p)
}

// outcomeOf reads the outcome from what the mutation returned, so the two
// places that build a record agree on one rule.
func outcomeOf(actErr error) Outcome {
	switch {
	case actErr == nil:
		return OutcomeSuccess
	case isPartial(actErr):
		return OutcomePartial
	}
	return OutcomeFailure
}

// entry assembles what the chain needs from a request and an outcome.
func (l *Log) entry(now time.Time, req Request, outcome Outcome, m *mutation, actErr error) Entry {
	detail := m.snapshot()
	if actErr != nil {
		detail["error"] = truncate(actErr.Error(), maxErrorTail)
	}
	req = req.encodable()
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

// encodable returns the request with every string the record will hash made
// valid UTF-8.
//
// Detail was repaired for this reason already, and these fields need it more.
// The canonical encoder refuses invalid UTF-8, and it refuses it inside
// AppendTx — after the mutation has run — so a justification, a target id or a
// client version carrying a raw byte from a subprocess or an HTTP body did not
// merely lose a field: it rolled the change back and left no audit record at
// all, which is the one outcome this seam promises cannot happen. Unlike
// Detail, every one of these arrives from outside the process.
//
// Nothing here can drop a field, so an actor still cannot become anonymous by
// sending a bad byte: a replaced rune is visible in the record.
func (r Request) encodable() Request {
	r.Actor = Actor{
		ID:      validUTF8(r.Actor.ID),
		Method:  validUTF8(r.Actor.Method),
		Session: validUTF8(r.Actor.Session),
	}
	r.Source = Source{
		IP:      validUTF8(r.Source.IP),
		Version: validUTF8(r.Source.Version),
	}
	r.Action = validUTF8(r.Action)
	r.IntentHash = validUTF8(r.IntentHash)
	r.Justification = validUTF8(r.Justification)
	if r.Target != nil {
		r.Target = &Target{Kind: validUTF8(r.Target.Kind), ID: validUTF8(r.Target.ID)}
	}
	return r
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
		// affected, so this is reported the same way any delivery failure is —
		// through Delivery, which holds the lock every other write to that
		// writer is made under. warn is a caller-supplied io.Writer with no
		// concurrency contract of its own.
		l.delivery.warnf("nodary: audit record %d cannot be serialised: %v\n", r.Seq, err)
		return
	}
	l.delivery.Emit(ctx, r.Seq, line)
}

// truncate bounds the error tail and keeps it valid UTF-8.
//
// Both halves matter. Cutting to a byte length splits a multi-byte rune, and an
// error's text can carry raw bytes from a subprocess; either leaves a string
// the canonical encoder refuses, the record then cannot be hashed, and a failed
// mutation produces no audit record at all — the one thing this seam promises
// cannot happen. Found by review: 700 CJK characters were enough.
func truncate(s string, n int) string {
	s = validUTF8(s)
	if len(s) <= n {
		return s
	}
	cut := n
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + "… (truncated)"
}

// validUTF8 replaces anything that is not well-formed. The canonical encoder
// refuses invalid UTF-8 rather than substituting silently, which is right for a
// record's own fields and wrong for a diagnostic detail: a detail must never
// cost the operator the change it was describing.
func validUTF8(s string) string { return strings.ToValidUTF8(s, "\uFFFD") }

// repairDetail rewrites v into something the canonical encoder can hold,
// wherever the encoder would walk to find a problem, and reports whether
// anything changed.
//
// It handles the two things a detail carries that the encoder will not:
//
// An error. canonical takes *errors.errorString for an ordinary struct whose
// only field is unexported, emits {} and reports no problem at all — so an
// operator reading a failure record found an empty object where the reason
// should have been, and the coercion path never fired because nothing had
// failed. Repairing only the top level left the same hole one level down, which
// is where a mutation that touched several nodes puts it.
//
// A string the encoder refuses, or one large enough to break a reader of the
// mirror. See maxDetailValue.
//
// The walk mirrors canonical's own: string-keyed maps and non-byte slices, and
// nothing else. Repairing in place keeps the value's shape, which is worth more
// to whoever reads the record than a %v rendering of the whole thing.
func repairDetail(v any) (any, bool) {
	if v == nil {
		return nil, false
	}
	if err, ok := v.(error); ok {
		// Rendering an error to its text loses nothing, so it is not a
		// coercion. Having to cut it down is.
		text := errorText(err)
		return truncate(text, maxDetailValue), len(text) > maxDetailValue
	}
	if s, ok := v.(string); ok {
		if r := truncate(s, maxDetailValue); r != s {
			return r, true
		}
		return s, false
	}
	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.Map:
		if rv.IsNil() || rv.Type().Key().Kind() != reflect.String {
			return v, false
		}
		out, changed := make(map[string]any, rv.Len()), false
		for iter := rv.MapRange(); iter.Next(); {
			e, c := repairDetail(iter.Value().Interface())
			out[iter.Key().String()], changed = e, changed || c
		}
		return out, changed
	case reflect.Slice, reflect.Array:
		// canonical refuses a []byte outright rather than base64ing it, so
		// leave one alone and let it be rendered like any other refusal.
		if rv.Type().Elem().Kind() == reflect.Uint8 {
			return v, false
		}
		if rv.Kind() == reflect.Slice && rv.IsNil() {
			return v, false
		}
		out, changed := make([]any, rv.Len()), false
		for i := range out {
			e, c := repairDetail(rv.Index(i).Interface())
			out[i], changed = e, changed || c
		}
		return out, changed
	}
	return v, false
}

// errorText renders one error without trusting it not to panic.
//
// A typed-nil error — `var e *myErr; Detail("cause", e)`, the shape a Go
// function produces by returning a concrete pointer type — is a non-nil
// interface whose Error method dereferences nil. Calling it directly panicked
// out of Act, so the mutation rolled back and no record was written: the exact
// outcome Detail's doc promises is impossible. fmt recovers a panicking Error
// and renders %!v(PANIC=...), which is a worse-looking detail than a message
// and a better one than a lost record.
func errorText(err error) (s string) {
	defer func() {
		if r := recover(); r != nil {
			s = fmt.Sprintf("%v", err)
		}
	}()
	if rv := reflect.ValueOf(err); rv.Kind() == reflect.Pointer && rv.IsNil() {
		return "<nil error>"
	}
	return err.Error()
}

// encodable returns a value canonical.Encode is guaranteed to accept, and
// reports whether anything had to change to get there.
func encodable(v any) (any, bool) {
	// An error's text is the whole reason for recording one. The encoder
	// accepts *errors.errorString as a struct whose only field is unexported,
	// emits {} and reports no problem — so an operator reading a failure record
	// found an empty object where the reason should have been. Found by review.
	v, repaired := repairDetail(v)
	if _, e := canonical.Encode(v); e == nil {
		return v, repaired
	}
	// Rendering alone is not enough: the rendering of an invalid-UTF-8 string
	// is still invalid UTF-8, and a map containing one renders to a string
	// containing one.
	s := validUTF8(fmt.Sprintf("%v", v))
	// Unreachable as canonical stands: it refuses a Go string only for invalid
	// UTF-8, which validUTF8 has just removed. Kept so that a new rejection
	// rule there cannot silently bring back the rollback this function exists
	// to prevent — deliberately redundant, and measured as such: removing this
	// alone breaks no test, removing it together with the repair above does.
	if _, e := canonical.Encode(s); e != nil {
		return "<unrepresentable value>", true
	}
	return s, true
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
//
// The guarantee is absolute rather than best-effort: whatever a caller passes,
// the resulting record encodes. An earlier version only rendered with %v, which
// left invalid UTF-8 still invalid and rolled the mutation back anyway.
func (m *mutation) Detail(key string, value any) {
	m.mu.Lock()
	defer m.mu.Unlock()
	// The key is a map key in the record, so it has to be encodable too.
	key = validUTF8(key)
	v, coerced := encodable(value)
	m.detail[key] = v
	if coerced {
		m.coerced = append(m.coerced, key)
	}
}

func (m *mutation) snapshot() map[string]any {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make(map[string]any, len(m.detail)+1)
	for k, v := range m.detail {
		out[k] = v
	}
	if len(m.coerced) > 0 {
		out["_coerced"] = slices.Sorted(slices.Values(m.coerced))
	}
	return out
}
