// Package audit implements the tamper-evident chain of
// docs/specs/07-identity-audit.md §3: one record per action, each hashed over
// its canonical JSON and carrying the hash of its predecessor.
//
// The chain does not prevent tampering; it makes tampering detectable. A
// compromised control plane can rewrite the whole chain consistently, which is
// why the spec also has the records leave the machine.
//
// Every byte a record hashes comes from internal/canonical (RFC 8785), so the
// same record hashes identically across processes, architectures and Go
// versions. Changing what a record contains, or how it is shaped, invalidates
// history that was never tampered with — so the field set is versioned rather
// than assumed permanent. See Version.
package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/nodarynet/nodary/internal/canonical"
)

// Version is the record schema version, carried in every record as "v".
//
// A field set that can never grow will eventually be wrong; one that grows
// without a version is unverifiable, because re-encoding an older record under
// a newer shape changes its hash and reports tampering that never happened.
// Carrying the version costs three bytes and means a later field addition
// leaves every existing record verifying under the builder that made it.
const Version = 1

// TimeFormat is the only shape a record timestamp takes: RFC3339, always UTC,
// always exactly three fractional digits.
//
// Go's time.Time marshalling trims trailing zeros, so two records written in
// the same second would otherwise hash under two different formats. Being
// fixed-width and UTC also makes lexicographic order chronological order, which
// is what lets --from and --to be string comparisons against an indexed column.
const TimeFormat = "2006-01-02T15:04:05.000Z"

// GenesisPrevHash is the prev_hash of the first record in a chain.
//
// Sixty-four zeros rather than empty or null, so prev_hash is a 64-character
// lowercase hex string in every record and verification needs no special case
// at seq 1.
const GenesisPrevHash = "0000000000000000000000000000000000000000000000000000000000000000"

// Outcome is docs/specs/07-identity-audit.md §3's outcome column.
type Outcome string

const (
	// OutcomeSuccess: the change was applied.
	OutcomeSuccess Outcome = "success"
	// OutcomeFailure: nothing changed.
	OutcomeFailure Outcome = "failure"
	// OutcomePartial: the change reached somewhere the transaction does not
	// cover — a node, a systemd unit — and cannot be undone by rolling back.
	OutcomePartial Outcome = "partial"
)

// Actor is who acted: docs/specs/07-identity-audit.md §3's "user id,
// authentication method, session id".
//
// Method is what disambiguates the ID's namespace. A local root CLI invocation
// is {ID: "root", Method: "local"}; an authenticated operator is an opaque
// usr_ identifier with a session.
type Actor struct {
	ID      string
	Method  string
	Session string
}

// Source is where the action came from: client address and client version.
// Both are empty for a local CLI invocation, which has neither.
type Source struct {
	IP      string
	Version string
}

// Target is what was acted on. A nil *Target encodes as null, for actions that
// have no target.
type Target struct {
	Kind string
	ID   string
}

// Record is one audit record.
//
// Hash is excluded from the bytes it is computed over; everything else,
// including PrevHash, is included.
type Record struct {
	V             int
	Install       string
	Seq           int64
	TS            time.Time
	Actor         Actor
	Source        Source
	Action        string
	Target        *Target
	IntentHash    string
	Justification string
	Outcome       Outcome
	Detail        map[string]any
	PrevHash      string
	Hash          string
}

// members is the record as the object it hashes and serialises as.
//
// This is the only place the field names exist. The hash preimage is this map
// minus "hash"; the sink line and the JSONL export are this map whole. Keeping
// them as one function is what stops the two from drifting — and the failure
// mode of drift is that hashes silently stop matching for records carrying one
// particular field, which reads as tampering.
//
// An unset optional is null, never absent and never "". Absent, null and empty
// are three different hashes, and none of these fields has a meaningful empty
// value: an actor with an id of "" is an actor with no id.
func (r Record) members() map[string]any {
	detail := make(map[string]any, len(r.Detail))
	for k, v := range r.Detail {
		detail[k] = v
	}

	var target any
	if r.Target != nil {
		target = map[string]any{
			"kind": nullable(r.Target.Kind),
			"id":   nullable(r.Target.ID),
		}
	}

	return map[string]any{
		"v":       r.V,
		"install": r.Install,
		"seq":     r.Seq,
		"ts":      r.TS.UTC().Format(TimeFormat),
		"actor": map[string]any{
			"id":      nullable(r.Actor.ID),
			"method":  nullable(r.Actor.Method),
			"session": nullable(r.Actor.Session),
		},
		"source": map[string]any{
			"ip":      nullable(r.Source.IP),
			"version": nullable(r.Source.Version),
		},
		"action":        r.Action,
		"target":        target,
		"intent_hash":   nullable(r.IntentHash),
		"justification": nullable(r.Justification),
		"outcome":       string(r.Outcome),
		"detail":        detail,
		"prev_hash":     r.PrevHash,
		"hash":          nullable(r.Hash),
	}
}

// detailJSON is the record's detail as the column stores it and the CSV export
// writes it.
//
// members() is documented as the only place the field names live, and reaching
// into it by string literal from two other files defeated that: rename the
// member and neither site fails to compile — canonical.Encode(nil) returns
// "null", and every row's detail_json silently becomes the string null while
// the hash, taken over the whole map, still verifies.
func (r Record) detailJSON() ([]byte, error) {
	b, err := canonical.Encode(r.members()["detail"])
	if err != nil {
		return nil, fmt.Errorf("encoding detail of record %d: %w", r.Seq, err)
	}
	return b, nil
}

// targetFields is the target flattened into its two columns. A Target is
// all-or-nothing — Validate refuses a half-set one — so this is the one place
// that decides what "no target" looks like in a row.
func (r Record) targetFields() (kind, id string) {
	if r.Target == nil {
		return "", ""
	}
	return r.Target.Kind, r.Target.ID
}

func nullable(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// Preimage is the canonical JSON a record's hash is taken over: every field
// except the hash itself.
func (r Record) Preimage() ([]byte, error) {
	m := r.members()
	delete(m, "hash")
	b, err := canonical.Encode(m)
	if err != nil {
		return nil, fmt.Errorf("encoding record %d: %w", r.Seq, err)
	}
	return b, nil
}

// Compute returns the hash a record should carry, as lowercase hex.
//
// Named Compute rather than Hash because Record already has a Hash field, and a
// field and a method of the same name is a collision that gets resolved in the
// wrong direction sooner or later.
func (r Record) Compute() (string, error) {
	b, err := r.Preimage()
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

// Line is the record as one canonical JSON object: what a sink emits and what
// `audit export --format jsonl` writes. No trailing newline.
func (r Record) Line() ([]byte, error) {
	if r.Hash == "" {
		return nil, fmt.Errorf("record %d has no hash: it has not been chained", r.Seq)
	}
	b, err := canonical.Encode(r.members())
	if err != nil {
		return nil, fmt.Errorf("encoding record %d: %w", r.Seq, err)
	}
	return b, nil
}

// ErrInvalidRecord is returned by Validate.
var ErrInvalidRecord = errors.New("audit record is not well formed")

var hexHash = regexp.MustCompile(`^[0-9a-f]{64}$`)

// Validate rejects a record that must not enter the chain.
//
// It runs before the row is written rather than relying on the table's CHECK
// constraints alone, so the error names the field rather than surfacing as
// "CHECK constraint failed" with a constraint the caller has never read.
func (r Record) Validate() error {
	switch {
	case r.V <= 0:
		return fmt.Errorf("%w: v is %d", ErrInvalidRecord, r.V)
	case r.Install == "":
		return fmt.Errorf("%w: install is empty", ErrInvalidRecord)
	case r.Seq <= 0:
		return fmt.Errorf("%w: seq is %d", ErrInvalidRecord, r.Seq)
	case r.TS.IsZero():
		return fmt.Errorf("%w: ts is unset", ErrInvalidRecord)
	case r.Actor.Method == "":
		return fmt.Errorf("%w: actor method is empty", ErrInvalidRecord)
	case r.Action == "":
		return fmt.Errorf("%w: action is empty", ErrInvalidRecord)
	case r.Outcome != OutcomeSuccess && r.Outcome != OutcomeFailure && r.Outcome != OutcomePartial:
		return fmt.Errorf("%w: outcome %q is not success, failure or partial", ErrInvalidRecord, r.Outcome)
	case !hexHash.MatchString(r.PrevHash):
		return fmt.Errorf("%w: prev_hash %q is not 64 lowercase hex characters", ErrInvalidRecord, r.PrevHash)
	}
	// A half-set target cannot be distinguished from null on the way back out
	// of the database, so it is refused on the way in. The table carries the
	// same rule as a CHECK; this is the half that can name the field.
	if r.Target != nil && (r.Target.Kind == "" || r.Target.ID == "") {
		return fmt.Errorf("%w: target has kind %q and id %q; it needs both or neither",
			ErrInvalidRecord, r.Target.Kind, r.Target.ID)
	}
	return nil
}
