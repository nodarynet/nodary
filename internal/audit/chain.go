package audit

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/nodarynet/nodary/internal/canonical"
	"github.com/nodarynet/nodary/internal/store"
)

// Entry is what a caller supplies to the chain.
//
// It carries no sequence, predecessor, installation or hash, so a caller cannot
// choose them even by mistake: those are assigned inside the transaction that
// writes the row, which is what makes docs/tasks/R1-core-audit-identity.md
// R1-07's guarantee hold across processes rather than only across goroutines.
type Entry struct {
	TS            time.Time
	Actor         Actor
	Source        Source
	Action        string
	Target        *Target
	IntentHash    string
	Justification string
	Outcome       Outcome
	Detail        map[string]any
}

// Append writes one record in its own transaction and returns it as stored.
func Append(ctx context.Context, db *store.DB, e Entry) (Record, error) {
	var r Record
	err := db.WriteTx(ctx, func(tx *sql.Tx) error {
		var err error
		r, err = AppendTx(tx, e)
		return err
	})
	if err != nil {
		return Record{}, err
	}
	return r, nil
}

// AppendTx writes one record inside an existing write transaction, so the
// record and the change it describes commit together or not at all.
//
// The tail is read here rather than by the caller: reading it outside the
// transaction is precisely the interleaving that lets two writers claim one
// sequence number.
func AppendTx(tx *sql.Tx, e Entry) (Record, error) {
	install, err := installID(tx, e.TS)
	if err != nil {
		return Record{}, err
	}
	seq, prev, err := tail(tx)
	if err != nil {
		return Record{}, err
	}

	r := Record{
		V:             Version,
		Install:       install,
		Seq:           seq + 1,
		TS:            e.TS.UTC().Truncate(time.Millisecond),
		Actor:         e.Actor,
		Source:        e.Source,
		Action:        e.Action,
		Target:        e.Target,
		IntentHash:    e.IntentHash,
		Justification: e.Justification,
		Outcome:       e.Outcome,
		Detail:        e.Detail,
		PrevHash:      prev,
	}
	if err := r.Validate(); err != nil {
		return Record{}, err
	}
	if r.Hash, err = r.Compute(); err != nil {
		return Record{}, err
	}

	// Stored canonical rather than through json.Marshal so the column holds one
	// stable form: the same detail always produces the same bytes, which is
	// what makes a CSV export and a diff of two databases meaningful. The hash
	// does not depend on it — it is taken over the decoded value either way.
	detail, err := r.detailJSON()
	if err != nil {
		return Record{}, err
	}

	var targetKind, targetID any
	if kind, id := r.targetFields(); r.Target != nil {
		targetKind, targetID = kind, id
	}
	_, err = tx.Exec(`
		INSERT INTO audit (seq, v, install, ts,
		                   actor_id, actor_method, actor_session,
		                   source_ip, source_version,
		                   action, target_kind, target_id,
		                   intent_hash, justification, outcome, detail_json,
		                   prev_hash, hash)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		r.Seq, r.V, r.Install, r.TS.Format(TimeFormat),
		nullable(r.Actor.ID), r.Actor.Method, nullable(r.Actor.Session),
		nullable(r.Source.IP), nullable(r.Source.Version),
		r.Action, targetKind, targetID,
		nullable(r.IntentHash), nullable(r.Justification), string(r.Outcome), string(detail),
		r.PrevHash, r.Hash)
	if err != nil {
		return Record{}, fmt.Errorf("writing audit record %d: %w", r.Seq, err)
	}
	return r, nil
}

// tail returns the sequence and hash of the last record, or 0 and the genesis
// hash for an empty chain.
func tail(tx *sql.Tx) (int64, string, error) {
	var seq int64
	var hash string
	err := tx.QueryRow(`SELECT seq, hash FROM audit ORDER BY seq DESC LIMIT 1`).Scan(&seq, &hash)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return 0, GenesisPrevHash, nil
	case err != nil:
		return 0, "", fmt.Errorf("reading the chain tail: %w", err)
	}
	return seq, hash, nil
}

// installID returns this appliance's identifier, minting one on first use.
//
// It runs inside the caller's write transaction, so two processes reaching a
// fresh database together cannot mint two: the loser sees the winner's row.
func installID(tx *sql.Tx, now time.Time) (string, error) {
	var id string
	err := tx.QueryRow(`SELECT id FROM installation WHERE singleton = 1`).Scan(&id)
	switch {
	case err == nil:
		return id, nil
	case !errors.Is(err, sql.ErrNoRows):
		return "", fmt.Errorf("reading the installation id: %w", err)
	}

	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("minting an installation id: %w", err)
	}
	id = "ins_" + hex.EncodeToString(raw[:])
	if _, err := tx.Exec(
		`INSERT INTO installation (singleton, id, created_at) VALUES (1, ?, ?)`,
		id, now.UTC().Truncate(time.Millisecond).Format(TimeFormat)); err != nil {
		return "", fmt.Errorf("recording the installation id: %w", err)
	}
	return id, nil
}

// columnNames is the row as stored, in schema order.
//
// One list, because three things depend on this order agreeing: the SELECT,
// scanRecord's argument order, and the CSV export's header. Two of those
// disagreeing produces data under the wrong heading rather than an error.
var columnNames = []string{
	"seq", "v", "install", "ts",
	"actor_id", "actor_method", "actor_session",
	"source_ip", "source_version",
	"action", "target_kind", "target_id",
	"intent_hash", "justification", "outcome", "detail_json",
	"prev_hash", "hash",
}

var columns = strings.Join(columnNames, ", ")

// scanRecord reads one row back into a Record.
//
// This has to be lossless. A field that does not survive the round trip makes
// the record re-hash differently and reports tampering that never happened,
// which is the one failure a tamper-detector must not have.
func scanRecord(rows interface{ Scan(...any) error }) (Record, error) {
	var (
		r                         Record
		ts, outcome, detailRaw    string
		actorID, actorSession     sql.NullString
		sourceIP, sourceVersion   sql.NullString
		targetKind, targetID      sql.NullString
		intentHash, justification sql.NullString
	)
	if err := rows.Scan(
		&r.Seq, &r.V, &r.Install, &ts,
		&actorID, &r.Actor.Method, &actorSession,
		&sourceIP, &sourceVersion,
		&r.Action, &targetKind, &targetID,
		&intentHash, &justification, &outcome, &detailRaw,
		&r.PrevHash, &r.Hash,
	); err != nil {
		return Record{}, err
	}

	parsed, err := time.Parse(TimeFormat, ts)
	if err != nil {
		return Record{}, fmt.Errorf("record %d has an unreadable ts %q: %w", r.Seq, ts, err)
	}
	r.TS = parsed
	r.Actor.ID, r.Actor.Session = actorID.String, actorSession.String
	r.Source.IP, r.Source.Version = sourceIP.String, sourceVersion.String
	r.IntentHash, r.Justification = intentHash.String, justification.String
	r.Outcome = Outcome(outcome)
	if targetKind.Valid {
		r.Target = &Target{Kind: targetKind.String, ID: targetID.String}
	}

	// UseNumber keeps the digits the column actually holds instead of a float64
	// approximation of them. For a value this package wrote it changes nothing,
	// because the column is already in canonical form. It matters for a value
	// this package did not write: 9007199254740993 decoded as a float64 becomes
	// ...992 and re-encodes as a perfectly ordinary number, so the only signal
	// left is a hash that does not match. As digits it is refused by name.
	dec := json.NewDecoder(strings.NewReader(detailRaw))
	dec.UseNumber()
	if err := dec.Decode(&r.Detail); err != nil {
		return Record{}, fmt.Errorf("record %d has unreadable detail: %w", r.Seq, err)
	}

	// The column has to be canonical, not merely decodable — the same
	// self-check ParseLine makes of a mirror line, because the two readers of
	// one record must not disagree about what is sound. The hash is taken over
	// the decoded value, so anything the decoder skips is invisible to it:
	// json.Decode stops at the end of the first value, and detail_json set to
	// `{"k":"v"}  {"injected":true}` decoded to the same map, re-hashed to the
	// stored hash, and verified. A tamper-detector cannot have a column it does
	// not look at.
	canon, err := canonical.EncodeJSON([]byte(detailRaw))
	if err != nil {
		return Record{}, fmt.Errorf("record %d has unreadable detail: %w", r.Seq, err)
	}
	if string(canon) != detailRaw {
		return Record{}, fmt.Errorf(
			"record %d has a detail that is not canonical; the column has been rewritten\n  stored: %s\n  canonical: %s",
			r.Seq, detailRaw, canon)
	}
	return r, nil
}
