// Package replay stores what a request already answered, so a repeat returns it
// rather than acting twice (dev/specs/09-api.md §2's Idempotency-Key).
//
// **It writes outside audit.Log.Act, which is the one thing this codebase does
// not allow without saying why.** internal/observed holds the same exemption
// and states the same kind of reason: a row here records nothing an operator
// did. It records that an HTTP request arrived and what was already sent back
// for it — bookkeeping about a transport, like a session or a login counter,
// and the act it protects has its own record in the chain already. Writing an
// audit record per idempotency claim would bury a month of administration under
// retries of it, which is the argument 0006_fleet.sql makes for usage rows.
//
// So the rule this package lives under: **it writes the idempotency table and
// nothing else, ever.** A change here that touches another table is a mutation
// escaping the seam, and the exemption in TestNothingBypassesTheSeam is what
// makes that reviewable rather than invisible.
package replay

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/nodarynet/nodary/internal/audit"
	"github.com/nodarynet/nodary/internal/store"
)

// Window is dev/specs/09-api.md §2's 24h. Past it a key means nothing, and the
// row — which holds a sealed copy of a response, and for a token mint that
// response holds a credential — has no reason to exist.
const Window = 24 * time.Hour

var (
	// ErrKeyReused is one key used for two different requests. Replaying the
	// first response to the second would hide a client's bug behind a plausible
	// success.
	ErrKeyReused = errors.New("this Idempotency-Key was used for a different request")
	// ErrKeyInFlight is a key whose first request has not finished, or whose
	// outcome nobody knows.
	ErrKeyInFlight = errors.New("a request with this Idempotency-Key is still in flight or its outcome is unknown")
)

// Store is the idempotency table.
type Store struct {
	db  *store.DB
	now func() time.Time
}

func New(db *store.DB, now func() time.Time) *Store { return &Store{db: db, now: now} }

// Response is what a repeat gets back. Body is sealed; the caller unseals it.
type Response struct {
	Status int
	Body   []byte
}

// Claim takes a key for this request, or reports what taking it found.
//
// **The row is inserted before the handler runs, not after.** Recording the
// outcome afterwards would make this a cache of responses, and a cache does not
// stop the case that actually happens: a client whose request timed out retries
// while the first attempt is still working, and both mint a token. Inserting
// first turns the key into an exclusion, and the primary key enforces it.
//
// A nil Response with a nil error means the key is yours and the handler should
// run.
func (s *Store) Claim(ctx context.Context, key, who, request string) (*Response, error) {
	var out *Response
	err := s.db.WriteTx(ctx, func(tx *sql.Tx) error {
		now := s.now().UTC()
		cutoff := now.Add(-Window).Format(audit.TimeFormat)
		stamp := now.Format(audit.TimeFormat)
		insert := func() error {
			_, err := tx.ExecContext(ctx,
				`INSERT INTO idempotency (key, principal, request, status, response, created_at)
				 VALUES (?, ?, ?, 0, ?, ?)`, key, who, request, []byte{}, stamp)
			return err
		}

		var (
			haveRequest string
			status      int
			response    []byte
			createdAt   string
		)
		err := tx.QueryRowContext(ctx,
			`SELECT request, status, response, created_at FROM idempotency WHERE key = ? AND principal = ?`,
			key, who).Scan(&haveRequest, &status, &response, &createdAt)
		switch {
		case errors.Is(err, sql.ErrNoRows):
			return insert()
		case err != nil:
			return err
		case createdAt < cutoff:
			// The window has passed, so the key means nothing any more: this is
			// a new request that happens to reuse the string.
			if _, err := tx.ExecContext(ctx,
				`DELETE FROM idempotency WHERE key = ? AND principal = ?`, key, who); err != nil {
				return err
			}
			return insert()
		case haveRequest != request:
			return ErrKeyReused
		case status == 0:
			// In flight, or left behind by a process that died mid-request.
			// **Not reclaimed**: nobody knows whether that mutation committed,
			// and the safe guess is not "it did not" — that is how a second
			// token gets minted. The retry is told to look instead.
			return ErrKeyInFlight
		}
		out = &Response{Status: status, Body: response}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("claiming an idempotency key: %w", err)
	}
	return out, nil
}

// Finish records what was sent, so a repeat can be handed the same thing.
func (s *Store) Finish(ctx context.Context, key, who string, status int, sealed []byte) error {
	return s.db.WriteTx(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx,
			`UPDATE idempotency SET status = ?, response = ? WHERE key = ? AND principal = ?`,
			status, sealed, key, who)
		return err
	})
}

// Release frees a key whose request failed. A refused request has not happened,
// and its key should be usable again — otherwise one malformed attempt burns
// the key the client will retry with.
func (s *Store) Release(ctx context.Context, key, who string) error {
	return s.db.WriteTx(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx,
			`DELETE FROM idempotency WHERE key = ? AND principal = ? AND status = 0`, key, who)
		return err
	})
}
