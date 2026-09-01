package identity

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/nodarynet/nodary/internal/audit"
	"github.com/nodarynet/nodary/internal/paths"
	"github.com/nodarynet/nodary/internal/secret"
)

// The key binding of docs/specs/08-data-model.md §4, and R1-36's refusal.
//
// It lives here rather than in internal/secret because it needs both halves:
// the keyring, and audit's installation row, which is where the identifier is
// recorded and which only audit may mint. secret importing audit would put the
// crypto package downstream of the log; audit importing secret would put the
// log downstream of the crypto. This package already imports both, and in R1
// the only thing sealed is a TOTP seed, which is identity's.
//
// It moves when a second subsystem seals something -- R2-40's CA key is the
// first candidate -- and that is recorded as an open item rather than solved
// early by inventing a package for two functions with one caller.

// ErrKeyMismatch is R1-36: this database's secrets were sealed under a key
// this process does not have. It maps to exit code 1, and the message has to
// be the one an operator acts on, because the two states behind it are
// unrecoverable in opposite directions.
var ErrKeyMismatch = errors.New("this database was sealed under a different key")

// CheckKey refuses a keyring that cannot open what this database already holds.
//
// An unbound database passes: until something is sealed there is nothing to
// lose, and refusing one that simply predates the key would break every
// install that has not enrolled anybody.
//
// A recorded id the keyring merely knows -- a retired key passed to
// secret.Load -- also passes. That is what makes rotation possible: everything
// sealed so far still opens, and the binding advances when the last ciphertext
// has been resealed rather than when a new key appears.
func CheckKey(ctx context.Context, q Querier, k *secret.Key) error {
	recorded, err := boundKeyID(ctx, q)
	if err != nil || recorded == "" {
		return err
	}
	if recorded == k.ID() || k.Knows(recorded) {
		return nil
	}
	return fmt.Errorf(
		"%w: it names key %s and this one is %s.\n"+
			"  Restore the original %s, or pass the old key as a retired key.\n"+
			"  Replacing it makes every sealed value permanently unreadable",
		ErrKeyMismatch, recorded, k.ID(), paths.SecretKey())
}

// BindKey records the key that seals this database, on the first seal.
//
// Once recorded it is never rewritten here: advancing it means everything
// sealed under the old key has been resealed, which is a rotation and not a
// side effect of enrolling somebody.
func BindKey(ctx context.Context, tx *sql.Tx, now time.Time, k *secret.Key) error {
	if err := CheckKey(ctx, tx, k); err != nil {
		return err
	}
	// The row may not exist yet: on a fresh database the first seal happens
	// inside a mutation, and the audit record that would otherwise mint it is
	// written after the mutation returns.
	if _, err := audit.Install(tx, now); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx,
		`UPDATE installation SET secret_key_id = ?
		 WHERE singleton = 1 AND secret_key_id IS NULL`, k.ID()); err != nil {
		return fmt.Errorf("recording the key id: %w", err)
	}
	return nil
}

// BoundKeyID reports which key this database says sealed it, or "" for none.
func BoundKeyID(ctx context.Context, q Querier) (string, error) {
	return boundKeyID(ctx, q)
}

func boundKeyID(ctx context.Context, q Querier) (string, error) {
	var id sql.NullString
	err := q.QueryRowContext(ctx,
		`SELECT secret_key_id FROM installation WHERE singleton = 1`).Scan(&id)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return "", nil
	case err != nil:
		return "", fmt.Errorf("reading the recorded key id: %w", err)
	}
	return id.String, nil
}
