package identity

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/nodarynet/nodary/internal/audit"
)

// SetupTTL is how long a setup link lives. docs/specs/01-install.md §4 step 9.
//
// Fifteen minutes is short enough that a URL left in a terminal's scrollback is
// not a credential, and long enough to walk to another machine.
const SetupTTL = 15 * time.Minute

// KindSetup is the prefix a setup credential carries.
//
// **Deliberately not in Kinds.** The prefix exists for the reason every prefix
// in docs/specs/02-enrollment.md §4 exists — a leaked credential should be
// greppable in a log and recognisable to a secret scanner — but this is not a
// kind anybody may mint. `nodary token create --kind st` has to stay an error,
// and leaving it out of Kinds is what makes ParseKind and Valid refuse it.
const KindSetup Kind = "st"

// ErrSetupUnavailable is a setup link that cannot be redeemed: wrong, expired,
// or already spent.
//
// One error for all three, on purpose. The caller is unauthenticated, and
// telling it which of the three it holds is a way to learn whether a live
// setup link exists.
var ErrSetupUnavailable = errors.New("this setup link is not usable")

// ErrSetupDone is an installation that already has an administrator.
//
// Distinct from ErrSetupUnavailable because it is not a secret: anyone can see
// that a control plane is configured by being asked to log in, and an operator
// who reran an install needs to be told this rather than left wondering about
// their link.
var ErrSetupDone = errors.New("this control plane already has an administrator")

// MintSetup issues the one-time credential and returns the plaintext.
//
// It replaces any credential already outstanding. Re-running `server install`
// on a control plane nobody has finished setting up should hand the operator a
// working link, not leave them holding one from a previous run whose plaintext
// scrolled away — and the old one stops working the moment this returns, which
// is the safer half of that trade.
func MintSetup(ctx context.Context, m audit.Mutation, now time.Time) (string, time.Time, error) {
	users, err := List(ctx, m.Tx(), false)
	if err != nil {
		return "", time.Time{}, err
	}
	if len(users) > 0 {
		return "", time.Time{}, ErrSetupDone
	}

	plaintext, err := mintSecret(KindSetup)
	if err != nil {
		return "", time.Time{}, err
	}
	expires := truncateTime(now.Add(SetupTTL))
	if _, err := audit.Install(m.Tx(), now); err != nil {
		return "", time.Time{}, err
	}
	if _, err := m.Tx().ExecContext(ctx,
		`UPDATE installation SET setup_hash = ?, setup_expires_at = ? WHERE singleton = 1`,
		hashToken(plaintext), formatTime(expires),
	); err != nil {
		return "", time.Time{}, fmt.Errorf("issuing the setup credential: %w", err)
	}

	// The expiry, never the secret, and no display prefix either: unlike a
	// token an operator manages, this one is never listed or revoked by name,
	// so a partial plaintext in the chain would buy nothing for the risk.
	m.Detail("expires", formatTime(expires))
	return plaintext, expires, nil
}

// RedeemSetup spends the setup credential and creates the first administrator.
//
// **The UPDATE is the check.** The hash comparison, the expiry and the burn are
// one statement, so two callers arriving together cannot both succeed — the
// same reasoning RedeemJoinToken gives, and it matters more here because what
// is at stake is who administers the installation.
//
// The credential is the authority. There is no principal to authorise this and
// there cannot be one: it runs before any account exists. So it passes
// RoleAdmin to Add and SetPassword, and what stands behind that is the
// single-use secret plus the refusal below — an installation with a user is
// past setup, whatever anyone presents.
func RedeemSetup(ctx context.Context, m audit.Mutation, now time.Time,
	presented, name, email, password string) (User, error) {
	// First, because it is the answer worth giving. A spent installation is not
	// a secret, and "already set up" is what an operator needs to hear.
	users, err := List(ctx, m.Tx(), false)
	if err != nil {
		return User{}, err
	}
	if len(users) > 0 {
		return User{}, ErrSetupDone
	}

	res, err := m.Tx().ExecContext(ctx,
		`UPDATE installation SET setup_hash = NULL, setup_expires_at = NULL
		 WHERE singleton = 1 AND setup_hash = ? AND setup_expires_at > ?`,
		hashToken(presented), formatTime(now))
	if err != nil {
		return User{}, fmt.Errorf("redeeming the setup credential: %w", err)
	}
	spent, err := res.RowsAffected()
	if err != nil {
		return User{}, err
	}
	if spent == 0 {
		return User{}, fmt.Errorf("%w: it may have expired, or it may already have been used",
			ErrSetupUnavailable)
	}

	u, err := Add(ctx, m, RoleAdmin, now, name, email, RoleAdmin)
	if err != nil {
		return User{}, err
	}
	if err := SetPassword(ctx, m, RoleAdmin, name, password); err != nil {
		return User{}, err
	}
	return u, nil
}

// SetupPending reports whether a live setup credential is outstanding.
//
// For `server status` and doctor: an installation nobody has finished setting
// up is worth saying out loud, because the window closes silently and the only
// other symptom is a login that cannot be performed by anybody.
func SetupPending(ctx context.Context, q Querier, now time.Time) (bool, error) {
	var hash sql.NullString
	var expires sql.NullString
	err := q.QueryRowContext(ctx,
		`SELECT setup_hash, setup_expires_at FROM installation WHERE singleton = 1`).
		Scan(&hash, &expires)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return false, nil
	case err != nil:
		return false, fmt.Errorf("reading the setup credential: %w", err)
	}
	if !hash.Valid || !expires.Valid {
		return false, nil
	}
	at, err := time.Parse(audit.TimeFormat, expires.String)
	if err != nil {
		return false, fmt.Errorf("the setup expiry %q is unreadable: %w", expires.String, err)
	}
	return now.Before(at), nil
}
