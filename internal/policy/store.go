package policy

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/nodarynet/nodary/internal/audit"
	"github.com/nodarynet/nodary/internal/identity"
)

// Active reads the profile in force.
//
// A fresh install has no row, and that absence means `default`
// (docs/specs/07-identity-audit.md §4). Seeding a row at migration time would
// claim somebody applied it while no audit record named who, so the default is
// resolved on read instead.
func Active(ctx context.Context, q interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}) (Profile, []byte, error) {
	var name, source string
	err := q.QueryRowContext(ctx, `SELECT name, source FROM policy WHERE singleton = 1`).
		Scan(&name, &source)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return Builtin(Default)
	case err != nil:
		return Profile{}, nil, fmt.Errorf("reading the active policy: %w", err)
	}

	p, err := Parse([]byte(source))
	if err != nil {
		// A stored profile that no longer parses is not something to paper
		// over: it means the posture in force cannot be stated, and a caller
		// about to check ceremony against it would be checking against a guess.
		return Profile{}, nil, fmt.Errorf("the stored %q profile no longer parses: %w", name, err)
	}
	return p, []byte(source), nil
}

// Apply replaces the active profile. It takes an audit.Mutation rather than a
// transaction, so it cannot be called without a record being written.
func Apply(ctx context.Context, m audit.Mutation, by identity.Role, now time.Time, p Profile, source []byte) error {
	if err := identity.Authorize(by, identity.PermPolicyApply); err != nil {
		return err
	}
	if _, err := m.Tx().ExecContext(ctx, `
		INSERT INTO policy (singleton, name, source, applied_at)
		VALUES (1, ?, ?, ?)
		ON CONFLICT (singleton) DO UPDATE SET
			name = excluded.name, source = excluded.source, applied_at = excluded.applied_at`,
		p.Name, string(source), now.UTC().Truncate(time.Millisecond).Format(audit.TimeFormat),
	); err != nil {
		return fmt.Errorf("applying the policy profile: %w", err)
	}

	// The source goes in the record, not just the name: a profile named
	// "default" that somebody edited is not the built-in one, and the chain is
	// where that distinction has to survive.
	m.Detail("profile", p.Name)
	m.Detail("source", string(source))
	return nil
}
