package fleet

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/nodarynet/nodary/internal/audit"
	"github.com/nodarynet/nodary/internal/config"
	"github.com/nodarynet/nodary/internal/identity"
)

// The administrative states an operator moves a node between. A node reaches
// `pending` by enrolling and nothing here creates one.
const (
	StateApproved = "approved"
	StateDraining = "draining"
	StateDeparted = "departed"
)

// Permission is the authority a transition needs.
//
// **Revoke shares approval's permission rather than inventing one.**
// docs/specs/07-identity-audit.md §1 gives admin "node approval" as the
// node-lifecycle authority and names no separate revoke, and ejecting a node is
// that same authority exercised in the other direction. Drain is an operator's
// to do — it takes work off a machine without ending its membership.
func Permission(to string) identity.Permission {
	if to == StateDraining {
		return identity.PermNodeDrain
	}
	return identity.PermNodeApprove
}

// TransitionPreview is what an administrator is agreeing to.
//
// It carries the node's advertised offer and constraints because that is the
// agreement: core.Act hashes the preview into intent_hash and writes it into
// the record, which is docs/specs/02-enrollment.md §1's "neither side can later
// claim terms the other did not see" made structural — the terms are inside the
// hash the approver signed off, not in prose beside it.
func TransitionPreview(ctx context.Context, q config.Querier, name, to string) (map[string]any, error) {
	var from, offer, constraints string
	err := q.QueryRowContext(ctx,
		`SELECT state, offer_json, constraints_json FROM node WHERE name = ?`, name).
		Scan(&from, &offer, &constraints)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("%w: no node named %q; a node joins by enrolling", identity.ErrBadName, name)
	}
	if err != nil {
		return nil, err
	}
	return map[string]any{"node": name, "from": from, "to": to,
		"offer": decoded(offer), "constraints": decoded(constraints)}, nil
}

// Transition moves a node's administrative state inside a mutation.
//
// Here rather than in either front end because there is one set of rules about
// which columns move with the state, and two copies of them had already drifted:
// the API's copy wrote `state` alone for anything that was not an approval, so
// a revoke served over HTTP would have failed 0006_fleet.sql's CHECK pairing
// `departed` with a `departed_at` — the endpoint could not have worked.
//
// approvedBy is the acting user's id, or "" for a local principal.
func Transition(ctx context.Context, m audit.Mutation, now time.Time, name, to, approvedBy string) error {
	stamp := now.UTC().Format(audit.TimeFormat)
	var (
		query string
		args  []any
	)
	switch to {
	case StateApproved:
		// Both columns or neither: 0006_fleet.sql pairs them with a CHECK, and
		// a local invocation has an actor but no *account* —
		// docs/specs/07-identity-audit.md §1 makes local root a real principal
		// without a user row, and `approved_by` references one. So a console
		// approval records NULL for both and the chain carries who and when,
		// which is the authoritative record either way. Inventing a user id
		// would put a name in the fleet table that resolves to nothing.
		var by, at any
		if approvedBy != "" {
			by, at = approvedBy, stamp
		}
		query, args = `UPDATE node SET state = ?, approved_by = ?, approved_at = ? WHERE name = ?`,
			[]any{to, by, at, name}
	case StateDeparted:
		// Paired in a CHECK for the reason `failed` is paired with a
		// last_error: a machine that left the fleet without a date is a record
		// that cannot be read back as history, which is most of what keeping it
		// is for.
		query, args = `UPDATE node SET state = ?, departed_at = ? WHERE name = ?`,
			[]any{to, stamp, name}
	default:
		query, args = `UPDATE node SET state = ? WHERE name = ?`, []any{to, name}
	}
	if _, err := m.Tx().ExecContext(ctx, query, args...); err != nil {
		return fmt.Errorf("moving node %q to %s: %w", name, to, err)
	}
	return nil
}

// decoded renders a stored JSON column into a preview.
//
// A preview is hashed into intent_hash, and internal/canonical accepts a closed
// domain of Go types that json.RawMessage is deliberately not in. Unparseable
// text is returned as itself, so a malformed column shows up in the preview
// rather than disappearing from it.
func decoded(raw string) any {
	if raw == "" {
		return map[string]any{}
	}
	var v any
	if err := json.Unmarshal([]byte(raw), &v); err != nil {
		return raw
	}
	return v
}
