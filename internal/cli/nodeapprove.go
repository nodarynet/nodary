package cli

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"

	"github.com/nodarynet/nodary/internal/agent"
	"github.com/nodarynet/nodary/internal/audit"
	"github.com/nodarynet/nodary/internal/config"
	"github.com/nodarynet/nodary/internal/identity"
)

// cmdNodeTransition is `node approve` and `node drain`.
//
// **The install tells the operator to run this.** `node install` closes with
// "It is pending and will receive no work until an administrator runs `nodary
// node approve <name>`", and that verb was a stub — approval existed only over
// the HTTP API, which on a single box means an administrator account, a token,
// and curl, to move a machine that is already sitting there. Found the first
// time a model was deployed: everything applied, the node stayed `pending`, and
// `agent plan` correctly showed nothing to do.
//
// It builds the same change the API's handler does rather than a second one.
// The preview carries the node's advertised offer and constraints because that
// is what the administrator is agreeing to, and core.Act hashes the preview
// into `intent_hash` — which is how docs/specs/02-enrollment.md §1's "neither
// side can later claim terms the other did not see" is structural rather than
// prose.
func cmdNodeTransition(e env, args []string, verb, to string) int {
	fs := newFlagSet(e, "node "+verb)
	dbPath, keyPath, credsPath := stateFlags(fs)
	cer := attestFlags(fs)
	format := formatFlag(fs)
	if code := parseFlags(e, fs, args); code >= 0 {
		return code
	}
	if !checkFormat(e, *format) {
		return ExitUsage
	}
	if fs.NArg() != 1 {
		fmt.Fprintf(e.stderr, "nodary node %s: expected one node name\n", verb)
		return ExitUsage
	}
	name := fs.Arg(0)

	s, ok := openSession(e, "node "+verb, *dbPath, *keyPath, *credsPath)
	if !ok {
		return ExitFailure
	}
	defer s.Close()

	// Revoke shares approval's permission rather than inventing one:
	// docs/specs/07-identity-audit.md §1 gives admin "node approval" as the
	// node-lifecycle authority and names no separate revoke, and ejecting a
	// node is that same authority exercised in the other direction. Drain is
	// an operator's to do — it takes work off a machine without ending its
	// membership.
	perm := identity.PermNodeApprove
	if verb == "drain" {
		perm = identity.PermNodeDrain
	}

	var from string
	rec, applied, code := s.attested(e, "node "+verb, change{
		action: "node." + verb,
		target: &audit.Target{Kind: "node", ID: name},
		render: func(ctx context.Context, tx *sql.Tx) (any, error) {
			var offer, constraints string
			err := tx.QueryRowContext(ctx,
				`SELECT state, offer_json, constraints_json FROM node WHERE name = ?`, name).
				Scan(&from, &offer, &constraints)
			if err == sql.ErrNoRows {
				return nil, fmt.Errorf("%w: no node named %q; a node joins by enrolling",
					identity.ErrBadName, name)
			}
			if err != nil {
				return nil, err
			}
			return map[string]any{"node": name, "from": from, "to": to,
				"offer": decodedJSONText(offer), "constraints": decodedJSONText(constraints)}, nil
		},
		apply: func(m audit.Mutation, _ any) error {
			if err := identity.Authorize(s.who.Role, perm); err != nil {
				return err
			}
			if err := s.touch(m); err != nil {
				return err
			}
			// Both columns or neither: 0006_fleet.sql pairs them with a CHECK,
			// and a local invocation has an actor but no *account* —
			// docs/specs/07-identity-audit.md §1 makes local root a real
			// principal without a user row, and `approved_by` references one.
			//
			// So a console approval records NULL for both and the audit chain
			// carries who and when, which is the authoritative record either
			// way. Inventing a user id to fill the column would put a name in
			// the fleet table that resolves to nothing.
			by, at := approverID(s.who), any(nil)
			if by != nil {
				at = s.now.UTC().Format(audit.TimeFormat)
			}
			switch to {
			case "approved":
				if _, err := m.Tx().ExecContext(context.Background(),
					`UPDATE node SET state = ?, approved_by = ?, approved_at = ? WHERE name = ?`,
					to, by, at, name); err != nil {
					return err
				}
			case "departed":
				// 0006_fleet.sql pairs the two in a CHECK, for the reason it
				// pairs `failed` with a last_error: a machine that left the
				// fleet without a date is a record that cannot be read back
				// as history, which is most of what keeping it is for.
				if _, err := m.Tx().ExecContext(context.Background(),
					`UPDATE node SET state = ?, departed_at = ? WHERE name = ?`,
					to, s.now.UTC().Format(audit.TimeFormat), name); err != nil {
					return err
				}
			default:
				if _, err := m.Tx().ExecContext(context.Background(),
					`UPDATE node SET state = ? WHERE name = ?`, to, name); err != nil {
					return err
				}
			}
			// `node.state` is in the configuration snapshot, so this is a
			// configuration change and records a revision like any other.
			// Without it the chain has a hole — and because the agent's
			// long-poll compares against that sequence, **an approved node
			// would not learn it had been approved** until something unrelated
			// moved the counter.
			_, err := config.Record(context.Background(), m, s.now, s.who.Actor.ID, *cer.justify)
			return err
		},
	}, cer, *format)
	if !applied {
		return code
	}

	fmt.Fprintf(e.stderr, "node %s: %s -> %s\n", name, from, to)
	if verb == "revoke" {
		// What actually happens now, because none of it is obvious and all of
		// it is already built: docs/specs/02-enrollment.md §3 refuses the
		// certificate on next contact (internal/api's agentNode), a node that
		// is not approved receives an empty desired state and so stops
		// everything within a poll, and the gateway stops routing to it
		// (internal/gateway's ConfigFor).
		fmt.Fprintf(e.stderr,
			"  Its certificate is refused from now on, it stops serving within a poll,\n"+
				"  and its deployments leave their routes on the next `nodary gateway sync`.\n"+
				"  Its history is kept. Rejoining is a fresh enrollment.\n")
	}
	if to == "approved" {
		fmt.Fprintf(e.stderr, "  It will receive its desired state on the agent's next poll.\n")
		if s.who.User.ID == "" {
			fmt.Fprintf(e.stderr,
				"  Approved locally, so the node row names no approver; the chain records who and when.\n")
		}
		// The next step, named. An approved node with nothing placed on it is
		// idle, healthy and indistinguishable from a broken one — and this verb
		// was where every printed instruction in the product ran out.
		fmt.Fprintf(e.stderr,
			"\nNothing is placed on it yet. With weights staged under %s:\n"+
				"  nodary model register <org/name> --node %s --gpu 0 --port 8001\n",
			agent.DefaultModelsDir(), name)
	}
	reportRecord(e, rec)
	return ExitOK
}

// approverID is who approved, or NULL for a local invocation.
//
// A local root action has no user row — docs/specs/07-identity-audit.md §1
// makes it a real principal without an account — and `approved_by` references
// one. NULL rather than a placeholder: the audit record carries the actor
// either way, and inventing a user id here would put a name in the fleet table
// that resolves to nothing.
func approverID(p identity.Principal) any {
	if p.User.ID == "" {
		return nil
	}
	return p.User.ID
}

// decodedJSONText renders a stored JSON column into the preview.
//
// Decoded rather than passed through as a string: the preview is what the
// administrator reads and what gets hashed into `intent_hash`, and an escaped
// blob is neither reviewable nor stable to look at.
func decodedJSONText(raw string) any {
	if raw == "" {
		return map[string]any{}
	}
	var v any
	if err := json.Unmarshal([]byte(raw), &v); err != nil {
		return raw
	}
	return v
}
