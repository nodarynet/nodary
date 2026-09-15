package fleet

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
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
// dev/specs/07-identity-audit.md §1 gives admin "node approval" as the
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
// the record, which is dev/specs/02-enrollment.md §1's "neither side can later
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
		// dev/specs/07-identity-audit.md §1 makes local root a real principal
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

// RestartTargets is every deployment of a model on a node, split into what a
// restart names and what it skips because it is disabled.
//
// Used identically by the render (to show, and to refuse when nothing matched)
// and the apply (to write the rows), so the preview an operator approves and
// the act cannot disagree about what matched — and shared by `nodary model
// restart` and POST /models/{id}/restart for the same reason one node
// transition now serves both.
//
// A disabled deployment is **skipped rather than failing the request**: an
// operator restarting a model with several replicas should not have the whole
// thing refused because one of them is off. The caller reports what it skipped.
func RestartTargets(ctx context.Context, q config.Querier, model, node string) (targets, skipped []Replica, err error) {
	query := `SELECT id, node_name, disabled, state FROM deployment WHERE model_id = ?`
	args := []any{model}
	if node != "" {
		query += ` AND node_name = ?`
		args = append(args, node)
	}
	// **Ordered by node, then id**, so a roll of one model across several hosts
	// takes them in a fixed order. An order that varied between runs would make
	// "the roll stopped at the second replica" name a different machine each
	// time it was said.
	query += ` ORDER BY node_name, id`

	rows, err := q.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var r Replica
		var disabled bool
		if err := rows.Scan(&r.ID, &r.Node, &disabled, &r.State); err != nil {
			return nil, nil, err
		}
		if disabled {
			skipped = append(skipped, r)
			continue
		}
		targets = append(targets, r)
	}
	return targets, skipped, rows.Err()
}

// Replica is one deployment of a model, on the node holding it.
//
// The node travels with the id because a roll spans hosts: a restart request is
// keyed by (node, deployment), and a model's replicas are on different machines
// by definition — putting two on one node buys no availability.
type Replica struct {
	ID    string
	Node  string
	State string
}

// Ready reports whether this replica is serving.
func (r Replica) Ready() bool { return r.State == "ready" }

// ReadyReplicas counts the deployments of a model that are serving right now.
//
// It is what --allow-downtime is decided against: 03 §7 requires a rolling
// restart never to drop the last ready replica, and with fewer than two there
// is no ordering that keeps one up. The count is fleet-wide even when --node
// narrows the restart, because the question is whether the *model* stays
// answerable, not whether one host does.
func ReadyReplicas(ctx context.Context, q config.Querier, model string) (int, error) {
	var n int
	err := q.QueryRowContext(ctx,
		`SELECT count(*) FROM deployment
		 WHERE model_id = ? AND state = 'ready' AND disabled = 0`, model).Scan(&n)
	return n, err
}

// RequestRestart records that these deployments should be cycled on their next
// reconcile. Edge-triggered, so it writes its own table rather than the
// configuration: a restart has no declarative change behind it, and the params
// before and after can be identical.
func RequestRestart(ctx context.Context, m audit.Mutation, now time.Time,
	rollID string, replicas []Replica) error {
	stamp := now.UTC().Format(audit.TimeFormat)
	for i, r := range replicas {
		// The whole roll is written in one transaction and offered one at a
		// time. Writing them as the roll progressed would need a process to
		// stay alive across minutes of restarts and would leave a half-written
		// roll behind whenever one was interrupted; the ordering lives in the
		// rows instead, and the control plane reads it on every poll.
		if _, err := m.Tx().ExecContext(ctx,
			`INSERT INTO deployment_restart
			   (node_name, deployment_id, requested_at, roll_id, sequence)
			 VALUES (?, ?, ?, ?, ?)
			 ON CONFLICT (node_name, deployment_id) DO UPDATE SET
			   requested_at = excluded.requested_at,
			   roll_id      = excluded.roll_id,
			   sequence     = excluded.sequence`,
			r.Node, r.ID, stamp, rollID, i); err != nil {
			return fmt.Errorf("requesting a restart of %s: %w", r.ID, err)
		}
	}
	return nil
}

// RollID names one operator's decision to cycle a model, so the replicas of it
// can be ordered against each other and not against somebody else's.
func RollID(now time.Time) string {
	return "roll_" + strconv.FormatInt(now.UTC().UnixNano(), 36)
}

// ErrWouldDropTheModel is a roll that cannot keep the model answerable.
var ErrWouldDropTheModel = errors.New("this would stop the model everywhere")

// AllowRoll is dev/specs/03-agent.md §7's "fewer than two replicas requires
// --allow-downtime".
//
// The refusal is not paternalism and it is not always right — restarting a
// single-replica model is an ordinary thing to do on a fleet nobody is serving
// from yet. What it prevents is doing it *without noticing*: the same command
// is safe on a model with four replicas and an outage on a model with one, and
// which of those you have is not visible in the command you typed.
//
// Counted fleet-wide even when the roll is narrowed to one node, because the
// question is whether the model stays answerable rather than whether one host
// does.
func AllowRoll(model string, ready, restarting int, allowDowntime bool) error {
	if allowDowntime || ready >= 2 {
		return nil
	}
	if restarting == 0 {
		return nil
	}
	switch ready {
	case 0:
		// Nothing is serving, so nothing can be dropped. Permitted, because
		// refusing here would make a model that is already down impossible to
		// restart — which is the state somebody most wants to restart out of.
		return nil
	}
	return fmt.Errorf("%w: %q has one replica serving and this restarts it. "+
		"Pass --allow-downtime to accept the gap, or add a replica first",
		ErrWouldDropTheModel, model)
}

// ReplicaIDs is the deployment ids of these replicas, for a preview or a report.
func ReplicaIDs(rs []Replica) []string {
	out := make([]string, len(rs))
	for i, r := range rs {
		out[i] = r.ID
	}
	return out
}

// OfferedRestarts is the restart requests a node may act on right now.
//
// **One replica of a roll at a time** (R4-22). A request is withheld while any
// earlier one in the same roll is still outstanding, and a row stays
// outstanding until the node has cycled the unit *and* the deployment is
// serving again — so the next node does not start stopping its copy until this
// one is back. The control plane is the only place that can enforce that,
// because it is the only place that sees every node: dev/specs/03-agent.md §1
// gives it no way to push, so what it does instead is decline to *offer* the
// next restart.
//
// A roll that stalls therefore stops where it stands rather than continuing.
// The row of the replica that did not come back is never cleared, nothing after
// it is ever offered, and the remainder keeps serving — which is §7's "halt,
// leave remainder running" with nothing to implement.
//
// An empty roll_id is a restart nobody asked to be rolled, and those never
// block each other.
func OfferedRestarts(ctx context.Context, q config.Querier, node string) ([]string, error) {
	rows, err := q.QueryContext(ctx,
		`SELECT r.deployment_id FROM deployment_restart r
		 WHERE r.node_name = ?
		   AND NOT EXISTS (
		     SELECT 1 FROM deployment_restart e
		      WHERE e.roll_id = r.roll_id AND e.roll_id <> '' AND e.sequence < r.sequence)
		 ORDER BY r.deployment_id`, node)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}
