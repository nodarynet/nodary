package fleet

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/nodarynet/nodary/internal/audit"
	"github.com/nodarynet/nodary/internal/config"
	"github.com/nodarynet/nodary/internal/identity"
)

// `model unstage` and `model restage` are the same underlying request —
// "discard what this node has for this model and let it stage from nothing"
// (internal/agent's Downloader.Reset, R4-35/R4-36) — told apart only by which
// precondition guards it.
const (
	Unstage = "unstage"
	Restage = "restage"
)

// StageResetPreview is that precondition, and what an operator attests to.
//
// It lives here rather than in either front end because it is the whole of the
// decision: which model, on which node, and whether the state that verb is for
// actually holds. A copy of it beside the HTTP handler would be a second set
// of rules for the same act, and the one that drifts is always the one nobody
// is looking at — R2-34's constraint, and the reason `model restart` already
// reads from this package rather than from a query written twice.
//
// Every refusal carries a sentinel. A bare fmt.Errorf reaches an API client as
// a 500 with the message withheld, which is a refusal that names an operator's
// own mistake and then declines to say what it was.
func StageResetPreview(ctx context.Context, q config.Querier, verb, model, node string) (map[string]any, error) {
	var source string
	switch err := q.QueryRowContext(ctx,
		`SELECT source FROM model WHERE id = ?`, model).Scan(&source); {
	case errors.Is(err, sql.ErrNoRows):
		return nil, fmt.Errorf("%w: no model named %q; `nodary model register` names it first",
			identity.ErrNotFound, model)
	case err != nil:
		return nil, err
	}

	var deployed bool
	if err := q.QueryRowContext(ctx,
		`SELECT EXISTS(SELECT 1 FROM deployment WHERE model_id = ? AND node_name = ?)`,
		model, node).Scan(&deployed); err != nil {
		return nil, err
	}

	switch verb {
	case Unstage:
		// Deleting weights out from under a live deployment is exactly the
		// accident this precondition exists to prevent.
		if deployed {
			return nil, fmt.Errorf(
				"%w: %s is still deployed on %s; remove its [[deployment]] and re-apply with --prune first",
				identity.ErrBadTransition, model, node)
		}
	case Restage:
		// source: local has nothing cached to reset — VerifyStaged re-reads
		// every byte on every reconcile already — so erasing an operator's
		// air-gapped media over one bad file would be destructive rather than
		// corrective. Replacing the file is the fix, and the next poll sees it.
		if source != "remote" {
			return nil, fmt.Errorf(
				"%w: %s is source: local; its weights are re-verified every reconcile already — "+
					"replace the bad file(s) under the node's models directory and the next poll reports it",
				identity.ErrBadTransition, model)
		}
		// dev/specs/05-catalog.md §3 makes `corrupt` the state an explicit
		// restage is for. A general redownload button could yank weights out
		// from under a healthy deployment.
		var state string
		err := q.QueryRowContext(ctx,
			`SELECT state FROM staging WHERE model_id = ? AND node_name = ?`, model, node).Scan(&state)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return nil, err
		}
		if state != "corrupt" {
			return nil, fmt.Errorf(
				"%w: %s on %s is not corrupt; restage is for the stuck state "+
					"(dev/specs/05-catalog.md §3), not a general redownload",
				identity.ErrBadTransition, model, node)
		}
	default:
		return nil, fmt.Errorf("%w: %q is not a staging verb", identity.ErrBadName, verb)
	}
	return map[string]any{"model": model, "node": node, "deployed": deployed}, nil
}

// RequestStageReset records the request the agent picks up on its next poll.
//
// Its own table rather than a column on anything: nothing here writes to
// config.Snapshot, so nothing here records a revision. It is a one-shot
// request, which the protocol's "no imperative commands" rule
// (dev/specs/03-agent.md §2) has no other way to express.
func RequestStageReset(ctx context.Context, m audit.Mutation, now time.Time, model, node string) error {
	_, err := m.Tx().ExecContext(ctx,
		`INSERT INTO stage_reset (node_name, model_id, requested_at) VALUES (?, ?, ?)
		 ON CONFLICT (node_name, model_id) DO UPDATE SET requested_at = excluded.requested_at`,
		node, model, now.UTC().Format(audit.TimeFormat))
	return err
}
