package cli

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/nodarynet/nodary/internal/audit"
	"github.com/nodarynet/nodary/internal/identity"
)

// cmdModelStageReset is `model unstage` and `model restage` — both are the
// same underlying request, "discard what this node has for this model and
// let it re-stage from nothing" (internal/agent/remote.go's Downloader.Reset,
// R4-35/R4-36), told apart only by which precondition guards it.
//
// **`unstage` requires no deployment on this node still wants the model** —
// deleting weights out from under a live deployment is exactly the accident
// that precondition exists to prevent. **`restage` requires the observed
// state to be `corrupt`** — docs/specs/05-catalog.md §3 makes that state the
// one an explicit restage is for, not a general "redownload even though it's
// fine" button that could yank weights out from under a healthy deployment.
// And `restage` refuses `source: local` outright: VerifyStaged re-reads
// every byte from disk on every reconcile already, so there is nothing
// cached to reset — an operator whose media has a bad file needs to replace
// that file, not have nodary erase all of them.
//
// Neither writes to config.Snapshot, so neither calls config.Record: the
// request lives in its own table (`stage_reset`), consumed by the agent and
// acknowledged over the heartbeat (internal/observed.Heartbeat), the same
// shape join-token redemption already uses for a one-shot request the
// protocol's "no imperative commands" rule (docs/specs/03-agent.md §2) has
// no other way to express.
func cmdModelStageReset(e env, args []string, verb string) int {
	fs := newFlagSet(e, "model "+verb)
	dbPath, keyPath, credsPath := stateFlags(fs)
	cer := attestFlags(fs)
	format := formatFlag(fs)
	node := fs.String("node", "", "the node whose copy this affects")
	if code := parseFlags(e, fs, args); code >= 0 {
		return code
	}
	if !checkFormat(e, *format) {
		return ExitUsage
	}
	if fs.NArg() != 1 {
		fmt.Fprintf(e.stderr, "nodary model %s: expected one model id\n", verb)
		return ExitUsage
	}
	if *node == "" {
		fmt.Fprintf(e.stderr, "nodary model %s: --node is required; `nodary node list` names them\n", verb)
		return ExitUsage
	}
	id := fs.Arg(0)

	s, ok := openSession(e, "model "+verb, *dbPath, *keyPath, *credsPath)
	if !ok {
		return ExitFailure
	}
	defer s.Close()

	rec, applied, code := s.attested(e, "model "+verb, change{
		action: "model." + verb,
		target: &audit.Target{Kind: "model", ID: id},
		render: func(ctx context.Context, tx *sql.Tx) (any, error) {
			var source string
			if err := tx.QueryRowContext(ctx, `SELECT source FROM model WHERE id = ?`, id).Scan(&source); err != nil {
				if err == sql.ErrNoRows {
					return nil, fmt.Errorf("%w: no model named %q; `nodary model register` names it first",
						identity.ErrBadName, id)
				}
				return nil, err
			}

			var deployed bool
			if err := tx.QueryRowContext(ctx,
				`SELECT EXISTS(SELECT 1 FROM deployment WHERE model_id = ? AND node_name = ?)`,
				id, *node).Scan(&deployed); err != nil {
				return nil, err
			}

			if verb == "unstage" {
				if deployed {
					return nil, fmt.Errorf(
						"%s is still deployed on %s; remove its [[deployment]] and re-apply with --prune first",
						id, *node)
				}
			} else {
				if source != "remote" {
					return nil, fmt.Errorf(
						"%s is source: local; its weights are re-verified every reconcile already — "+
							"replace the bad file(s) under the node's models directory and the next poll reports it",
						id)
				}
				var stagingState string
				err := tx.QueryRowContext(ctx,
					`SELECT state FROM staging WHERE model_id = ? AND node_name = ?`, id, *node).Scan(&stagingState)
				if err == sql.ErrNoRows || stagingState != "corrupt" {
					return nil, fmt.Errorf(
						"%s on %s is not corrupt; restage is for the stuck state (docs/specs/05-catalog.md §3), "+
							"not a general redownload", id, *node)
				}
			}
			return map[string]any{"model": id, "node": *node, "deployed": deployed}, nil
		},
		apply: func(m audit.Mutation, _ any) error {
			if err := identity.Authorize(s.who.Role, identity.PermModelStage); err != nil {
				return err
			}
			if err := s.touch(m); err != nil {
				return err
			}
			_, err := m.Tx().ExecContext(context.Background(),
				`INSERT INTO stage_reset (node_name, model_id, requested_at) VALUES (?, ?, ?)
				 ON CONFLICT (node_name, model_id) DO UPDATE SET requested_at = excluded.requested_at`,
				*node, id, s.now.UTC().Format(audit.TimeFormat))
			return err
		},
	}, cer, *format)
	if !applied {
		return code
	}

	fmt.Fprintf(e.stderr, "model %s: %s on %s will be applied on the agent's next poll (up to 60s)\n",
		verb, id, *node)
	reportRecord(e, rec)
	return ExitOK
}
