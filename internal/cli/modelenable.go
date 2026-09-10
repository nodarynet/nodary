package cli

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/nodarynet/nodary/internal/audit"
	"github.com/nodarynet/nodary/internal/config"
	"github.com/nodarynet/nodary/internal/identity"
)

// cmdModelToggle is `nodary model enable`/`disable` — toggling an existing
// deployment without re-registering anything. `nodary model register`
// (already built) does everything docs/specs/05-catalog.md §4 describes for
// *creating* one, so this is only the on/off switch register never needed.
//
// **Resolves to every deployment naming this model, not to one row.**
// `deployment.id` is the only primary key on that table — nothing stops two
// deployments of one model on one node (replicas) — so treating (model,
// node) as naming a single row would be wrong, and `--node` stays optional
// (fleet-wide when omitted) exactly as docs/specs/05-catalog.md §4's own
// example shows it: `nodary model disable google/gemma-4-31b-it [--node
// gpu-01]`.
func cmdModelToggle(e env, args []string, verb string, disabled bool) int {
	fs := newFlagSet(e, "model "+verb)
	dbPath, keyPath, credsPath := stateFlags(fs)
	cer := attestFlags(fs)
	format := formatFlag(fs)
	node := fs.String("node", "", "limit to one node; every node this model is deployed on otherwise")
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
	id := fs.Arg(0)

	s, ok := openSession(e, "model "+verb, *dbPath, *keyPath, *credsPath)
	if !ok {
		return ExitFailure
	}
	defer s.Close()

	perm := identity.PermModelEnable
	if disabled {
		perm = identity.PermModelDisable
	}

	// Read once here, applied identically inside render (for the preview) and
	// apply (for the bound mutation) — the same double-read shape
	// cmdLimitsSet uses, since attest.Render runs twice by contract.
	edit := func(snap *config.Snapshot) (matched int) {
		for i := range snap.Deployments {
			if snap.Deployments[i].ModelID != id {
				continue
			}
			if *node != "" && snap.Deployments[i].NodeName != *node {
				continue
			}
			snap.Deployments[i].Disabled = disabled
			matched++
		}
		return matched
	}

	rec, applied, code := s.attested(e, "model "+verb, change{
		action: "model." + verb,
		target: &audit.Target{Kind: "model", ID: id},
		render: func(ctx context.Context, tx *sql.Tx) (any, error) {
			have, err := config.Read(ctx, tx)
			if err != nil {
				return nil, err
			}
			next, err := config.Read(ctx, tx)
			if err != nil {
				return nil, err
			}
			if matched := edit(next); matched == 0 {
				return nil, fmt.Errorf("%w: %q has no deployment%s; `nodary node show` names them",
					identity.ErrBadName, id, onNode(*node))
			}
			return map[string]any{"changes": config.Changes(have, next)}, nil
		},
		apply: func(m audit.Mutation, _ any) error {
			if err := identity.Authorize(s.who.Role, perm); err != nil {
				return err
			}
			if err := s.touch(m); err != nil {
				return err
			}
			next, err := config.Read(context.Background(), m.Tx())
			if err != nil {
				return err
			}
			edit(next)
			if _, err := config.Apply(context.Background(), m, s.now, next, config.Options{}); err != nil {
				return err
			}
			_, err = config.Record(context.Background(), m, s.now, s.who.Actor.ID, *cer.justify)
			return err
		},
	}, cer, *format)
	if !applied {
		return code
	}

	fmt.Fprintf(e.stderr, "model %s: %s will be applied on the agent's next poll (up to 60s)\n", verb, id)
	reportRecord(e, rec)
	return ExitOK
}

func onNode(node string) string {
	if node == "" {
		return ""
	}
	return " on " + node
}
