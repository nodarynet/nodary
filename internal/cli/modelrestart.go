package cli

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"

	"github.com/nodarynet/nodary/internal/audit"
	"github.com/nodarynet/nodary/internal/fleet"
	"github.com/nodarynet/nodary/internal/identity"
)

// cmdModelRestart is `nodary model restart` — a one-shot "cycle this now"
// request with no declarative state to change (a deployment's params before
// and after a restart can be identical), so it follows cmdModelStageReset's
// shape exactly: it writes into its own table (`deployment_restart`),
// consumed by the agent and acknowledged over the heartbeat
// (internal/observed.Heartbeat), rather than through config.Record.
//
// **--node is mandatory here, unlike enable/disable.** A restart is
// inherently a single node's act — cycling a systemd unit — where
// enable/disable are a fleet-wide declarative toggle.
//
// Resolves to every deployment of this model on that node (not a single
// row — deployment.id is the only primary key, so replicas are possible) and
// restarts every one that is not disabled. A disabled one is skipped with a
// message, not a hard refusal: direct the operator to `enable` first rather
// than failing the whole request over one replica among several.
func cmdModelRestart(e env, args []string) int {
	fs := newFlagSet(e, "model restart")
	dbPath, keyPath, credsPath := stateFlags(fs)
	server := serverFlag(fs)
	cer := attestFlags(fs)
	format := formatFlag(fs)
	node := fs.String("node", "", "the node to restart it on")
	if code := parseFlags(e, fs, args); code >= 0 {
		return code
	}
	if !checkFormat(e, *format) {
		return ExitUsage
	}
	if fs.NArg() != 1 {
		fmt.Fprintf(e.stderr, "nodary model restart: expected one model id\n")
		return ExitUsage
	}
	if *node == "" {
		fmt.Fprintf(e.stderr, "nodary model restart: --node is required; `nodary node list` names them\n")
		return ExitUsage
	}
	id := fs.Arg(0)

	r, code := remoteFor(e, "model restart", *server, *credsPath, *dbPath, *keyPath)
	if code >= 0 {
		return code
	}
	if r != nil {
		out, applied, code := r.attested(e, "model restart", "POST",
			"/models/"+url.PathEscape(id)+"/restart?node="+url.QueryEscape(*node),
			nil, cer, *format)
		if !applied {
			return code
		}
		reportRestarted(e, id, *node, resultStrings(out.Result, "skipped_disabled"))
		reportRecord(e, audit.Record{Seq: out.AuditSeq})
		return ExitOK
	}

	s, ok := openSession(e, "model restart", *dbPath, *keyPath, *credsPath)
	if !ok {
		return ExitFailure
	}
	defer s.Close()

	var skippedDisabled []string
	rec, applied, code := s.attested(e, "model restart", change{
		action: "model.restart",
		target: &audit.Target{Kind: "model", ID: id},
		render: func(ctx context.Context, tx *sql.Tx) (any, error) {
			targets, skipped, err := fleet.RestartTargets(ctx, tx, id, *node)
			if err != nil {
				return nil, err
			}
			if len(targets) == 0 && len(skipped) == 0 {
				return nil, fmt.Errorf("%w: %q has no deployment on %s; `nodary node show %s` names them",
					identity.ErrBadName, id, *node, *node)
			}
			return map[string]any{"restart": targets, "skipped_disabled": skipped}, nil
		},
		apply: func(m audit.Mutation, _ any) error {
			if err := identity.Authorize(s.who.Role, identity.PermModelRestart); err != nil {
				return err
			}
			if err := s.touch(m); err != nil {
				return err
			}
			// Re-derived rather than trusting render's returned preview, the
			// same discipline cmdModelToggle's edit closure follows: apply
			// runs inside its own transaction and must not depend on a value
			// that only round-tripped through the preview shown on screen.
			targets, skipped, err := fleet.RestartTargets(context.Background(), m.Tx(), id, *node)
			if err != nil {
				return err
			}
			skippedDisabled = skipped
			return fleet.RequestRestart(context.Background(), m, s.now, *node, targets)
		},
	}, cer, *format)
	if !applied {
		return code
	}

	reportRestarted(e, id, *node, skippedDisabled)
	reportRecord(e, rec)
	return ExitOK
}

// reportRestarted names what will happen and what will not.
//
// A replica skipped for being disabled is named rather than left silent: an
// operator who asked for a restart and got one fewer than they have needs to
// know which, and why.
func reportRestarted(e env, id, node string, skippedDisabled []string) {
	fmt.Fprintf(e.stderr, "model restart: %s on %s will be applied on the agent's next poll (up to 60s)\n", id, node)
	for _, depID := range skippedDisabled {
		fmt.Fprintf(e.stderr, "%s is disabled; skipped — `nodary model enable %s --node %s` first\n",
			depID, id, node)
	}
}

// resultStrings reads a list of strings out of a mutation's result body.
func resultStrings(result map[string]any, field string) []string {
	raw, _ := result[field].([]any)
	out := make([]string, 0, len(raw))
	for _, v := range raw {
		if s, ok := v.(string); ok {
			out = append(out, s)
		}
	}
	return out
}
