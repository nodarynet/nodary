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
// **It rolls** (R4-22): the replicas are cycled one at a time, and the next is
// not offered to its node until the one before it is serving again. The
// sequencing is enforced by the control plane rather than by this command,
// because replicas of one model live on different hosts and no agent can see
// another's — so the verb returns as soon as the roll is recorded, and the
// fleet works through it.
//
// **--node is optional**, and it used to be required on the reasoning that a
// restart is one node's act. That is true of cycling a unit and false of the
// thing dev/specs/03-agent.md §7 describes, which iterates over the replicas
// of a *model* and is where the "never drops the last ready replica" guarantee
// comes from. Named, it narrows the roll to one host's copies; omitted, it
// takes every replica.
//
// A disabled replica is skipped with a message, not a hard refusal: direct the
// operator to `enable` first rather than failing the whole request over one
// among several.
func cmdModelRestart(e env, args []string) int {
	fs := newFlagSet(e, "model restart")
	dbPath, keyPath, credsPath := stateFlags(fs)
	server := serverFlag(fs)
	cer := attestFlags(fs)
	format := formatFlag(fs)
	node := fs.String("node", "", "limit the roll to one node; every replica otherwise")
	allowDowntime := fs.Bool("allow-downtime", false,
		"restart even though fewer than two replicas are serving")
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
	id := fs.Arg(0)

	r, code := remoteFor(e, "model restart", *server, *credsPath, *dbPath, *keyPath)
	if code >= 0 {
		return code
	}
	if r != nil {
		path := "/models/" + url.PathEscape(id) + "/restart"
		if *node != "" {
			path = addQuery(path, "node="+url.QueryEscape(*node))
		}
		if *allowDowntime {
			path = addQuery(path, "allow_downtime=true")
		}
		out, applied, code := r.attested(e, "model restart",
			remoteAct{method: "POST", path: path}, cer, *format)
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
	plan := func(ctx context.Context, tx *sql.Tx) (targets, skipped []fleet.Replica, ready int, err error) {
		if targets, skipped, err = fleet.RestartTargets(ctx, tx, id, *node); err != nil {
			return nil, nil, 0, err
		}
		if len(targets) == 0 && len(skipped) == 0 {
			return nil, nil, 0, fmt.Errorf(
				"%w: %q has no deployment%s; `nodary node show` names them",
				identity.ErrNotFound, id, onNode(*node))
		}
		if ready, err = fleet.ReadyReplicas(ctx, tx, id); err != nil {
			return nil, nil, 0, err
		}
		return targets, skipped, ready, fleet.AllowRoll(id, ready, len(targets), *allowDowntime)
	}

	rec, applied, code := s.attested(e, "model restart", change{
		action: "model.restart",
		target: &audit.Target{Kind: "model", ID: id},
		render: func(ctx context.Context, tx *sql.Tx) (any, error) {
			targets, skipped, ready, err := plan(ctx, tx)
			if err != nil {
				return nil, err
			}
			return map[string]any{"restart": fleet.ReplicaIDs(targets),
				"skipped_disabled": fleet.ReplicaIDs(skipped),
				"ready_replicas":   ready, "allow_downtime": *allowDowntime}, nil
		},
		apply: func(m audit.Mutation, _ any) error {
			if err := identity.Authorize(s.who.Role, identity.PermModelRestart); err != nil {
				return err
			}
			if err := s.touch(m); err != nil {
				return err
			}
			// Re-planned rather than trusting render's returned preview, the
			// same discipline cmdModelToggle's edit closure follows: apply runs
			// inside its own transaction, and a replica that stopped serving in
			// between changes the answer to the downtime question.
			targets, skipped, _, err := plan(context.Background(), m.Tx())
			if err != nil {
				return err
			}
			skippedDisabled = fleet.ReplicaIDs(skipped)
			return fleet.RequestRestart(context.Background(), m, s.now,
				fleet.RollID(s.now), targets)
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
