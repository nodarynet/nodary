package cli

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/nodarynet/nodary/internal/agent"
	"github.com/nodarynet/nodary/internal/install"
	"github.com/nodarynet/nodary/internal/paths"
	"github.com/nodarynet/nodary/internal/preflight"
)

// leaveStep is an install.Step that can also have failed. A teardown reports
// removals rather than creations and keeps going when one of them does not
// work, so it needs both a different word than report()'s "(created)" and a
// way to mark the line that went wrong.
type leaveStep struct {
	install.Step
	Failed bool `json:"failed,omitempty"`
}

// cmdNodeLeave is docs/specs/12-node-guardrails.md §5, run on the node.
//
// **It needs nothing to be reachable.** "This exists because taking a machine
// back should not require the control plane to be healthy — the common case
// is precisely that something has gone wrong." So it talks to no server,
// opens no database and writes no audit record: a GPU node has none of those
// on it. What it does is local and complete — stop the deployments, stop the
// agent, and destroy the credentials that made this machine a node.
//
// **Ejecting the node from the fleet's own record is the other half, and it
// is `nodary node revoke` on the control plane.** Deliberately not attempted
// from here: a node announcing its own departure is a claim the control plane
// would have to trust from the machine least able to make it — and the
// authoritative act is one an administrator performs, audited, from the side
// that holds the chain. This prints the command rather than pretending the
// fleet has been told.
//
// Weights stay unless asked for: `--purge-models` is separate because they
// cost hours to restage and a decommissioned disk is often reused as-is,
// the same split docs/specs/01-install.md §10 draws for uninstall.
func cmdNodeLeave(e env, args []string) int {
	fs := newFlagSet(e, "node leave")
	root := fs.String("root", "", "act on this prefix instead of / (for testing; nothing is stopped)")
	purgeModels := fs.Bool("purge-models", false,
		"delete staged weights too; they cost hours to restage")
	yes := fs.Bool("yes", false, "do not ask for confirmation")
	format := formatFlag(fs)
	if code := parseFlags(e, fs, args); code >= 0 {
		return code
	}
	if !checkFormat(e, *format) {
		return ExitUsage
	}

	ctx := context.Background()
	configDir := filepath.Join(*root, paths.ConfigDir)
	confPath := filepath.Join(configDir, "agent.toml")

	// Read before removing, for two reasons: the certificate and key are
	// wherever this file says they are, and the node's own name is what the
	// operator has to type into `node revoke` afterwards.
	conf, confErr := agent.LoadConfig(confPath)
	if confErr != nil && os.IsNotExist(confErr) {
		fmt.Fprintf(e.stderr, "nodary node leave: %s does not exist, so this host is not enrolled\n", confPath)
		return ExitFailure
	}

	if !*yes {
		fmt.Fprintf(e.stderr,
			"This stops every deployment and the agent on this host and destroys its credentials.\n"+
				"Rejoining is a fresh enrollment.\n")
		if *purgeModels {
			fmt.Fprintf(e.stderr, "--purge-models will also delete the staged weights under %s.\n",
				orElse(conf.ModelsDir, agent.DefaultModelsDir()))
		}
		if !confirm(e) {
			fmt.Fprintln(e.stderr, "nothing was changed")
			return ExitOK
		}
	}

	o := install.Options{Root: *root}
	var steps []leaveStep
	failed := false
	stop := func(unit string) {
		step, err := install.Stop(ctx, unit, o)
		if err != nil {
			// Reported and carried past, not aborted. A teardown that stops
			// halfway leaves a machine in a state that is neither a node nor
			// not one, which is worse than either end — so every step is
			// attempted and every failure is named.
			step.Detail, failed = err.Error(), true
			steps = append(steps, leaveStep{Step: step, Failed: true})
			return
		}
		steps = append(steps, leaveStep{Step: step})
	}

	// Deployments before the agent: stopping the agent first would leave the
	// containers running with nothing supervising them, and the reconcile
	// loop is what would otherwise have stopped them.
	if *root == "" {
		ids, err := agent.RunningDeployments(ctx, agent.RealHost("", configDir))
		if err != nil {
			steps = append(steps, leaveStep{
				Step: install.Step{Name: "deployments", Detail: err.Error()}, Failed: true})
			failed = true
		}
		for _, id := range ids {
			stop(agent.UnitName(id))
		}
	}
	stop("nodary-agent.service")

	// The credentials last, because until they are gone this is still a node
	// — and if something above failed, an operator who reruns this still has
	// the file naming what to clean up.
	for _, p := range []string{conf.Certificate, conf.Key, confPath} {
		if p == "" {
			continue
		}
		step := leaveStep{Step: install.Step{Name: "remove: " + p}}
		switch err := os.Remove(p); {
		case err == nil:
			step.Changed, step.Detail = true, "removed"
		case os.IsNotExist(err):
			step.Detail = "already gone"
		default:
			step.Detail, step.Failed, failed = err.Error(), true, true
		}
		steps = append(steps, step)
	}

	if *purgeModels {
		dir := orElse(conf.ModelsDir, agent.DefaultModelsDir())
		step := leaveStep{Step: install.Step{Name: "remove: " + dir}}
		if err := os.RemoveAll(dir); err != nil {
			step.Detail, step.Failed, failed = err.Error(), true, true
		} else {
			step.Changed, step.Detail = true, "weights deleted"
		}
		steps = append(steps, step)
	}

	if *format == "json" {
		return writeJSON(e, "node leave", map[string]any{"steps": steps, "node": conf.Name})
	}
	for _, s := range steps {
		level := preflight.LevelOK
		if s.Failed {
			level = preflight.LevelFail
		}
		fmt.Fprintf(e.stdout, "%s %-28s %s\n", mark(level), s.Name, s.Detail)
	}
	if failed {
		fmt.Fprintf(e.stderr, "\nSome steps failed. This host may still be partly enrolled; "+
			"rerun after fixing what is named above.\n")
		return ExitFailure
	}

	// The half this cannot do, named exactly.
	fmt.Fprintf(e.stderr,
		"\n%s has left. Its certificate still exists in the fleet's record until an administrator runs\n"+
			"  nodary node revoke %s\n"+
			"on the control plane, which is what stops it being routed to and refuses it if it comes back.\n",
		orElse(conf.Name, "this host"), orElse(conf.Name, "<name>"))
	return ExitOK
}
