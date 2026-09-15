package cli

import (
	"bytes"
	"context"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/nodarynet/nodary/internal/agent"
	"github.com/nodarynet/nodary/internal/components"
	"github.com/nodarynet/nodary/internal/dataplane"
	"github.com/nodarynet/nodary/internal/install"
	"github.com/nodarynet/nodary/internal/paths"
	"github.com/nodarynet/nodary/internal/preflight"
)

// unitMarker is the first line every unit nodary writes carries.
//
// Ownership is checked, never inferred — the rule components.Owned.Placed
// already states for binaries, applied to unit files. containerd's unit is
// upstream's text placed by nodary and carries the marker too; one an operator
// wrote themselves does not, and is left where it is.
const unitMarker = "# Written by nodary."

// cmdUninstall is dev/specs/01-install.md §10, for whichever roles this host
// actually has.
//
// **One verb for both, because a host can be both.** `--with-node` installs a
// control plane and a node on one machine, so a verb per role would need the
// operator to know which they have and run the right one — and to run both, in
// the right order, on the box the pilot topology actually uses. This looks at
// what is on the disk instead.
//
// **Uninstalling a control plane requires --purge, and the reason is sharper
// than being explicit about the audit database.** Step 3 removes /etc/nodary,
// and paths.SecretKey() lives there: without --purge the database survives in
// /var/lib/nodary with the key that unseals it deleted, so every TOTP seed, the
// agent CA private key and the LiteLLM master key inside it become permanently
// unreadable. That is the unrecoverable state checkKeyBinding exists to catch
// after the fact; here it can simply be refused, with `nodary backup create`
// named as the thing to do first.
//
// **It does not tell the control plane.** Same decision, for the same reason,
// as `nodary node leave`: a node announcing its own departure is a claim the
// far end would have to trust from the machine least able to make it, and the
// authoritative act is `nodary node revoke`, audited, from the side holding the
// chain. §10 step 1 says deregister; 12 §5 and R4-06 say revoke, and the later
// decision is the one with the argument behind it. So --force keeps the job it
// has here — skipping the confirmation — rather than skipping a call nodary
// does not make.
func cmdUninstall(e env, args []string) int {
	fs := newFlagSet(e, "uninstall")
	root := fs.String("root", "", "act on this prefix instead of / (for testing; nothing is stopped)")
	purge := fs.Bool("purge", false, "also remove state and logs; required to uninstall a control plane")
	purgeModels := fs.Bool("purge-models", false, "also delete staged weights; they cost hours to restage")
	force := fs.Bool("force", false, "do not ask for confirmation")
	format := formatFlag(fs)
	if code := parseFlags(e, fs, args); code >= 0 {
		return code
	}
	if !checkFormat(e, *format) {
		return ExitUsage
	}

	configDir := filepath.Join(*root, paths.ConfigDir)
	roles := rolesOn(*root, configDir)
	if len(roles) == 0 {
		fmt.Fprintf(e.stderr, "nodary uninstall: nothing installed here — no %s and no %s\n",
			filepath.Join(configDir, "server.toml"), filepath.Join(configDir, "agent.toml"))
		return ExitFailure
	}

	// Read before anything is removed: the weights are wherever agent.toml says
	// they are, and the node's own name is what has to be typed into `node
	// revoke` afterwards. A file that will not parse is not fatal here — an
	// uninstall has to work on a host that is broken, which is often why it is
	// being run.
	conf, _ := agent.LoadConfig(filepath.Join(configDir, "agent.toml"))
	// Under the prefix, like every other path here. The models directory is
	// absolute — agent.toml's value, or paths.DataDir/models — so using it bare
	// would make `--root <tmp> --purge-models` delete the real weights on the
	// machine running the test.
	modelsDir := filepath.Join(*root, orElse(conf.ModelsDir, agent.DefaultModelsDir()))

	// Stated as the thing that actually goes wrong rather than as "a server
	// needs --purge", which is only a proxy for it: what must not happen is
	// removing /etc/nodary while a database that needs the key inside it stays
	// behind. Checking the condition itself means a node has nothing to refuse,
	// and rerunning against a half-finished teardown — where the key is already
	// gone, so there is nothing left to strand — finishes rather than refusing.
	db := filepath.Join(*root, paths.Database())
	key := filepath.Join(*root, paths.SecretKey())
	if !*purge && exists(db) && exists(key) {
		fmt.Fprintf(e.stderr,
			"nodary uninstall: this host holds a control-plane database, so it needs --purge.\n"+
				"  %s is removed either way and %s is in it, so keeping\n"+
				"  %s would leave a database nothing can ever unseal again:\n"+
				"  every TOTP seed, the agent CA private key and the data plane's credential with it.\n"+
				"  Take a backup first if you want any of it: nodary backup create FILE\n",
			paths.ConfigDir, paths.SecretKey(), paths.Database())
		return ExitFailure
	}

	if !*force && !confirmUninstall(e, roles, *purge, *purgeModels, modelsDir) {
		fmt.Fprintln(e.stderr, "nothing was changed")
		return ExitOK
	}

	u := &teardown{e: e, opt: install.Options{Root: *root}, root: *root}
	ctx := context.Background()

	// Deployments first: stopping the agent before them would leave containers
	// running with nothing supervising them, which is `node leave`'s ordering
	// and its reasoning.
	if slices.Contains(roles, "node") && *root == "" {
		ids, err := agent.RunningDeployments(ctx, agent.RealHost("", configDir))
		if err != nil {
			u.failed("deployments", err.Error())
		}
		for _, id := range ids {
			u.stop(ctx, agent.UnitName(id))
		}
	}
	for _, unit := range stoppableUnits(roles, selectedPlane(configDir)) {
		u.stop(ctx, unit)
	}
	u.removeUnitFiles(roles)
	u.removeComponents(filepath.Join(configDir, components.OwnershipFile))

	u.remove("PATH link", filepath.Join(*root, install.DefaultBinDir, "nodary"))
	u.remove("binaries", filepath.Join(*root, paths.OptDir))
	u.remove("configuration", configDir)

	if *purge {
		// The models directory sits inside the data directory by default, and
		// --purge-models exists precisely because weights are the expensive
		// thing on the machine. Purging state must not take them by accident.
		u.purgeState(filepath.Join(*root, paths.DataDir), modelsDir, *purgeModels)
		u.remove("logs", filepath.Join(*root, paths.LogDir))
	}
	if *purgeModels {
		u.remove("weights", modelsDir)
	}

	return u.report(*format, roles, conf.Name)
}

// rolesOn says which roles this host carries, by what the install wrote.
func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func rolesOn(root, configDir string) []string {
	var roles []string
	for _, r := range []struct{ role, file string }{
		{"server", "server.toml"},
		{"node", "agent.toml"},
	} {
		if _, err := os.Stat(filepath.Join(configDir, r.file)); err == nil {
			roles = append(roles, r.role)
		}
	}
	// A configuration file removed by a half-finished uninstall leaves the
	// binaries behind, and rerunning has to finish the job rather than report
	// nothing to do.
	if len(roles) == 0 {
		if _, err := os.Stat(filepath.Join(root, paths.OptDir)); err == nil {
			roles = []string{"server", "node"}
		}
	}
	return roles
}

// stoppableUnits is every unit to stop, dependents before what they depend on.
//
// startedUnits is in dependency order, so reversing it stops the gateway before
// the data plane it proxies to and the agent before containerd — systemd would
// order this itself, but a failure then names the thing that failed rather than
// whatever was waiting on it.
func stoppableUnits(roles []string, plane dataplane.Plane) []string {
	var out []string
	for _, role := range roles {
		for _, u := range slices.Backward(startedUnits(role, plane)) {
			if !slices.Contains(out, u) {
				out = append(out, u)
			}
		}
	}
	// The timer's oneshot is not in startedUnits — nothing enables it directly
	// — but it is written, so it is stopped.
	if slices.Contains(roles, "server") {
		out = append(out, "nodary-prune.service", "nodary-gateway-sync.service")
	}
	return out
}

// teardown accumulates what was done, in the shape `node leave` reports.
type teardown struct {
	e     env
	opt   install.Options
	root  string
	steps []leaveStep
	bad   bool
}

func (t *teardown) failed(name, detail string) {
	t.steps = append(t.steps, leaveStep{Step: install.Step{Name: name, Detail: detail}, Failed: true})
	t.bad = true
}

func (t *teardown) stop(ctx context.Context, unit string) {
	step, err := install.Stop(ctx, unit, t.opt)
	if err != nil {
		// Reported and carried past, never aborted: a teardown that stops
		// halfway leaves a machine that is neither installed nor not, which is
		// worse than either end.
		t.failed(step.Name, err.Error())
		return
	}
	t.steps = append(t.steps, leaveStep{Step: step})
}

// remove deletes a path and says so, treating an absent one as done.
func (t *teardown) remove(name, path string) {
	step := leaveStep{Step: install.Step{Name: name, Detail: path}}
	switch _, err := os.Lstat(path); {
	case os.IsNotExist(err):
		step.Detail = path + " (already gone)"
	case err != nil:
		t.failed(name, err.Error())
		return
	default:
		if err := os.RemoveAll(path); err != nil {
			t.failed(name, err.Error())
			return
		}
		step.Changed, step.Detail = true, path+" removed"
	}
	t.steps = append(t.steps, step)
}

// removeUnitFiles deletes only units carrying nodary's own marker.
//
// Every plane's unit, not only the selected one: a host that switched planes
// has the other unit on disk, and an uninstall that left it behind would leave
// systemd holding a unit for a product that is gone.
func (t *teardown) removeUnitFiles(roles []string) {
	dir := filepath.Join(t.root, install.DefaultUnitDir)
	names := map[string]bool{}
	for _, role := range roles {
		for _, plane := range dataplane.All() {
			for name := range install.Units(role, plane) {
				names[name] = true
			}
		}
	}
	for _, name := range slices.Sorted(maps.Keys(names)) {
		path := filepath.Join(dir, name)
		body, err := os.ReadFile(path)
		switch {
		case os.IsNotExist(err):
			continue
		case err != nil:
			t.failed("unit: "+name, err.Error())
			continue
		case !bytes.HasPrefix(body, []byte(unitMarker)):
			t.steps = append(t.steps, leaveStep{Step: install.Step{
				Name: "unit: " + name, Detail: path + " was not written by nodary; left alone"}})
			continue
		}
		t.remove("unit: "+name, path)
	}
}

// removeComponents deletes what nodary placed, and nothing it merely found.
func (t *teardown) removeComponents(record string) {
	owned, err := components.LoadOwnership(record)
	if err != nil {
		t.failed("components", err.Error())
		return
	}
	removable := owned.Removable()
	if len(removable) == 0 {
		t.steps = append(t.steps, leaveStep{Step: install.Step{
			Name: "components", Detail: "nothing recorded as placed by nodary"}})
		return
	}
	for _, c := range removable {
		t.remove("component: "+c.Component, filepath.Join(t.root, c.Path))
	}
}

// purgeState removes the data directory, keeping the weights unless they were
// asked for as well.
func (t *teardown) purgeState(dataDir, modelsDir string, alsoModels bool) {
	nested := strings.HasPrefix(filepath.Clean(modelsDir)+string(filepath.Separator),
		filepath.Clean(dataDir)+string(filepath.Separator))
	if alsoModels || !nested {
		t.remove("state", dataDir)
		return
	}
	entries, err := os.ReadDir(dataDir)
	if os.IsNotExist(err) {
		t.steps = append(t.steps, leaveStep{Step: install.Step{
			Name: "state", Detail: dataDir + " (already gone)"}})
		return
	}
	if err != nil {
		t.failed("state", err.Error())
		return
	}
	keep := filepath.Base(filepath.Clean(modelsDir))
	for _, entry := range entries {
		if entry.Name() == keep {
			continue
		}
		t.remove("state: "+entry.Name(), filepath.Join(dataDir, entry.Name()))
	}
	t.steps = append(t.steps, leaveStep{Step: install.Step{
		Name: "weights", Detail: modelsDir + " kept; --purge-models deletes them"}})
}

func (t *teardown) report(format string, roles []string, node string) int {
	if format == "json" {
		return writeJSON(t.e, "uninstall", map[string]any{"steps": t.steps, "roles": roles})
	}
	for _, s := range t.steps {
		level := preflight.LevelOK
		if s.Failed {
			level = preflight.LevelFail
		}
		fmt.Fprintf(t.e.stdout, "%s %-28s %s\n", mark(level), s.Name, s.Detail)
	}
	if t.bad {
		fmt.Fprintf(t.e.stderr, "\nSome steps failed. This host is partly uninstalled; "+
			"rerun after fixing what is named above.\n")
		return ExitFailure
	}
	if slices.Contains(roles, "node") && !slices.Contains(roles, "server") {
		fmt.Fprintf(t.e.stderr,
			"\n%s is gone from this machine. The fleet's record still holds its certificate until\n"+
				"an administrator runs\n  nodary node revoke %s\n"+
				"on the control plane, which is what stops it being routed to.\n",
			orElse(node, "This host"), orElse(node, "<name>"))
	}
	return ExitOK
}

func confirmUninstall(e env, roles []string, purge, purgeModels bool, modelsDir string) bool {
	fmt.Fprintf(e.stderr, "This removes nodary (%s) from this host: its units, its binaries,\n"+
		"%s, and the components nodary itself installed.\n",
		strings.Join(roles, " and "), paths.ConfigDir)
	if purge {
		fmt.Fprintf(e.stderr, "--purge also deletes %s and %s.\n", paths.DataDir, paths.LogDir)
	}
	if purgeModels {
		fmt.Fprintf(e.stderr, "--purge-models also deletes the staged weights under %s.\n", modelsDir)
	} else {
		fmt.Fprintf(e.stderr, "Weights under %s are kept.\n", modelsDir)
	}
	return confirm(e)
}
