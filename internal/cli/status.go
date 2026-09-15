package cli

import (
	"context"
	"fmt"
	"path/filepath"
	"slices"
	"text/tabwriter"
	"time"

	"github.com/nodarynet/nodary/internal/dataplane"
	"github.com/nodarynet/nodary/internal/fleet"
	"github.com/nodarynet/nodary/internal/install"
	"github.com/nodarynet/nodary/internal/paths"
	"github.com/nodarynet/nodary/internal/store"
)

// cmdStatus is dev/specs/10-cli.md §1's whole-appliance verb: what is
// installed on this host, and is it running.
//
// **One verb for a host that is both.** `nodary server status` reads
// server.toml and the chain, `nodary agent status` reads the node's side, and
// neither says whether anything is actually up — the operator asking "is this
// appliance working" had to know which roles the machine has, run the right
// two verbs, and then run `systemctl status` for the part neither answers.
// That last part is the whole question, and it is the one nothing answered.
//
// It is deliberately **shallow and fast**: no chain verification, no network,
// no probes. `nodary doctor` is the verb that goes looking, and this one says
// which of its siblings to reach for next. A status command that takes twenty
// seconds on a large chain is one an operator stops running.
func cmdStatus(e env, args []string) int {
	fs := newFlagSet(e, "status")
	root := fs.String("root", "", "act on this prefix instead of / (for testing; systemd is not asked)")
	dbPath := dbFlag(fs)
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
		fmt.Fprintf(e.stderr, "nodary status: nothing installed here — no %s and no %s\n",
			filepath.Join(configDir, "server.toml"), filepath.Join(configDir, "agent.toml"))
		fmt.Fprintf(e.stderr, "  `nodary install` sets this host up as a control plane, a node, or both.\n")
		return ExitFailure
	}

	ctx := context.Background()
	o := install.Options{Root: *root}
	doc := map[string]any{"version": versionString(), "roles": roles}

	var units []install.UnitStatus
	for _, u := range hostUnits(roles, selectedPlane(configDir)) {
		st, err := install.UnitState(ctx, u, o)
		if err != nil {
			// Reported in the row rather than fatal: a host where systemd
			// cannot be asked about one unit still has an answer about the
			// rest, and the missing one is the interesting part.
			st.Active = "unknown: " + err.Error()
		}
		units = append(units, st)
	}
	doc["units"] = units
	doc["ok"] = unitsOK(units)

	// The fleet, from the control plane's own database. Counts only: `nodary
	// node list` is the verb that names them, and this is the line that says
	// whether it is worth running.
	if slices.Contains(roles, "server") {
		path, explicit := resolveDBIn(e, *dbPath)
		if !explicit && *root != "" {
			path = filepath.Join(*root, paths.Database())
		}
		if db, err := store.OpenReadOnly(ctx, path); err == nil {
			defer db.Close()
			if nodes, err := fleet.Nodes(ctx, db.Read(), time.Now()); err == nil {
				doc["fleet"] = fleetSummary(nodes)
			}
		}
	}

	if *format == "json" {
		if code := writeJSON(e, "status", doc); code != ExitOK {
			return code
		}
		return statusExit(units)
	}

	tw := tabwriter.NewWriter(e.stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintf(tw, "version\t%s\n", versionString())
	fmt.Fprintf(tw, "roles\t%s\n", joinWords(roles))
	if f, ok := doc["fleet"].(map[string]any); ok {
		fmt.Fprintf(tw, "fleet\t%v nodes, %v ready, %v stale\n", f["nodes"], f["ready"], f["stale"])
		fmt.Fprintf(tw, "deployments\t%v placed, %v ready\n", f["deployments"], f["deployments_ready"])
	}
	if code := flush(e, "status", tw); code != ExitOK {
		return code
	}

	fmt.Fprintln(e.stdout)
	tw = tabwriter.NewWriter(e.stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "UNIT\tACTIVE\tENABLED")
	for _, u := range units {
		fmt.Fprintf(tw, "%s\t%s\t%s\n", u.Unit, orDash(u.Active), orDash(u.Enabled))
	}
	if code := flush(e, "status", tw); code != ExitOK {
		return code
	}

	if !unitsOK(units) {
		fmt.Fprintf(e.stderr,
			"\nSomething this host installed is not running. `nodary doctor` looks;\n"+
				"`nodary restart` bounces what nodary owns; `journalctl -u <unit>` says why.\n")
	}
	return statusExit(units)
}

// hostUnits is every unit this host's roles own, in the order an install starts
// them — the reverse of what `uninstall` stops, and the same list, so a unit
// that arrives in one place cannot be missing from the other.
func hostUnits(roles []string, plane dataplane.Plane) []string {
	var out []string
	for _, role := range roles {
		for _, u := range startedUnits(role, plane) {
			if !slices.Contains(out, u) {
				out = append(out, u)
			}
		}
	}
	if slices.Contains(roles, "server") {
		// The timer's oneshot: `active` is the wrong question for a Type=oneshot
		// — it is inactive between runs and that is correct — but "installed"
		// is worth seeing beside the timer that triggers it.
		out = append(out, "nodary-prune.service", "nodary-gateway-sync.service")
	}
	return out
}

// unitsOK is whether everything this host installed is running.
//
// A unit with no unit file is not counted: `startedUnits` is what each role
// installs, and on a staged tree — or a half-finished install — asking systemd
// about a unit that was never written answers "not installed", which is
// reported in the table rather than called a failure of the running system.
// A `Type=oneshot` triggered by a timer is inactive between runs by design, so
// the oneshots are skipped and the timers that drive them are not: a stopped
// timer is a retention pass or a data-plane sync that has quietly stopped
// happening, which is exactly what this verb is for.
func unitsOK(units []install.UnitStatus) bool {
	for _, u := range units {
		if !u.Installed() || oneshot(u.Unit) {
			continue
		}
		if u.Active != "active" {
			return false
		}
	}
	return true
}

// oneshot names the units a timer triggers, which finish and go inactive.
func oneshot(unit string) bool {
	return unit == "nodary-prune.service" || unit == "nodary-gateway-sync.service"
}

// statusExit follows `systemctl is-active`'s contract, which is the one an
// operator scripting this already knows: zero when what is installed is
// running, nonzero when it is not. A stopped control plane is not a successful
// answer to "is this appliance up".
func statusExit(units []install.UnitStatus) int {
	if unitsOK(units) {
		return ExitOK
	}
	return ExitFailure
}

func fleetSummary(nodes []fleet.Node) map[string]any {
	var ready, stale, placed, servingNow int
	for _, n := range nodes {
		if n.State == "approved" && !n.Stale {
			ready++
		}
		if n.Stale {
			stale++
		}
		placed += n.DeploymentCount
		servingNow += n.ReadyCount
	}
	return map[string]any{"nodes": len(nodes), "ready": ready, "stale": stale,
		"deployments": placed, "deployments_ready": servingNow}
}

func joinWords(words []string) string {
	out := ""
	for i, w := range words {
		if i > 0 {
			out += ", "
		}
		out += w
	}
	return out
}

// cmdRestart bounces every nodary unit this host runs, in dependency order.
//
// **Not a synonym for `systemctl restart nodary-server`.** `nodary server stop`
// refuses to exist for exactly that reason — wrapping one systemctl call adds
// nothing but a second name for it. What this knows and the operator does not
// is the *set*: which units this host's roles own, and that the data plane goes
// before the API that proxies to it. On a `--with-node` box that is four units
// in an order that matters.
//
// **containerd is not in the set.** It is a shared system service nodary
// installs rather than owns, and restarting it stops every running container on
// the machine — every deployment on the node, to fix something that is almost
// never containerd. `systemctl restart containerd` is available to anybody who
// has decided that is the problem.
//
// No audit record. It changes nothing a chain is about — no identity, no
// configuration, no fleet state — and the control plane is the process being
// restarted, so a record of it would have to be written by the thing going
// away. `systemctl` and the journal are where a restart of a service is
// recorded, which is where an assessor already looks for one.
func cmdRestart(e env, args []string) int {
	fs := newFlagSet(e, "restart")
	root := fs.String("root", "", "act on this prefix instead of / (for testing; nothing is restarted)")
	if code := parseFlags(e, fs, args); code >= 0 {
		return code
	}

	configDir := filepath.Join(*root, paths.ConfigDir)
	roles := rolesOn(*root, configDir)
	if len(roles) == 0 {
		fmt.Fprintf(e.stderr, "nodary restart: nothing installed here — no %s and no %s\n",
			filepath.Join(configDir, "server.toml"), filepath.Join(configDir, "agent.toml"))
		return ExitFailure
	}

	// Everything the roles start; restartUnits decides which of those are
	// nodary's to bounce and in what order, so the set lives in one place
	// rather than being filtered here and filtered again there.
	want := map[string]bool{}
	plane := selectedPlane(configDir)
	for _, role := range roles {
		for _, u := range startedUnits(role, plane) {
			want[u] = true
		}
	}
	return restartUnits(e, context.Background(), want, install.Options{Root: *root})
}
