package cli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/BurntSushi/toml"
	"github.com/nodarynet/nodary/internal/config"
	"github.com/nodarynet/nodary/internal/dataplane"
	"github.com/nodarynet/nodary/internal/install"
	"github.com/nodarynet/nodary/internal/preflight"
)

// cmdGatewaySync re-renders the data plane's configuration from current routes.
//
// `server install` writes it once, with an empty member list, because
// a fresh control plane has no deployments. Something has to write it again
// when one appears, and this is that something until R3-14 makes route
// membership live.
//
// **It is a separate verb because the processes that know cannot write.**
// nodary-server holds the routes and runs unprivileged under
// `ProtectSystem=strict` with `ReadOnlyPaths=/etc/nodary`; it can neither write
// this file nor restart a unit. Rather than widen that unit until it can — which
// would give the network-facing process the ability to rewrite the data plane's
// configuration and restart services — the re-render is an explicit act by
// somebody who already has root. That also suits what the product argues
// everywhere else: a change with an author beats a change that happened.
func cmdGatewaySync(e env, args []string) int {
	fs := newFlagSet(e, "gateway sync")
	dbPath := dbFlag(fs)
	confDir := fs.String("config-dir", "", "where the data plane's configuration lives (default /etc/nodary)")
	root := fs.String("root", "", "operate under this prefix instead of / (for testing; nothing is restarted)")
	dryRun := fs.Bool("dry-run", false, "print what would change and write nothing")
	if code := parseFlags(e, fs, args); code >= 0 {
		return code
	}
	return syncGateway(e, *dbPath, *confDir, *root, *dryRun)
}

// syncGateway is the verb's body, so `config apply` can run the same thing
// rather than telling an operator to remember it. See autoSync.
func syncGateway(e env, dbPath, confDir, root string, dryRun bool) int {
	ctx := context.Background()
	dir := confDir
	if dir == "" {
		dir = filepath.Join(root, "/etc/nodary")
	}

	path, _ := resolveDB(dbPath)
	db, ok := openForReading(e, "gateway sync", path)
	if !ok {
		return ExitFailure
	}
	defer db.Close()

	snap, err := config.Read(ctx, db.Read())
	if err != nil {
		fmt.Fprintf(e.stderr, "nodary gateway sync: %v\n", err)
		return ExitFailure
	}

	master, code := readMasterKey(e, dir)
	if code != ExitOK {
		return code
	}
	// The deployment states, read separately because they are deliberately not
	// in the configuration snapshot: they are observations, and a heartbeat
	// that moved one would otherwise read as a configuration change
	// (dev/plans/R4a-agent-protocol.md §4).
	ready, err := readyDeployments(ctx, db.Read())
	if err != nil {
		fmt.Fprintf(e.stderr, "nodary gateway sync: %v\n", err)
		return ExitFailure
	}
	plane := selectedPlane(dir)
	members, skipped := routeModels(e, snap, ready, dir)

	// Named, not counted. "3 route(s) would be served" leaves an operator
	// unable to answer the one question they have after applying a
	// configuration — what may a client ask for, and by what name — and the
	// answer is not guessable: the plane routes on the *route* name, not the
	// model id, so a client sending the weights path gets a 404 from a fleet
	// that is working perfectly.
	for _, m := range members {
		fmt.Fprintf(e.stdout, "%s %-18s %s -> %s\n",
			mark(preflight.LevelOK), "route", m.Name, m.APIBase)
	}

	body := plane.Render(dataplane.Config{Members: members, MasterKey: master})
	if err := plane.Assert(body); err != nil {
		fmt.Fprintf(e.stderr, "nodary gateway sync: %v\n", err)
		return ExitFailure
	}

	conf := filepath.Join(dir, plane.ConfigFile)
	existing, _ := os.ReadFile(conf)
	changed := !bytes.Equal(existing, body)

	if dryRun {
		fmt.Fprintf(e.stdout, "%d route(s) would be served", len(members))
		if skipped > 0 {
			fmt.Fprintf(e.stdout, ", %d skipped", skipped)
		}
		if changed {
			fmt.Fprintf(e.stdout, "; %s would be rewritten\n", conf)
		} else {
			fmt.Fprintf(e.stdout, "; %s is already correct\n", conf)
		}
		return ExitOK
	}

	step, err := writePlaneConfig(dir, plane, body)
	if err != nil {
		fmt.Fprintf(e.stderr, "nodary gateway sync: %v\n", err)
		return ExitFailure
	}
	step.Detail = fmt.Sprintf("%s, %d route(s)", conf, len(members))
	report(e, []install.Step{step})

	// **Not "only when the file changed".** A data plane reads its
	// configuration at startup, so what matters is whether the *running
	// process* has this one — and those come apart exactly when it matters: the
	// file was written while the plane was already up, so a later sync found it correct, restarted
	// nothing, and left the data plane serving an empty model list with a
	// perfectly good file on disk beside it. `gateway sync` reported success
	// and changed nothing that mattered.
	//
	// So the digest of what the running process was started with is recorded in
	// /run, which the boot clears — and a boot starts the plane from the current
	// file anyway, so a missing marker means "unknown", which restarts. The
	// alternative, restarting unconditionally, would drop live requests every
	// time somebody ran this to check.
	applied := appliedMarker(root, plane)
	if !changed {
		if prior, err := os.ReadFile(applied); err == nil &&
			strings.TrimSpace(string(prior)) == digestOf(body) {
			return ExitOK
		}
	}
	step, err = install.Restart(ctx, plane.Unit, install.Options{Root: root})
	if err != nil {
		fmt.Fprintf(e.stdout, "%s %-18s %v\n", mark(preflight.LevelWarn), "restart", err)
		fmt.Fprintf(e.stderr, "\nThe configuration is written. `systemctl restart %s` applies it.\n", plane.Unit)
		return ExitOK
	}
	report(e, []install.Step{step})
	if err := os.MkdirAll(filepath.Dir(applied), 0o755); err == nil {
		// Best effort: a marker that could not be written means the next sync
		// restarts once more, which is the safe direction.
		_ = os.WriteFile(applied, []byte(digestOf(body)+"\n"), 0o644)
	}
	return ExitOK
}

// appliedMarker records the configuration the running data plane was started
// with. In /run because that is state about a process, not about the install.
func appliedMarker(root string, plane dataplane.Plane) string {
	return filepath.Join(root, "/run/nodary", plane.AppliedName)
}

func digestOf(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// routeModels turns routes into what the data plane proxies to, and says what
// it left out.
//
// **Only deployments on this host.** dev/specs/03-agent.md publishes a
// deployment's port on `127.0.0.1` *"so the container is reachable by the
// gateway"* — which holds when the gateway is on the same machine, and does not
// when it is not. dev/specs/00-overview.md §2 also has traffic to nodes
// **agent-initiated only**, so the control plane has no way to dial a node's
// loopback and no specified way to reach a deployment on one.
//
// That is an unresolved question in the specifications rather than a bug here,
// and it is not papered over: a deployment on another node is skipped and named,
// so a single-box install works and a fleet is told what is missing instead of
// being handed a configuration pointing at an address that answers nothing.
// readyDeployments is every deployment whose node reports it as serving.
//
// dev/specs/05-catalog.md §5 round-robins across **ready** members, and `ready`
// already folds in health: internal/agent's observedState calls a unit `ready`
// only when it is active *and* its health probe answers, so a replica that goes
// unhealthy drops back to `starting` and leaves its route here. That is what
// makes this health-driven without this file knowing what a health probe is.
func readyDeployments(ctx context.Context, q config.Querier) (map[string]bool, error) {
	rows, err := q.QueryContext(ctx, `SELECT id FROM deployment WHERE state = 'ready'`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out[id] = true
	}
	return out, rows.Err()
}

func routeModels(e env, snap *config.Snapshot, ready map[string]bool, dir string) ([]dataplane.Member, int) {
	byID := map[string]config.Deployment{}
	for _, d := range snap.Deployments {
		byID[d.ID] = d
	}
	local := localNodeName(dir)
	// A node that is draining or departed receives an empty desired state
	// (internal/api's desiredFor) and stops everything within a poll, so a
	// route to it is an address about to stop answering. Without this,
	// `nodary node drain` and `node revoke` moved a node's state and the
	// gateway kept sending it traffic — the state said one thing and the
	// data plane did another.
	//
	// Only for a node the snapshot actually names: a fragment that carries
	// deployments and no nodes should render, for the reason
	// TestAControlPlaneThatIsNotANodeServesEveryRoute gives.
	state := map[string]string{}
	for _, n := range snap.Nodes {
		state[n.Name] = n.State
	}
	serving := func(node string) bool {
		s, known := state[node]
		return !known || s == "approved" || s == "ready"
	}

	var members []dataplane.Member
	var skipped int
	for _, r := range snap.Routes {
		for _, m := range r.Members {
			d, ok := byID[m.DeploymentID]
			if !ok {
				continue
			}
			if d.Port == 0 {
				// Not yet placed. A route pointing at a deployment with no port
				// would render an api_base of http://127.0.0.1:0.
				skipped++
				fmt.Fprintf(e.stdout, "%s %-18s %s: %s has no port yet\n",
					mark(preflight.LevelWarn), "route", r.Name, d.ID)
				continue
			}
			if !serving(d.NodeName) {
				skipped++
				fmt.Fprintf(e.stdout, "%s %-18s %s: %s is on %q, which is %s and not serving\n",
					mark(preflight.LevelWarn), "route", r.Name, d.ID, d.NodeName, state[d.NodeName])
				continue
			}
			// R3-14: only members that are actually serving. Without this a
			// route kept pointing at a deployment the operator had disabled,
			// one whose card had left the bus, and one that had never started
			// — so a client got a connection refused from a data plane that
			// believed it was routing correctly, rather than the 503 with a
			// Retry-After that 06 §5 specifies for a route with no ready
			// member.
			//
			// Disabled is checked separately from the state map because it is a
			// *decision* and it is in the snapshot: an operator who runs
			// `model disable` has said so, and a route still naming it should
			// not depend on whether the node has got around to reporting the
			// stop yet.
			if d.Disabled {
				skipped++
				fmt.Fprintf(e.stdout, "%s %-18s %s: %s is disabled\n",
					mark(preflight.LevelWarn), "route", r.Name, d.ID)
				continue
			}
			if !ready[d.ID] {
				skipped++
				fmt.Fprintf(e.stdout, "%s %-18s %s: %s is not ready, so it is not in the route yet\n",
					mark(preflight.LevelWarn), "route", r.Name, d.ID)
				continue
			}
			if local != "" && d.NodeName != local {
				skipped++
				fmt.Fprintf(e.stdout, "%s %-18s %s: %s runs on %q and publishes on that host's loopback, "+
					"which this one cannot reach\n",
					mark(preflight.LevelWarn), "route", r.Name, d.ID, d.NodeName)
				continue
			}
			members = append(members, dataplane.Member{
				Name:    r.Name,
				Model:   r.Name,
				APIBase: fmt.Sprintf("http://127.0.0.1:%d/v1", d.Port),
				Weight:  m.Weight,
				// So a usage row can say which member of this route served the
				// request, and therefore which node and which GPU.
				ID: d.ID,
			})
		}
	}
	sort.Slice(members, func(i, j int) bool { return members[i].Name < members[j].Name })
	return members, skipped
}

// localNodeName reads which node this host enrolled as, or "" when it is not
// also a node.
//
// Only the name, not agent.LoadConfig. That validates a whole agent
// configuration — server URL, pinned fingerprint, certificate and key — and all
// this needs is an identity. A control plane that could not tell which
// deployments it can reach because the agent's certificate path looked wrong
// would be failing at the wrong question.
//
// Empty means "do not filter": a control plane that is not a node has no way to
// know, and refusing every route would be a worse answer than letting the
// operator see the configuration that resulted.
func localNodeName(dir string) string {
	var conf struct {
		Name string `toml:"name"`
	}
	if _, err := toml.DecodeFile(filepath.Join(dir, "agent.toml"), &conf); err != nil {
		return ""
	}
	return conf.Name
}

// readMasterKey reads the credential the data plane accepts.
//
// It is never generated here. `server install` owns it, and a verb that minted
// one when the file was unreadable would write a configuration the gateway
// cannot authenticate against — the failure being every request rejected
// upstream, on a sync that reported success.
func readMasterKey(e env, dir string) (string, int) {
	path := filepath.Join(dir, "gateway.env")
	body, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintf(e.stderr, "nodary gateway sync: %v\n", err)
		fmt.Fprintf(e.stderr, "  `nodary server install` writes it; this verb never mints one\n")
		return "", ExitFailure
	}
	key := trimEnvValue(string(body), "NODARY_MASTER_KEY")
	if key == "" {
		fmt.Fprintf(e.stderr, "nodary gateway sync: %s holds no NODARY_MASTER_KEY\n", path)
		return "", ExitFailure
	}
	return key, ExitOK
}
