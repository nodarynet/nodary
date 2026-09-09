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
	"github.com/nodarynet/nodary/internal/gateway"
	"github.com/nodarynet/nodary/internal/install"
	"github.com/nodarynet/nodary/internal/preflight"
)

// cmdGatewaySync re-renders the data plane's configuration from current routes.
//
// `server install` writes litellm.yaml once, with an empty model_list, because
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
	confDir := fs.String("config-dir", "", "where litellm.yaml lives (default /etc/nodary)")
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
	models, skipped := routeModels(e, snap, dir)

	// Named, not counted. "3 route(s) would be served" leaves an operator
	// unable to answer the one question they have after applying a
	// configuration — what may a client ask for, and by what name — and the
	// answer is not guessable: LiteLLM routes on the *route* name, not the
	// model id, so a client sending the weights path gets a 404 from a fleet
	// that is working perfectly.
	for _, m := range models {
		fmt.Fprintf(e.stdout, "%s %-18s %s -> %s\n",
			mark(preflight.LevelOK), "route", m.Name, m.APIBase)
	}

	body := gateway.LiteLLMConfig{Models: models, MasterKey: master}.Render()
	if err := gateway.AssertLoggingOff(body); err != nil {
		fmt.Fprintf(e.stderr, "nodary gateway sync: %v\n", err)
		return ExitFailure
	}

	conf := filepath.Join(dir, "litellm.yaml")
	existing, _ := os.ReadFile(conf)
	changed := !bytes.Equal(existing, body)

	if dryRun {
		fmt.Fprintf(e.stdout, "%d route(s) would be served", len(models))
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

	if changed {
		if err := os.WriteFile(conf, body, 0o640); err != nil {
			fmt.Fprintf(e.stderr, "nodary gateway sync: %v\n", err)
			return ExitFailure
		}
	}
	report(e, []install.Step{{Name: "litellm config", Changed: changed,
		Detail: fmt.Sprintf("%s, %d route(s)", conf, len(models))}})

	// **Not "only when the file changed".** LiteLLM reads its configuration at
	// startup, so what matters is whether the *running process* has this one —
	// and those come apart exactly when it matters: the file was written while
	// LiteLLM was already up, so a later sync found it correct, restarted
	// nothing, and left the data plane serving an empty model list with a
	// perfectly good file on disk beside it. `gateway sync` reported success
	// and changed nothing that mattered.
	//
	// So the digest of what the running process was started with is recorded in
	// /run, which the boot clears — and a boot starts LiteLLM from the current
	// file anyway, so a missing marker means "unknown", which restarts. The
	// alternative, restarting unconditionally, would drop live requests every
	// time somebody ran this to check.
	applied := appliedMarker(root)
	if !changed {
		if prior, err := os.ReadFile(applied); err == nil &&
			strings.TrimSpace(string(prior)) == digestOf(body) {
			return ExitOK
		}
	}
	step, err := install.Start(ctx, "nodary-litellm.service", install.Options{Root: root})
	if err != nil {
		fmt.Fprintf(e.stdout, "%s %-18s %v\n", mark(preflight.LevelWarn), "restart", err)
		fmt.Fprintf(e.stderr, "\nThe configuration is written. `systemctl restart nodary-litellm` applies it.\n")
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
func appliedMarker(root string) string {
	return filepath.Join(root, "/run/nodary/litellm.applied")
}

func digestOf(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// routeModels turns routes into what LiteLLM proxies to, and says what it left
// out.
//
// **Only deployments on this host.** docs/specs/03-agent.md publishes a
// deployment's port on `127.0.0.1` *"so the container is reachable by the
// gateway"* — which holds when the gateway is on the same machine, and does not
// when it is not. docs/specs/00-overview.md §2 also has traffic to nodes
// **agent-initiated only**, so the control plane has no way to dial a node's
// loopback and no specified way to reach a deployment on one.
//
// That is an unresolved question in the specifications rather than a bug here,
// and it is not papered over: a deployment on another node is skipped and named,
// so a single-box install works and a fleet is told what is missing instead of
// being handed a configuration pointing at an address that answers nothing.
func routeModels(e env, snap *config.Snapshot, dir string) ([]gateway.LiteLLMModel, int) {
	byID := map[string]config.Deployment{}
	for _, d := range snap.Deployments {
		byID[d.ID] = d
	}
	local := localNodeName(dir)

	var models []gateway.LiteLLMModel
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
			if local != "" && d.NodeName != local {
				skipped++
				fmt.Fprintf(e.stdout, "%s %-18s %s: %s runs on %q and publishes on that host's loopback, "+
					"which this one cannot reach\n",
					mark(preflight.LevelWarn), "route", r.Name, d.ID, d.NodeName)
				continue
			}
			models = append(models, gateway.LiteLLMModel{
				Name:    r.Name,
				Model:   r.Name,
				APIBase: fmt.Sprintf("http://127.0.0.1:%d/v1", d.Port),
			})
		}
	}
	sort.Slice(models, func(i, j int) bool { return models[i].Name < models[j].Name })
	return models, skipped
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

// readMasterKey reads the credential LiteLLM accepts.
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
