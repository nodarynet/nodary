package cli

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/nodarynet/nodary/internal/agent"
	"github.com/nodarynet/nodary/internal/buildinfo"
	"github.com/nodarynet/nodary/internal/components"
	"github.com/nodarynet/nodary/internal/install"
	"github.com/nodarynet/nodary/internal/preflight"
)

// cmdNodeInstall is docs/specs/01-install.md §5's six steps.
//
// Preflight, fetch from the mirror, place the runtime, create the isolated
// network, enroll, write agent.toml, start the agent. Each is idempotent and
// says whether it changed anything, because §4 requires the install to be
// re-runnable and a step that cannot say is one nobody can safely repeat.
//
// It composes verbs that already exist rather than reimplementing them:
// `components fetch --mirror`, `node enroll` and `agent run` are the same code
// paths an operator can run one at a time when something needs repairing.
func cmdNodeInstall(e env, args []string) int {
	fs := newFlagSet(e, "node install")
	server := fs.String("server", "", "control plane URL, https://host:8443")
	token := fs.String("token", "", "join token from nodary token join")
	fingerprint := fs.String("ca-fingerprint", "", "the control plane certificate to pin, sha256:…")
	name := fs.String("name", "", "this node's name in the fleet (default: hostname)")
	modelsDir := fs.String("models-dir", "", "where weights are staged")
	gpus := fs.String("gpus", "", "GPU indices to offer, comma-separated (default: all present)")
	maxDeployments := fs.Int("max-deployments", 0, "deployment ceiling")
	maintenance := fs.String("maintenance", "", `maintenance window, e.g. "sat 02:00-06:00 UTC"`)
	root := fs.String("root", "", "install into this prefix instead of / (for testing; nothing is started)")
	skipPreflight := fs.Bool("skip-preflight", false,
		"do not run the host checks. Records that they were skipped; it does not make them pass")
	dryRun := fs.Bool("dry-run", false, "run preflight and print what would be done")
	if code := parseFlags(e, fs, args); code >= 0 {
		return code
	}

	for _, req := range []struct{ flag, value string }{
		{"--server", *server}, {"--token", *token}, {"--ca-fingerprint", *fingerprint},
	} {
		if req.value == "" && !*dryRun {
			fmt.Fprintf(e.stderr, "nodary node install: %s is required\n", req.flag)
			return ExitUsage
		}
	}

	ctx := context.Background()
	o := install.Options{Root: *root}
	configDir := filepath.Join(*root, "/etc/nodary")
	models := orElse(*modelsDir, agent.DefaultModelsDir())

	// 1. Preflight. Abort on any hard failure, printing every failure at once.
	if !*skipPreflight {
		r := preflight.Run(ctx, preflight.Options{
			Role: preflight.RoleNode, ModelsDir: models, DataDir: filepath.Join(*root, "/var/lib/nodary"),
		})
		for _, c := range r.Checks {
			if c.Level != preflight.LevelOK && c.Level != preflight.LevelSkip {
				fmt.Fprintf(e.stdout, "%s %-18s %s\n", mark(c.Level), c.Name, c.Detail)
			}
		}
		if !r.OK() {
			fmt.Fprintf(e.stderr, "\nnodary node install: %d hard failure(s); nothing was changed.\n",
				len(r.Failures()))
			fmt.Fprintf(e.stderr, "  `nodary doctor` shows the full list.\n")
			return ExitFailure
		}
		fmt.Fprintf(e.stdout, "%s preflight          %d checks passed\n", mark(preflight.LevelOK), len(r.Checks))
	} else {
		fmt.Fprintf(e.stdout, "%s preflight          skipped by --skip-preflight\n", mark(preflight.LevelWarn))
	}
	if *dryRun {
		fmt.Fprintf(e.stderr, "\n--dry-run: nothing was changed.\n")
		return ExitOK
	}

	// 2. Enroll first, because the mirror is behind mTLS and a node cannot
	// fetch from its control plane until it has a certificate. This inverts
	// §5's printed order, and it has to: the order in the specification assumes
	// components come from upstream.
	confPath := filepath.Join(configDir, "agent.toml")
	if *gpus != "" || *maxDeployments > 0 || *maintenance != "" {
		if code := writeNodeConfig(e, filepath.Join(configDir, "node.toml"),
			*gpus, *maxDeployments, *maintenance); code != ExitOK {
			return code
		}
	}
	if _, err := os.Stat(confPath); err == nil {
		fmt.Fprintf(e.stdout, "%s enroll             already enrolled (%s)\n", mark(preflight.LevelOK), confPath)
	} else {
		res, err := agent.Enroll(ctx, agent.EnrollOptions{
			Server: *server, Token: *token, CAFingerprint: *fingerprint,
			Name: *name, Dir: filepath.Join(configDir, "pki"),
			NodeConfig: filepath.Join(configDir, "node.toml"),
		})
		if err != nil {
			fmt.Fprintf(e.stderr, "nodary node install: %v\n", err)
			return exitFor(err)
		}
		c := agent.Config{Server: *server, Name: res.Node, CAFingerprint: *fingerprint,
			Certificate: res.CertPath, Key: res.KeyPath, ModelsDir: models}
		if err := os.MkdirAll(configDir, 0o755); err != nil {
			fmt.Fprintf(e.stderr, "nodary node install: %v\n", err)
			return ExitFailure
		}
		if err := os.WriteFile(confPath, agent.RenderConfig(c), 0o644); err != nil {
			fmt.Fprintf(e.stderr, "nodary node install: %v\n", err)
			return ExitFailure
		}
		fmt.Fprintf(e.stdout, "%s enroll             %s, pending approval\n", mark(preflight.LevelOK), res.Node)
	}

	// 3. The layout, before anything is written into it.
	steps, err := install.EnsureLayout(o)
	if err != nil {
		fmt.Fprintf(e.stderr, "nodary node install: %v\n", err)
		return ExitFailure
	}
	report(e, steps)

	if steps, _, err := install.EnsureBinary(buildinfo.Version, o); err != nil {
		fmt.Fprintf(e.stdout, "%s binary             %v\n", mark(preflight.LevelWarn), err)
	} else {
		report(e, steps)
	}

	// 4. Fetch the runtime through the control plane's mirror, and place it.
	conf, err := agent.LoadConfig(confPath)
	if err != nil {
		fmt.Fprintf(e.stderr, "nodary node install: %v\n", err)
		return exitFor(err)
	}
	base, client, code := mirrorClient(e, confPath)
	if code != ExitOK {
		return code
	}
	m, ok := loadManifest(e)
	if !ok {
		return ExitFailure
	}
	var want []components.Component
	for _, c := range m.ForPlatform(resolvePlatform("host")) {
		if c.HasRole(components.RoleNode) && c.Kind != components.KindImage {
			want = append(want, c)
		}
	}
	cache := filepath.Join(*root, "/var/lib/nodary/dist")
	fetched, err := components.Fetch(ctx, want, components.FetchOptions{
		Dir: cache, BaseURL: base, Client: client,
	})
	if err != nil {
		fmt.Fprintf(e.stderr, "nodary node install: %v\n", err)
		return ExitFailure
	}
	fmt.Fprintf(e.stdout, "%s components         %d fetched from %s\n",
		mark(preflight.LevelOK), len(fetched), conf.Server)

	record := filepath.Join(configDir, components.OwnershipFile)
	placed, err := install.PlaceComponents(ctx, fetched, o, record, versionString())
	if err != nil {
		fmt.Fprintf(e.stderr, "nodary node install: %v\n", err)
		return ExitFailure
	}
	report(e, placed)
	for _, f := range fetched {
		if f.Component != "cni-plugins" {
			continue
		}
		step, err := install.PlaceCNIPlugins(f, o)
		if err != nil {
			fmt.Fprintf(e.stderr, "nodary node install: %v\n", err)
			return ExitFailure
		}
		report(e, []install.Step{step})
	}

	// 5. The isolated network, before any deployment can attach to it.
	host := agent.RealHost("", configDir)
	changed, err := agent.EnsureIsolatedNetwork(ctx, host, filepath.Join(*root, agent.CNIConfigDir))
	if err != nil {
		// Not fatal on a staged install: nft and sysctl need root and a real
		// host. Reported so it is not mistaken for success.
		fmt.Fprintf(e.stdout, "%s nodary-isolated    %v\n", mark(preflight.LevelWarn), err)
	} else {
		report(e, []install.Step{{Name: "nodary-isolated", Changed: changed,
			Detail: filepath.Join(*root, agent.CNIConfigDir, agent.IsolatedConfName)}})
	}

	// 6. The unit, and start it.
	units, err := install.WriteUnits(ctx, "node", o)
	if err != nil {
		fmt.Fprintf(e.stderr, "nodary node install: %v\n", err)
		return ExitFailure
	}
	report(e, units)
	// One list, shared with the test that compares it against install.Units:
	// a unit written and never started is installed and listening nowhere.
	// containerd is first because nodary-model@.service requires it, and the
	// agent will try to start a deployment as soon as it has one.
	for _, unit := range startedUnits("node") {
		step, err := install.Start(ctx, unit, o)
		if err != nil {
			fmt.Fprintf(e.stderr, "nodary node install: %v\n", err)
			return ExitFailure
		}
		report(e, []install.Step{step})
	}

	fmt.Fprintf(e.stderr, "\nnodary node %s installed.\n", conf.Name)
	fmt.Fprintf(e.stderr, "  It is pending and will receive no work until an administrator runs\n")
	fmt.Fprintf(e.stderr, "    nodary node approve %s\n", conf.Name)
	fmt.Fprintf(e.stderr, "  `nodary doctor` checks this host; `nodary agent plan` shows what it would run.\n")
	return ExitOK
}

// report prints one line per step, marking what changed.
//
// "changed" and "already correct" are shown differently because that is the
// only way an operator can tell a re-run from a first run, which is what
// idempotent means to the person typing it.
func report(e env, steps []install.Step) {
	for _, s := range steps {
		m := mark(preflight.LevelOK)
		detail := s.Detail
		if s.Changed {
			detail += "  (created)"
		}
		fmt.Fprintf(e.stdout, "%s %-18s %s\n", m, s.Name, detail)
	}
}
