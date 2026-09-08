package cli

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"crypto/rand"
	"encoding/hex"
	"github.com/nodarynet/nodary/internal/api"
	"github.com/nodarynet/nodary/internal/audit"
	"github.com/nodarynet/nodary/internal/buildinfo"
	"github.com/nodarynet/nodary/internal/components"
	"github.com/nodarynet/nodary/internal/identity"
	"github.com/nodarynet/nodary/internal/install"
	"github.com/nodarynet/nodary/internal/paths"
	"github.com/nodarynet/nodary/internal/preflight"
)

func cmdServer(e env, args []string) int {
	if len(args) == 0 {
		fmt.Fprintf(e.stderr, "nodary server: expected a subcommand (install, start, status)\n")
		return ExitUsage
	}
	switch args[0] {
	case "install":
		return cmdServerInstall(e, args[1:])
	case "start":
		return cmdServerStart(e, args[1:])
	case "status":
		return cmdServerStatus(e, args[1:])
	case "stop":
		// Stopping is systemd's job, and saying so is more useful than a verb
		// that shells out to it. R5 owns the unit.
		fmt.Fprintf(e.stderr,
			"nodary server stop: the control plane runs under systemd; use `systemctl stop nodary-server`.\n")
		return ExitUsage
	}
	fmt.Fprintf(e.stderr, "nodary server: unknown subcommand %q\n", args[0])
	return ExitUsage
}

// serverConfigPath is where server.toml lives, beside the other configuration.
func serverConfigPath(flagValue string) string {
	if flagValue != "" {
		return flagValue
	}
	return filepath.Join(filepath.Dir(paths.SecretKey()), "server.toml")
}

func cmdServerInstall(e env, args []string) int {
	fs := newFlagSet(e, "server install")
	dbPath, keyPath, _ := stateFlags(fs)
	confPath := fs.String("config", "", "server.toml path")
	bind := fs.String("bind", "0.0.0.0:8443", "address to serve on")
	host := fs.String("host", "", "hostname operators and nodes will use (repeatable, comma-separated)")
	root := fs.String("root", "", "install into this prefix instead of / (for testing; nothing is started)")
	svcUser := fs.String("user", "nodary", "the service account; empty runs as root")
	withNode := fs.Bool("with-node", false,
		"also install this host as a GPU node of the control plane it just created (00 §2)")
	offline := fs.Bool("offline", false,
		"do not contact any upstream source; the mirror is whatever is already in the data directory")
	skipPreflight := fs.Bool("skip-preflight", false,
		"do not run the host checks. Records that they were skipped; it does not make them pass")
	if code := parseFlags(e, fs, args); code >= 0 {
		return code
	}

	ctx := context.Background()
	o := install.Options{Root: *root, User: *svcUser}

	// 1. Preflight. docs/specs/01-install.md §4 step 1: abort on any hard
	// failure, printing every failure at once.
	if !*skipPreflight {
		r := preflight.Run(ctx, preflight.Options{
			Role: preflight.RoleServer, DataDir: filepath.Join(*root, "/var/lib/nodary"),
		})
		for _, c := range r.Checks {
			if c.Level != preflight.LevelOK && c.Level != preflight.LevelSkip {
				fmt.Fprintf(e.stdout, "%s %-18s %s\n", mark(c.Level), c.Name, c.Detail)
			}
		}
		if !r.OK() {
			fmt.Fprintf(e.stderr, "\nnodary server install: %d hard failure(s); nothing was changed.\n",
				len(r.Failures()))
			return ExitFailure
		}
	}

	// 2. The service account, then the layout it owns. Both before anything is
	// written into it, and both idempotent.
	//
	// Not fatal when this is not root: `server install` is legitimately run
	// unprivileged against a --db in a home directory, and refusing that would
	// make every test and every demo need sudo. What it must not do is claim to
	// have set an ownership it could not.
	if step, err := install.EnsureUser(ctx, *svcUser, o); err != nil {
		fmt.Fprintf(e.stdout, "%s user               %v\n", mark(preflight.LevelWarn), err)
		o.User = ""
	} else {
		report(e, []install.Step{step})
	}
	steps, err := install.EnsureLayout(o)
	if err != nil {
		fmt.Fprintf(e.stdout, "%s layout             %v\n", mark(preflight.LevelWarn), err)
	} else {
		report(e, steps)
	}

	// The binary at docs/specs/01-install.md §12's location, before the units
	// that invoke it. Not fatal unprivileged: the units are then written
	// pointing at a path that will exist once somebody installs properly.
	if step, _, err := install.EnsureBinary(buildinfo.Version, o); err != nil {
		fmt.Fprintf(e.stdout, "%s binary             %v\n", mark(preflight.LevelWarn), err)
	} else {
		report(e, []install.Step{step})
	}

	// --root prefixes the *default* path only. An explicit --config is taken as
	// given: a caller who named a file meant that file, and prefixing it would
	// silently write somewhere else — which is exactly what happened the first
	// time this was run with both.
	conf := serverConfigPath(*confPath)
	if *root != "" && *confPath == "" {
		conf = filepath.Join(*root, conf)
	}
	dir := filepath.Dir(conf)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		fmt.Fprintf(e.stderr, "nodary server install: %v\n", err)
		return ExitFailure
	}

	// The database and the sealing key first: the agent CA is sealed under it,
	// so a missing key must fail here rather than halfway through the PKI.
	s, ok := openSession(e, "server install", *dbPath, *keyPath, "")
	if !ok {
		return ExitFailure
	}
	defer s.Close()
	key, err := s.key()
	if err != nil {
		fmt.Fprintf(e.stderr, "nodary server install: %v\n", err)
		return ExitFailure
	}

	// Record which key seals this database, before anything is sealed with it.
	//
	// R1-36's refusal — "this database was sealed under a different key" — is
	// armed only once the installation row names one, and on a fresh control
	// plane nothing named one. BindKey had a single caller, the first TOTP seal,
	// and internal/identity/keybind.go anticipated exactly this gap: *"it moves
	// when a second subsystem seals something -- R2-40's CA key is the first
	// candidate"*. R2-40 arrived; the binding did not follow. So a control plane
	// whose only sealed material was the agent CA started happily under a
	// replaced secret.key and made that CA permanently unreadable — the
	// unrecoverable path 11 §5 is about, with nothing said.
	//
	// Measured on a fresh install before this: `SELECT secret_key_id FROM
	// installation` returned no row at all.
	//
	// Only when unbound, so re-running the install does not append a record
	// saying nothing happened. An install that predates this binds on its next
	// run, which is how an existing control plane gets the protection.
	if bound, err := identity.BoundKeyID(ctx, s.db.Read()); err != nil {
		fmt.Fprintf(e.stderr, "nodary server install: %v\n", err)
		return ExitFailure
	} else if bound == "" {
		if _, err := s.log.Act(ctx, audit.Request{
			Actor:  s.who.Actor,
			Action: "installation.bind-key",
			Target: &audit.Target{Kind: "installation", ID: key.ID()},
		}, func(m audit.Mutation) error {
			return identity.BindKey(ctx, m, s.now, key)
		}); err != nil {
			fmt.Fprintf(e.stderr, "nodary server install: %v\n", err)
			return ExitFailure
		}
		report(e, []install.Step{{Name: "sealing key", Changed: true,
			Detail: "bound to " + key.ID() + "; a different key will now be refused"}})
	}

	// 0700: it holds the agent CA's sealed key (docs/specs/01-install.md §12).
	pki := filepath.Join(dir, "pki")
	if err := os.MkdirAll(pki, 0o700); err != nil {
		fmt.Fprintf(e.stderr, "nodary server install: %v\n", err)
		return ExitFailure
	}

	hosts := []string{"localhost", "127.0.0.1"}
	if *host != "" {
		hosts = append(hosts, splitList(*host)...)
	}
	cert, tlsKey, fingerprint, err := api.EnsureServerCertificate(pki, s.now, hosts)
	if err != nil {
		fmt.Fprintf(e.stderr, "nodary server install: %v\n", err)
		return ExitFailure
	}
	if _, err := api.EnsureAgentCA(context.Background(), pki, key, s.now); err != nil {
		fmt.Fprintf(e.stderr, "nodary server install: %v\n", err)
		return ExitFailure
	}

	c := api.ServerConfig{Bind: *bind, DataDir: filepath.Dir(s.db.Path())}
	c.TLS.Certificate, c.TLS.Key = cert, tlsKey
	if err := os.WriteFile(conf, api.RenderServerConfig(c), 0o640); err != nil {
		fmt.Fprintf(e.stderr, "nodary server install: %v\n", err)
		return ExitFailure
	}

	// 3. Resolve the node runtime into the mirror.
	if *offline {
		report(e, []install.Step{{Name: "components",
			Detail: "skipped by --offline; nodes will fetch whatever is already in the mirror"}})
	} else {
		fetchIntoMirror(e, ctx, filepath.Dir(s.db.Path()))
	}

	// The units, so `systemctl enable --now nodary-server` works. Written
	// after server.toml, because the unit's ExecStart reads it at startup.
	units, err := install.WriteUnits(ctx, "server", o)
	if err != nil {
		fmt.Fprintf(e.stderr, "nodary server install: %v\n", err)
		return ExitFailure
	}
	report(e, units)

	// The gateway's master key. Generated here and never a default: one built
	// in would be the same key on every install, which is no key at all
	// (docs/specs/06-gateway.md §1).
	gwEnv := filepath.Join(dir, "gateway.env")
	if _, err := os.Stat(gwEnv); os.IsNotExist(err) {
		master := "sk-nodary-" + randomToken()
		if err := os.WriteFile(gwEnv, []byte("NODARY_MASTER_KEY="+master+"\n"), 0o640); err != nil {
			fmt.Fprintf(e.stderr, "nodary server install: %v\n", err)
			return ExitFailure
		}
		report(e, []install.Step{{Name: "gateway key", Changed: true, Detail: gwEnv}})
	} else {
		report(e, []install.Step{{Name: "gateway key", Detail: gwEnv}})
	}

	// Last: hand everything just written to the account the units run as. The
	// install is root and the service is not, so this is what makes the
	// difference between a system that is installed and one that starts.
	owned, err := install.EnsureOwnership(o)
	if err != nil {
		fmt.Fprintf(e.stderr, "nodary server install: %v\n", err)
		return ExitFailure
	}
	report(e, owned)

	// The first administrator, as a one-time link rather than an account this
	// install invents. R5-08 is one line — **no default password ever exists** —
	// and every other shape creates one: a generated password printed here is a
	// default until somebody changes it, and a /setup left open until first use
	// is a default that lasts until somebody notices.
	//
	// Minting replaces any link still outstanding, so re-running the install on
	// a control plane nobody finished setting up hands the operator a working
	// one instead of a dead one they cannot see.
	var setupURL string
	if _, err := s.log.Act(ctx, audit.Request{
		Actor:  s.who.Actor,
		Action: "installation.setup-link",
	}, func(m audit.Mutation) error {
		token, _, err := identity.MintSetup(ctx, m, s.now)
		if err != nil {
			return err
		}
		setupURL = api.SetupURL("https://"+firstHost(hosts, *bind), token)
		return nil
	}); errors.Is(err, identity.ErrSetupDone) {
		setupURL = ""
	} else if err != nil {
		fmt.Fprintf(e.stderr, "nodary server install: %v\n", err)
		return ExitFailure
	}

	// 10. A join token, so the printed command is one an operator can run rather
	// than one they have to complete. It expires in an hour and enrols one node
	// (02 §4: minutes to hours), which is the shape of a credential printed to a
	// terminal — long enough to walk to the GPU host, short enough that the
	// scrollback stops being a way in.
	var joinToken string
	if _, err := s.log.Act(ctx, audit.Request{
		Actor: s.who.Actor, Action: "token.join",
	}, func(m audit.Mutation) error {
		_, plain, err := identity.MintJoinToken(ctx, m, s.who.Role, s.now,
			s.who.Actor.ID, 1, s.now.Add(time.Hour))
		joinToken = plain
		return err
	}); err != nil {
		fmt.Fprintf(e.stderr, "nodary server install: %v\n", err)
		return ExitFailure
	}

	// 8, last. The units are started after every write this install makes, not
	// in 01 §4's printed position: the control plane opens the same database,
	// and there is no reason to have two writers on it while the install is
	// still minting credentials into it.
	for _, unit := range []string{"nodary-server.service"} {
		step, err := install.Start(ctx, unit, o)
		if err != nil {
			// Not fatal. Everything is written and correct; what failed is the
			// starting, and an operator can see why with `systemctl status`.
			fmt.Fprintf(e.stdout, "%s %-18s %v\n", mark(preflight.LevelWarn), "start", err)
		} else {
			report(e, []install.Step{step})
		}
	}

	fmt.Fprintln(e.stdout, fingerprint)
	fmt.Fprintf(e.stderr, "Wrote %s. The control plane serves on %s.\n", conf, c.Bind)
	if setupURL != "" {
		fmt.Fprintf(e.stderr, "\nOpen this once, within %d minutes, to create the first administrator:\n\n  %s\n\n"+
			"  Nobody — including this install — knows a password until somebody sets one there.\n",
			int(identity.SetupTTL.Minutes()), setupURL)
	} else {
		fmt.Fprintf(e.stderr, "\nThis control plane already has an administrator; no setup link was issued.\n")
	}
	fmt.Fprintf(e.stderr, "\nNodes pin that fingerprint. On each GPU host:\n\n")
	fmt.Fprintf(e.stderr, "  nodary node install --server https://%s --token %s \\\n      --ca-fingerprint %s\n\n",
		firstHost(hosts, *bind), joinToken, fingerprint)
	fmt.Fprintf(e.stderr, "  That token enrols one node and expires in an hour; `nodary token join` mints more.\n\n")
	fmt.Fprintf(e.stderr, "The agent CA is separate from that certificate and its key is sealed\nunder %s.\n", s.keyPath)

	if *withNode {
		return installLocalNode(e, s, *root, *bind, fingerprint)
	}
	return ExitOK
}

// installLocalNode is docs/specs/00-overview.md §2's single-box deployment: the
// control plane and one GPU host on the same machine.
//
// It **composes the two installs** rather than reimplementing either, for the
// reason `node install` itself composes `components fetch` and `node enroll` —
// the path an operator would take by hand is the path this takes, so there is
// one implementation to be wrong about. It is also the shape
// scripts/verify-privileged.sh has been exercising all along, now as one verb.
func installLocalNode(e env, s *session, root, bind, fingerprint string) int {
	if root != "" {
		// A staged install starts nothing, so there is no control plane to
		// enroll into. Said rather than attempted: the failure would otherwise
		// be a connection refused that names none of this.
		fmt.Fprintf(e.stderr, "\nnodary server install: --with-node needs a running control plane, "+
			"and --root stages one without starting it.\n")
		return ExitUsage
	}

	// 127.0.0.1, not the printed hostname. The server certificate always covers
	// it (EnsureServerCertificate seeds `localhost` and `127.0.0.1` before any
	// --host), so the single-box case never depends on the operator having named
	// this machine correctly.
	_, port, err := net.SplitHostPort(bind)
	if err != nil {
		fmt.Fprintf(e.stderr, "nodary server install: cannot read a port from %q: %v\n", bind, err)
		return ExitFailure
	}
	addr := net.JoinHostPort("127.0.0.1", port)

	// **The control plane has to be listening.** `systemctl enable --now`
	// returns once the unit is active, and `Type=exec` means active as soon as
	// the binary has been exec'd — not once it holds the port. Enrolling into
	// that gap fails with `connection refused`, which would show up as an
	// install that works most of the time.
	fmt.Fprintf(e.stderr, "\nWaiting for the control plane on %s…\n", addr)
	if !waitForListener(addr, 30*time.Second) {
		fmt.Fprintf(e.stderr, "nodary server install: nothing is listening on %s after 30s.\n"+
			"  `systemctl status nodary-server` says why; then `nodary node install` finishes this.\n", addr)
		return ExitFailure
	}

	// Its own token. The one already printed is for a *remote* node, and
	// spending it here would hand the operator a command that fails the first
	// time they run it somewhere else.
	var token string
	if _, err := s.log.Act(context.Background(), audit.Request{
		Actor: s.who.Actor, Action: "token.join",
	}, func(m audit.Mutation) error {
		_, plain, err := identity.MintJoinToken(context.Background(), m, s.who.Role, s.now,
			s.who.Actor.ID, 1, s.now.Add(time.Hour))
		token = plain
		return err
	}); err != nil {
		fmt.Fprintf(e.stderr, "nodary server install: %v\n", err)
		return ExitFailure
	}

	fmt.Fprintf(e.stderr, "\n== Installing this host as a node ==\n")
	return cmdNodeInstall(e, []string{
		"--server", "https://" + addr, "--token", token, "--ca-fingerprint", fingerprint,
	})
}

// waitForListener returns once something accepts on addr, or the deadline
// passes.
//
// A TCP connect rather than a request: the question is whether the port is
// held, and the enrolment immediately after is the real test of whether the
// control plane works. Answering the smaller question keeps this from having
// its own opinion about what "ready" means.
func waitForListener(addr string, within time.Duration) bool {
	deadline := time.Now().Add(within)
	for {
		conn, err := net.DialTimeout("tcp", addr, time.Second)
		if err == nil {
			conn.Close()
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(250 * time.Millisecond)
	}
}

func cmdServerStart(e env, args []string) int {
	fs := newFlagSet(e, "server start")
	dbPath, keyPath, _ := stateFlags(fs)
	confPath := fs.String("config", "", "server.toml path")
	if code := parseFlags(e, fs, args); code >= 0 {
		return code
	}

	c, err := api.LoadServerConfig(serverConfigPath(*confPath))
	if err != nil {
		fmt.Fprintf(e.stderr, "nodary server start: %v\n", err)
		fmt.Fprintf(e.stderr, "  run `nodary server install` first\n")
		return ExitFailure
	}

	s, ok := openSession(e, "server start", *dbPath, *keyPath, "")
	if !ok {
		return ExitFailure
	}
	defer s.Close()

	srv := api.New(api.Options{DB: s.db, Log: s.log, Key: s.key,
		PKI:  filepath.Join(filepath.Dir(serverConfigPath(*confPath)), "pki"),
		Dist: api.DistDir(c.DataDir)})
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	fmt.Fprintf(e.stderr, "serving %s%s on %s\n", "https://", c.Bind, api.Prefix)
	if err := srv.Serve(ctx, c); err != nil {
		fmt.Fprintf(e.stderr, "nodary server start: %v\n", err)
		return ExitFailure
	}
	return ExitOK
}

func cmdServerStatus(e env, args []string) int {
	fs := newFlagSet(e, "server status")
	format := formatFlag(fs)
	dbPath := dbFlag(fs)
	confPath := fs.String("config", "", "server.toml path")
	if code := parseFlags(e, fs, args); code >= 0 {
		return code
	}
	if !checkFormat(e, *format) {
		return ExitUsage
	}

	conf := serverConfigPath(*confPath)
	doc := map[string]any{"config": conf}
	c, err := api.LoadServerConfig(conf)
	if err != nil {
		doc["installed"] = false
		doc["detail"] = err.Error()
	} else {
		doc["installed"] = true
		doc["bind"] = c.Bind
		doc["tls_certificate"] = c.TLS.Certificate
	}

	path, _ := resolveDB(*dbPath)
	if db, ok := openForReading(e, "server status", path); ok {
		defer db.Close()
		res, err := audit.VerifyDB(context.Background(), db)
		doc["audit_records"] = res.Records
		doc["audit_ok"] = err == nil && res.OK()
		// An installation nobody has finished setting up is worth saying out
		// loud: the window closes silently, and the only other symptom is a
		// login that nobody on earth can perform.
		if pending, err := identity.SetupPending(context.Background(), db.Read(), time.Now()); err == nil {
			doc["setup_pending"] = pending
		}
	} else {
		doc["database"] = "unreadable"
	}

	if *format == "json" {
		return writeJSON(e, "server status", doc)
	}
	for _, k := range []string{"installed", "bind", "tls_certificate", "setup_pending",
		"audit_records", "audit_ok", "detail"} {
		if v, ok := doc[k]; ok {
			fmt.Fprintf(e.stdout, "%-16s %v\n", k, v)
		}
	}
	return ExitOK
}

func splitList(s string) []string {
	var out []string
	for _, p := range splitComma(s) {
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// firstHost is the address an operator will actually type, host **and port**.
//
// Both halves are load-bearing and both were missing. A named --host is a name,
// not an address: printing `https://nodary.example.internal` for a control
// plane on :8443 gives a setup link and a join command that quietly connect to
// 443. And the default --bind is `0.0.0.0:8443`, so an install with no --host
// printed `https://0.0.0.0:8443` — a wildcard is what to listen on and never
// what to connect to.
//
// So: the port always comes from --bind, and the host is the first real name
// given, falling back to this machine's own when the bind names no address a
// client could use.
func firstHost(hosts []string, bind string) string {
	host, port, err := net.SplitHostPort(bind)
	if err != nil {
		return bind
	}
	for _, h := range hosts {
		if h != "localhost" && h != "127.0.0.1" {
			return net.JoinHostPort(h, port)
		}
	}
	if ip := net.ParseIP(host); host == "" || (ip != nil && ip.IsUnspecified()) {
		if name, err := os.Hostname(); err == nil && name != "" {
			return net.JoinHostPort(strings.ToLower(name), port)
		}
	}
	return bind
}

// randomToken is 256 bits of randomness for the gateway's master key.
//
// It is generated per install and written to a file only root and the service
// account can read. docs/specs/06-gateway.md §1 has LiteLLM stateless behind a
// single key that is never exposed to clients; a built-in default would be that
// key on every install in the world.
func randomToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		// Refusing is better than a predictable key, and the caller writes the
		// file — so an empty string here produces a config the gateway rejects
		// rather than one that works with a guessable credential.
		return ""
	}
	return hex.EncodeToString(b)
}

// fetchIntoMirror is 01 §4 step 3: the cache every GPU host bootstraps from.
//
// **It resolves the node set, not the server's own.** docs/specs/01-install.md
// §3 is the reason this belongs in the install rather than in a verb somebody
// remembers to run: only the control-plane host ever contacts an upstream
// source, and every node fetches this cache over mTLS. A control plane with an
// empty mirror is one where `node install` fails on a machine with no internet
// — which is the machine this product is for.
//
// 01 §4 step 2 also has the operator choose the server's own stack, `minimal`
// or `all`. That is **not implemented, deliberately**: every server-role
// component in the manifest is an `image` — LiteLLM, Prometheus and Grafana are
// pulled by a container runtime from a registry by digest, not staged into a
// file cache — and no unit in this slice runs one. A `--components` flag today
// would offer a choice between two sets the install cannot act on, which is
// worse than not offering it. Manifest.Select already implements the semantics
// for when there is something to select.
//
// The platform is this host's. A control plane serving nodes of another
// architecture needs `components fetch --platform` as well, which is what that
// verb is for.
func fetchIntoMirror(e env, ctx context.Context, dataDir string) {
	m, ok := loadManifest(e)
	if !ok {
		return
	}
	plat := resolvePlatform("host")
	want, err := mirrorComponents(m, plat)
	if err != nil {
		fmt.Fprintf(e.stderr, "nodary server install: %v\n", err)
		return
	}
	if len(want) == 0 {
		report(e, []install.Step{{Name: "components", Detail: "nothing to resolve for " + plat}})
		return
	}

	cache := filepath.Join(dataDir, "dist")
	fetched, err := components.Fetch(ctx, want, components.FetchOptions{Dir: cache, Platform: plat})
	if err != nil {
		// A warning, not a failure. Everything else about this control plane is
		// correct, and an install that rolled back because a CDN was
		// unreachable would leave nothing behind for the operator to retry
		// from. What it must not do is stay quiet: an empty mirror is a fleet
		// that cannot be built, and the symptom appears on a *different*
		// machine much later.
		fmt.Fprintf(e.stdout, "%s %-18s %v\n", mark(preflight.LevelWarn), "components", err)
		fmt.Fprintf(e.stdout, "%s %-18s nodes cannot bootstrap until this succeeds; "+
			"re-run the install or `nodary components fetch --role node`\n",
			mark(preflight.LevelWarn), "")
		return
	}
	// Downloaded and already-correct are reported apart, because that is the
	// only way an operator can tell a re-run from a first run — the same reason
	// every other step here says whether it changed anything.
	var downloaded int
	for _, f := range fetched {
		if f.Placement == components.PlacedFetched {
			downloaded++
		}
	}
	detail := fmt.Sprintf("%d in %s for nodes to fetch", len(fetched), cache)
	if downloaded == 0 {
		detail += " (all present and verified)"
	}
	report(e, []install.Step{{Name: "components", Changed: downloaded > 0, Detail: detail}})
}

// mirrorComponents is what the mirror must hold, separated from fetching it so
// that the decision can be asserted without a network.
//
// **The node set.** Getting this wrong is invisible on the control plane and
// fatal on a GPU host: `node install` on a machine with no internet reaches an
// empty mirror and stops, one machine and some hours away from the change that
// caused it.
func mirrorComponents(m *components.Manifest, plat string) ([]components.Component, error) {
	selected, err := m.Select(components.RoleNode, "minimal")
	if err != nil {
		return nil, err
	}
	// Images are pulled by the container runtime from a registry by digest,
	// which is a different mechanism with different credentials — and a
	// platform with no source for a component is not a component to fetch.
	var want []components.Component
	for _, c := range selected {
		if c.Kind == components.KindImage {
			continue
		}
		if _, ok := c.Platforms[plat]; !ok {
			continue
		}
		want = append(want, c)
	}
	return want, nil
}
