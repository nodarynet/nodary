package cli

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"crypto/rand"
	"encoding/hex"
	"github.com/nodarynet/nodary/internal/api"
	"github.com/nodarynet/nodary/internal/audit"
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
	skipPreflight := fs.Bool("skip-preflight", false,
		"do not run the host checks. Records that they were skipped; it does not make them pass")
	if code := parseFlags(e, fs, args); code >= 0 {
		return code
	}

	ctx := context.Background()
	o := install.Options{Root: *root, Binary: selfPath(), User: *svcUser}

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

	// 3. The units, so `systemctl enable --now nodary-server` works. Written
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

	fmt.Fprintln(e.stdout, fingerprint)
	fmt.Fprintf(e.stderr, "Wrote %s. The control plane serves on %s.\n", conf, c.Bind)
	fmt.Fprintf(e.stderr, "\nNodes pin that fingerprint. On each GPU host:\n\n")
	fmt.Fprintf(e.stderr, "  nodary node install --server https://%s --token nodary_jt_… \\\n      --ca-fingerprint %s\n\n",
		firstHost(hosts, *bind), fingerprint)
	fmt.Fprintf(e.stderr, "The agent CA is separate from that certificate and its key is sealed\nunder %s.\n", s.keyPath)
	return ExitOK
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
	} else {
		doc["database"] = "unreadable"
	}

	if *format == "json" {
		return writeJSON(e, "server status", doc)
	}
	for _, k := range []string{"installed", "bind", "tls_certificate", "audit_records", "audit_ok", "detail"} {
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

func firstHost(hosts []string, bind string) string {
	for _, h := range hosts {
		if h != "localhost" && h != "127.0.0.1" {
			return h
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
