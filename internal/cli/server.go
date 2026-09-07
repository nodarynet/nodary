package cli

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/nodarynet/nodary/internal/api"
	"github.com/nodarynet/nodary/internal/audit"
	"github.com/nodarynet/nodary/internal/paths"
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
	if code := parseFlags(e, fs, args); code >= 0 {
		return code
	}

	conf := serverConfigPath(*confPath)
	dir := filepath.Dir(conf)
	if err := os.MkdirAll(dir, 0o750); err != nil {
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

	pki := filepath.Join(dir, "pki")
	if err := os.MkdirAll(pki, 0o750); err != nil {
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
		PKI: filepath.Join(filepath.Dir(serverConfigPath(*confPath)), "pki")})
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	fmt.Fprintf(e.stderr, "serving %s%s on %s\n", "https://", c.Bind, api.Prefix)
	if err := api.Serve(ctx, srv.Handler(), c); err != nil {
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
