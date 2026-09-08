package cli

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/nodarynet/nodary/internal/gateway"
	"github.com/nodarynet/nodary/internal/store"
)

func cmdGateway(e env, args []string) int {
	if len(args) == 0 {
		fmt.Fprintf(e.stderr, "nodary gateway: expected a subcommand (start, sync)\n")
		return ExitUsage
	}
	switch args[0] {
	case "start":
		return cmdGatewayStart(e, args[1:])
	case "sync":
		return cmdGatewaySync(e, args[1:])
	}
	fmt.Fprintf(e.stderr, "nodary gateway: unknown subcommand %q (want start or sync)\n", args[0])
	return ExitUsage
}

// cmdGatewayStart serves docs/specs/06-gateway.md's OpenAI surface.
//
// It runs in the foreground and logs to stderr, for the reason `agent run`
// does: systemd owns its lifetime, and R5's nodary-gateway.service is where
// that belongs.
func cmdGatewayStart(e env, args []string) int {
	fs := newFlagSet(e, "gateway start")
	dbPath := dbFlag(fs)
	bind := fs.String("bind", "127.0.0.1:8080", "address to serve the inference API on")
	upstream := fs.String("upstream", "http://127.0.0.1:4000", "the LiteLLM proxy")
	masterKey := fs.String("master-key", "", "the key the gateway presents to LiteLLM")
	if code := parseFlags(e, fs, args); code >= 0 {
		return code
	}
	if *masterKey == "" {
		// Refused rather than defaulted. docs/specs/06-gateway.md §1 has LiteLLM
		// stateless behind a single key; a built-in default would be the same
		// key on every install, which is no key at all.
		fmt.Fprintf(e.stderr, "nodary gateway start: --master-key is required; it is the credential "+
			"LiteLLM accepts and it must not be a default\n")
		return ExitUsage
	}

	// A writing handle: the gateway records usage, and authentication updates
	// last_used_at (docs/specs/06-gateway.md §2).
	path, _ := resolveDB(*dbPath)
	db, err := store.Open(context.Background(), path)
	if err != nil {
		fmt.Fprintf(e.stderr, "nodary gateway start: %v\n", err)
		return ExitFailure
	}
	defer db.Close()

	log := slog.New(slog.NewTextHandler(e.stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	g, gerr := gateway.New(gateway.Options{DB: db, Upstream: *upstream,
		MasterKey: *masterKey, Log: log})
	if err := gerr; err != nil {
		fmt.Fprintf(e.stderr, "nodary gateway start: %v\n", err)
		return exitFor(err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	fmt.Fprintf(e.stderr, "serving the inference API on %s, proxying to %s\n", *bind, *upstream)
	if err := gateway.Serve(ctx, g.Handler(), *bind); err != nil {
		fmt.Fprintf(e.stderr, "nodary gateway start: %v\n", err)
		return ExitFailure
	}
	return ExitOK
}
