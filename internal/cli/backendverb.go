package cli

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"github.com/nodarynet/nodary/internal/backend"
	"github.com/nodarynet/nodary/internal/config"
	"github.com/nodarynet/nodary/internal/store"
)

// cmdBackend is docs/specs/04-backends.md §9.
//
// The reads only, for now. `register` and `remove` need a registry to write to
// — a control plane one, since a descriptor an operator copies to each node by
// hand is two sources of truth that are guaranteed to drift — and that is
// R2-03's table.
func cmdBackend(e env, args []string) int {
	if len(args) == 0 {
		fmt.Fprintf(e.stderr, "nodary backend: expected a subcommand (list, show)\n")
		return ExitUsage
	}
	switch args[0] {
	case "list":
		return cmdBackendList(e, args[1:])
	case "show":
		return cmdBackendShow(e, args[1:])
	case "register", "remove":
		fmt.Fprintf(e.stderr,
			"nodary backend %s: not implemented in this release (%s).\n"+
				"  This build serves the descriptors compiled into it: %s.\n",
			args[0], versionString(), strings.Join(builtinNames(e), ", "))
		return ExitFailure
	}
	fmt.Fprintf(e.stderr, "nodary backend: unknown subcommand %q (want list or show)\n", args[0])
	return ExitUsage
}

func builtinNames(e env) []string {
	all, err := backend.Builtins()
	if err != nil {
		return nil
	}
	return backend.Names(all)
}

func cmdBackendList(e env, args []string) int {
	fs := newFlagSet(e, "backend list")
	format := formatFlag(fs)
	dbPath := dbFlag(fs)
	server, credsPath := serverFlag(fs), credentialsFlag(fs)
	if code := parseFlags(e, fs, args); code >= 0 {
		return code
	}
	if !checkFormat(e, *format) {
		return ExitUsage
	}
	rem, code := remoteFor(e, "backend list", *server, *credsPath, *dbPath)
	if code >= 0 {
		return code
	}

	reports, ok := backendReports(e, "backend list", rem, *dbPath)
	if !ok {
		return ExitFailure
	}
	if *format == "json" {
		return writeJSON(e, "backend list", map[string]any{"backends": reports})
	}
	fmt.Fprintf(e.stdout, "%-12s %-10s %-14s %-9s %s\n",
		"NAME", "API", "LAYOUT", "SOURCE", "CAPABILITIES")
	for _, b := range reports {
		fmt.Fprintf(e.stdout, "%-12s %-10s %-14s %-9s %s\n",
			b.Name, b.API, b.WeightsLayout, b.Source, capabilityLine(b))
	}
	return ExitOK
}

func cmdBackendShow(e env, args []string) int {
	fs := newFlagSet(e, "backend show")
	format := formatFlag(fs)
	dbPath := dbFlag(fs)
	server, credsPath := serverFlag(fs), credentialsFlag(fs)
	if code := parseFlags(e, fs, args); code >= 0 {
		return code
	}
	if !checkFormat(e, *format) {
		return ExitUsage
	}
	if fs.NArg() != 1 {
		fmt.Fprintf(e.stderr, "nodary backend show: expected one backend name\n")
		return ExitUsage
	}
	name := fs.Arg(0)
	rem, code := remoteFor(e, "backend show", *server, *credsPath, *dbPath)
	if code >= 0 {
		return code
	}

	var b backend.Report
	if rem != nil {
		if _, err := rem.get("/backends/"+url.PathEscape(name), &b); err != nil {
			fmt.Fprintf(e.stderr, "nodary backend show: %v\n", err)
			return exitFor(err)
		}
	} else if db, ok := registryDB(e, "backend show", *dbPath); ok {
		defer db.Close()
		var err error
		if b, err = config.BackendReport(context.Background(), db.Read(), name); err != nil {
			fmt.Fprintf(e.stderr, "nodary backend show: %v\n", err)
			return ExitFailure
		}
	} else {
		d, err := backend.Get(name)
		if err != nil {
			fmt.Fprintf(e.stderr, "nodary backend show: %v\n", err)
			return ExitFailure
		}
		b = backend.NewReport(d, backend.SourceBuiltIn, "")
	}

	if *format == "json" {
		return writeJSON(e, "backend show", b)
	}
	fmt.Fprintf(e.stdout, "%s (%s)\n", b.Name, b.Source)
	fmt.Fprintf(e.stdout, "  api            %s\n", b.API)
	fmt.Fprintf(e.stdout, "  weights        %s at %s\n", b.WeightsLayout, orElse(b.MountPath, "—"))
	fmt.Fprintf(e.stdout, "  image          %s\n", orElse(b.ImageDefault, "—"))
	fmt.Fprintf(e.stdout, "  port           %d\n", b.ContainerPort)
	fmt.Fprintf(e.stdout, "  capabilities   %s\n", capabilityLine(b))
	// The two lists stay two lists: a name in `params` is translated and means
	// the same thing against another backend, a name in `extra` is passed
	// through and does not (04 §3). Flattening them would lose exactly the
	// distinction an operator needs before moving a deployment.
	fmt.Fprintf(e.stdout, "  params         %s\n", orElse(strings.Join(b.Args, ", "), "—"))
	if len(b.Extra) > 0 {
		fmt.Fprintf(e.stdout, "  extra          %s  (passed through, not translated)\n",
			strings.Join(b.Extra, ", "))
	}
	fmt.Fprintf(e.stdout, "  probe          health %s, ready %s, timeout %ds\n",
		orElse(b.Probe.Health, "—"), orElse(b.Probe.Ready, "—"), b.Probe.ReadyTimeoutS)
	if b.SHA256 != "" {
		fmt.Fprintf(e.stdout, "  sha256         %s\n", b.SHA256)
	}
	return ExitOK
}

// backendReports is the listing, from whichever side this invocation reads.
func backendReports(e env, verb string, rem *remote, dbPath string) ([]backend.Report, bool) {
	if rem != nil {
		out, err := remoteList[backend.Report](rem, "/backends", "backends", nil)
		if err != nil {
			fmt.Fprintf(e.stderr, "nodary %s: %v\n", verb, err)
			return nil, false
		}
		return out, true
	}
	db, ok := registryDB(e, verb, dbPath)
	if !ok {
		// No registry reachable, so the built-ins are the whole answer — and
		// they are a complete one on a machine with no control plane on it,
		// which is where `backend list` is most often run.
		all, err := backend.Builtins()
		if err != nil {
			fmt.Fprintf(e.stderr, "nodary %s: %v\n", verb, err)
			return nil, false
		}
		return backend.Reports(all), true
	}
	defer db.Close()
	out, err := config.BackendReports(context.Background(), db.Read())
	if err != nil {
		fmt.Fprintf(e.stderr, "nodary %s: %v\n", verb, err)
		return nil, false
	}
	return out, true
}

// registryDB opens the control plane's database if this machine has one.
//
// Absent is not an error here. The built-in descriptors are compiled into this
// binary and are the whole answer on an operator's laptop; what an unreadable
// registry costs is the *registered* ones, so it is said once rather than
// failing a read that can be answered.
func registryDB(e env, verb, dbPath string) (*store.DB, bool) {
	path, explicit := resolveDB(dbPath)
	db, err := store.OpenReadOnly(context.Background(), path)
	if err != nil {
		if explicit {
			// Named explicitly and not readable is a mistake worth reporting:
			// the operator meant that file.
			fmt.Fprintf(e.stderr, "nodary %s: %v\n", verb, err)
		} else {
			fmt.Fprintf(e.stderr,
				"nodary %s: no control plane on this machine, so this is what the binary "+
					"carries; registered backends live on the control plane (--server).\n", verb)
		}
		return nil, false
	}
	return db, true
}

// capabilityLine renders only what a backend *has*.
//
// A row of `tensor_parallel=false lora=false cpu_offload=true` is four words of
// noise around the one that matters. What a backend cannot do is answered by
// its absence here and, at the moment it matters, by the refusal itself
// (docs/specs/04-backends.md §7).
func capabilityLine(b backend.Report) string {
	var has []string
	for _, c := range []struct {
		name string
		on   bool
	}{
		{"tensor-parallel", b.Capabilities.TensorParallel},
		{"expert-parallel", b.Capabilities.ExpertParallel},
		{"lora", b.Capabilities.LoRA},
		{"cpu-offload", b.Capabilities.CPUOffload},
	} {
		if c.on {
			has = append(has, c.name)
		}
	}
	if len(b.Capabilities.Quantization) > 0 {
		has = append(has, "quant:"+strings.Join(b.Capabilities.Quantization, "/"))
	}
	if len(has) == 0 {
		return "—"
	}
	return strings.Join(has, " ")
}
