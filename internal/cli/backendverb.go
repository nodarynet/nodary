package cli

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"

	"github.com/nodarynet/nodary/internal/backend"
	"github.com/nodarynet/nodary/internal/config"
	"github.com/nodarynet/nodary/internal/store"
)

// cmdBackend is dev/specs/04-backends.md §9.
//
// `register` and `remove` write through config.Apply rather than to the
// backend table, which is the whole reason they are four lines of flag
// parsing each: a descriptor is part of the configuration snapshot, so
// registering one is a revision like anything else, records `config.apply`
// like anything else, and works over --server without an endpoint of its own.
// The three refusals that make registration more than an upsert live in
// config.applyBackends, where `config apply -f` meets them too.
func cmdBackend(e env, args []string) int {
	if len(args) == 0 {
		fmt.Fprintf(e.stderr,
			"nodary backend: expected a subcommand (list, show, register, remove, build, rebuild)\n")
		return ExitUsage
	}
	switch args[0] {
	case "list":
		return cmdBackendList(e, args[1:])
	case "show":
		return cmdBackendShow(e, args[1:])
	case "register":
		return cmdBackendRegister(e, args[1:])
	case "remove":
		return cmdBackendRemove(e, args[1:])
	case "build", "rebuild":
		return cmdBackendBuild(e, args[1:], args[0])
	}
	fmt.Fprintf(e.stderr,
		"nodary backend: unknown subcommand %q (want list, show, register, remove, build or rebuild)\n",
		args[0])
	return ExitUsage
}

// cmdBackendRegister adds an operator's descriptor to the catalog — 04 §9.
//
// The file is parsed here as well as in the applier, and the duplication is
// the point: a descriptor with a typo refuses in front of the person holding
// the file, naming the line, rather than three hops later as a 422. What this
// side does *not* do is decide anything — the name comes out of the
// descriptor rather than off the command line, so there is no second place to
// write it and nothing for the applier's name check to disagree with.
func cmdBackendRegister(e env, args []string) int {
	fs := newFlagSet(e, "backend register")
	dbPath, keyPath, credsPath := stateFlags(fs)
	server := serverFlag(fs)
	cer := attestFlags(fs)
	file := fs.String("file", "", "the descriptor to register, a TOML file")
	// `-f` too: `config apply -f` is the same idea, and an operator who
	// learned one spelling should not be told the other does not exist. Both
	// default to "", so the second declaration resetting the variable is a
	// no-op rather than the bug this shape usually is.
	fs.StringVar(file, "f", "", "same as --file")
	if code := parseFlags(e, fs, args); code >= 0 {
		return code
	}
	if *file == "" {
		fmt.Fprintf(e.stderr, "nodary backend register: -f FILE is required\n")
		return ExitUsage
	}
	raw, err := os.ReadFile(*file)
	if err != nil {
		fmt.Fprintf(e.stderr, "nodary backend register: %v\n", err)
		return ExitUsage
	}
	d, err := backend.Parse(raw)
	if err != nil {
		fmt.Fprintf(e.stderr, "nodary backend register: %s: %v\n", *file, err)
		return ExitUsage
	}
	want := &config.Snapshot{Backends: []config.Backend{
		{Name: d.Backend.Name, Source: string(raw)},
	}}

	rem, code := remoteFor(e, "backend register", *server, *credsPath, *dbPath, *keyPath)
	if code >= 0 {
		return code
	}
	if rem != nil {
		body, err := config.RenderTOML(want)
		if err != nil {
			fmt.Fprintf(e.stderr, "nodary backend register: %v\n", err)
			return ExitFailure
		}
		code = remoteApply(e, rem, "backend register",
			remoteAct{method: "POST", path: "/config/apply", body: rawTOML(body)}, false, cer)
	} else {
		code = applySnapshot(e, "backend register", want, false, false, cer, dbPath, keyPath, credsPath)
	}
	if code == ExitOK && !*cer.dryRun {
		fmt.Fprintf(e.stderr,
			"\nRegistered as %q. `nodary backend show %s` reports what it understands;\n"+
				"`nodary model register --backend %s` places a model on it.\n",
			d.Backend.Name, d.Backend.Name, d.Backend.Name)
	}
	return code
}

// cmdBackendRemove takes a registered descriptor back out of the catalog.
//
// **The whole configuration goes back, minus one backend, with --prune.** A
// fragment cannot express a deletion — config.Apply creates and updates what a
// document names and, without prune, leaves everything else alone — and a
// fragment *with* prune would delete the fleet. So this reads live desired
// state, drops one entry, and applies that: the change list is the single
// `- backend NAME` line an operator confirms, and every other object is
// present in the document and therefore untouched.
//
// Refusing to delete one still in use is the applier's job (config.applyBackends),
// not this verb's, so `config apply --prune` cannot walk around it.
func cmdBackendRemove(e env, args []string) int {
	fs := newFlagSet(e, "backend remove")
	dbPath, keyPath, credsPath := stateFlags(fs)
	server := serverFlag(fs)
	cer := attestFlags(fs)
	if code := parseFlags(e, fs, args); code >= 0 {
		return code
	}
	if fs.NArg() != 1 {
		fmt.Fprintf(e.stderr, "nodary backend remove: expected one backend name\n")
		return ExitUsage
	}
	name := fs.Arg(0)

	rem, code := remoteFor(e, "backend remove", *server, *credsPath, *dbPath, *keyPath)
	if code >= 0 {
		return code
	}

	var want *config.Snapshot
	if rem != nil {
		var err error
		if want, err = remoteSnapshot(rem, 0); err != nil {
			fmt.Fprintf(e.stderr, "nodary backend remove: %v\n", err)
			return exitFor(err)
		}
	} else {
		db, ok := openConfigRead(e, "backend remove", *dbPath)
		if !ok {
			return ExitFailure
		}
		if want, ok = revisionAt(e, "backend remove", db, 0); !ok {
			db.Close()
			return ExitFailure
		}
		db.Close()
	}

	kept := slices.DeleteFunc(want.Backends, func(b config.Backend) bool { return b.Name == name })
	if len(kept) == len(want.Backends) {
		if _, builtin := backend.Get(name); builtin == nil {
			fmt.Fprintf(e.stderr,
				"nodary backend remove: %q is built into this binary, not registered; "+
					"there is nothing to take out of the catalog\n", name)
		} else {
			fmt.Fprintf(e.stderr,
				"nodary backend remove: no registered backend named %q; "+
					"`nodary backend list` names them\n", name)
		}
		return ExitFailure
	}
	want.Backends = kept

	if rem != nil {
		body, err := config.RenderTOML(want)
		if err != nil {
			fmt.Fprintf(e.stderr, "nodary backend remove: %v\n", err)
			return ExitFailure
		}
		return remoteApply(e, rem, "backend remove",
			remoteAct{method: "POST", path: applyPath("/config/apply", true), body: rawTOML(body)},
			false, cer)
	}
	return applySnapshot(e, "backend remove", want, true, false, cer, dbPath, keyPath, credsPath)
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
	fmt.Fprintf(e.stdout, "%-12s %-10s %-14s %-17s %s\n",
		"NAME", "API", "LAYOUT", "SOURCE", "CAPABILITIES")
	for _, b := range reports {
		fmt.Fprintf(e.stdout, "%-12s %-10s %-14s %-17s %s\n",
			b.Name, b.API, b.WeightsLayout, sourceLine(b), capabilityLine(b))
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
	// Only for a derive. "recipe —" against vLLM would put a build phase in
	// front of an operator that vLLM has not got, the way "prepare —" would.
	if r := b.Recipe; r != nil {
		fmt.Fprintf(e.stdout, "  derives from   %s\n", r.From)
		fmt.Fprintf(e.stdout, "  recipe         %s, up to %s\n",
			strings.Join(r.Steps, "; "), humanSeconds(r.TimeoutS))
		fmt.Fprintf(e.stdout, "  index          %s\n", orElse(r.IndexURL, "— (no egress)"))
		fmt.Fprintf(e.stdout, "  built          %s\n", builtLine(b.Built))
	}
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
	// Only when there is one. A line saying "prepare —" on vLLM would put a
	// phase in front of an operator that vLLM does not have.
	if p := b.Prepare; p != nil {
		portable := "portable across GPU models"
		if p.GPUArchSpecific {
			portable = "not portable across GPU models"
		}
		fmt.Fprintf(e.stdout, "  prepare        builds a %s in %s, up to %s; %s\n",
			p.Artifact, p.Image, humanSeconds(p.TimeoutS), portable)
	}
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
// (dev/specs/04-backends.md §7).
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

// humanSeconds renders a prepare timeout the way an operator would say it. Six
// hours is what TensorRT-LLM asks for, and "21600s" is a number somebody has
// to divide before it means anything.
func humanSeconds(n int) string {
	switch {
	case n >= 3600 && n%3600 == 0:
		return strconv.Itoa(n/3600) + "h"
	case n >= 60 && n%60 == 0:
		return strconv.Itoa(n/60) + "m"
	default:
		return strconv.Itoa(n) + "s"
	}
}
