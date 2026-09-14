package cli

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/nodarynet/nodary/internal/agent"
	"github.com/nodarynet/nodary/internal/backend"
	"github.com/nodarynet/nodary/internal/buildinfo"
	"github.com/nodarynet/nodary/internal/config"
	"github.com/nodarynet/nodary/internal/preflight"
	"github.com/nodarynet/nodary/internal/store"
)

// modelVerbs that this release does not implement, listed rather than falling
// through to "unknown" for the reason nodeVerbs gives.
var modelVerbs = map[string]string{
	"list": "the catalog, from an operator workstation",
	"show": "one model in detail",
	// Staging already starts the instant a deployment references a model
	// (internal/agent/plan.go's Build), so there is no distinct "kick it off"
	// act for this verb to perform. `restage` (stuck/corrupt) and `unstage`
	// (reclaim disk) are real verbs, below.
	"stage": "not a separate act here; register (or restage, for a stuck download) does this",
}

func cmdModel(e env, args []string) int {
	if len(args) == 0 {
		fmt.Fprintf(e.stderr, "nodary model: expected a subcommand (register)\n")
		return ExitUsage
	}
	if args[0] == "register" {
		return cmdModelRegister(e, args[1:])
	}
	if args[0] == "unstage" || args[0] == "restage" {
		return cmdModelStageReset(e, args[1:], args[0])
	}
	if args[0] == "enable" || args[0] == "disable" {
		return cmdModelToggle(e, args[1:], args[0], args[0] == "disable")
	}
	if args[0] == "restart" {
		return cmdModelRestart(e, args[1:])
	}
	if what, ok := modelVerbs[args[0]]; ok {
		fmt.Fprintf(e.stderr, "nodary model %s: %s is not implemented in this release (%s)\n",
			args[0], what, versionString())
		return ExitFailure
	}
	fmt.Fprintf(e.stderr, "nodary model: unknown subcommand %q (want register)\n", args[0])
	return ExitUsage
}

// cmdModelRegister turns a model — weights already on disk, or a manifest
// naming what to fetch — into a served route.
//
// **`--source local` is the step that was a shell script, and the script is
// not installed anywhere.** docs/specs/05-catalog.md §3 makes it the
// air-gapped path and a first-class one, so placing weights by hand is the
// supported flow — but everything *after* placing them is arithmetic: digest
// every file, hash the list, look up the pinned image for this platform, and
// write a configuration document naming a model, a deployment and a route.
// Getting any of it wrong fails minutes later inside a container, and an
// operator was expected to do all of it in TOML by hand.
//
// **`--source remote` (R4-33) downloads nothing here either** — the agent
// does, on the node, across as many reconcile cycles as it takes
// (internal/agent/remote.go). What this verb does for remote is register: read
// a manifest an operator already produced (`scripts/stage-model.sh` writes one
// as a side effect, or by hand), validate it, and carry its content into the
// configuration document, because the control plane holds only a digest for
// local and there is no other channel for remote to get the real list from.
//
// The document goes through the same applier `config apply` uses, so a model
// registered here records a revision exactly like a hand-written one. There is
// no second write path to disagree with the first.
func cmdModelRegister(e env, args []string) int {
	fs := newFlagSet(e, "model register")
	dbPath, keyPath, credsPath := stateFlags(fs)
	cer := attestFlags(fs)
	node := fs.String("node", "", "the node to place it on; nodary node list names them")
	gpus := fs.String("gpu", "0", "GPU indices on that node, comma-separated")
	port := fs.Int("port", 8001, "loopback port the deployment publishes (default: the first free one on that node)")
	route := fs.String("route", "", "the name clients ask for (default: the model's name, lowercased)")
	backendName := fs.String("backend", "vllm", "backend descriptor")
	modelsDir := fs.String("models-dir", "", "where weights are staged (default "+agent.DefaultModelsDir()+")")
	image := fs.String("image", "", "container image (default: the digest this build pins)")
	gpuMemory := fs.Float64("gpu-memory", 0.80, "fraction of each card's VRAM to reserve")
	envJSON := fs.String("env", "", "container environment, a JSON object")
	grant := fs.String("grant", "", "users who may call this route, comma-separated")
	source := fs.String("source", "local", "local (weights already on this box) or remote (the agent fetches them)")
	// docs/specs/05-catalog.md §1. Provenance is checked against the active
	// profile's origin lists (§2) and the license is recorded and never
	// interpreted, so one is a control and the other is evidence.
	originOrg := fs.String("origin-org", "", "who published the weights, checked against policy")
	originCountry := fs.String("origin-country", "", "where they were published, checked against policy")
	license := fs.String("license", "", "the weights' license; recorded for audit, not interpreted")
	manifestPath := fs.String("manifest", "",
		"path to a manifest file, sha256sum format — required for --source remote")
	out := fs.String("o", "", "write the configuration document here instead of applying it")
	noSync := fs.Bool("no-sync", false, "do not re-render the data plane")
	if code := parseFlags(e, fs, args); code >= 0 {
		return code
	}
	if fs.NArg() != 1 {
		fmt.Fprintf(e.stderr, "nodary model register: expected one model id, e.g. Qwen/Qwen2.5-0.5B-Instruct\n")
		return ExitUsage
	}
	id := fs.Arg(0)
	if *node == "" {
		fmt.Fprintf(e.stderr, "nodary model register: --node is required; `nodary node list` names them\n")
		return ExitUsage
	}
	if *source != "local" && *source != "remote" {
		fmt.Fprintf(e.stderr, "nodary model register: --source must be local or remote, not %q\n", *source)
		return ExitUsage
	}
	indices, ok := parseGPUList(e, *gpus)
	if !ok {
		return ExitUsage
	}
	name := *route
	if name == "" {
		name = strings.ToLower(id[strings.LastIndex(id, "/")+1:])
	}

	// The weights' layout comes from the backend, which
	// internal/config/apply.go already calls the authority on it: each
	// descriptor declares one `weights_layout`, and 05 §1 requires the model's
	// artifact kind to match. It was hardcoded to `hf-cache` here, so
	// `--backend llama-cpp` looked for a HuggingFace cache that a GGUF is not
	// in, and stamped an artifact kind config.Apply then refused — the one
	// path an operator would actually take.
	desc, err := backend.Get(*backendName)
	if err != nil {
		fmt.Fprintf(e.stderr, "nodary model register: %v\n", err)
		return ExitUsage
	}
	layout := desc.Backend.WeightsLayout

	var sum, manifestBody string
	var total int64
	if *source == "remote" {
		// total_bytes is not asked for here: nothing on this machine has
		// downloaded anything to measure, and asking the operator to type a
		// number that only has to be trusted is worse than not having one.
		// The agent computes a real total itself, from HEAD requests, before
		// it starts fetching (internal/agent/remote.go).
		sum, manifestBody, ok = readRemoteManifest(e, *manifestPath)
		if !ok {
			return ExitUsage
		}
	} else {
		dir, err := agent.ModelDir(orElse(*modelsDir, agent.DefaultModelsDir()), layout, id)
		if err != nil {
			fmt.Fprintf(e.stderr, "nodary model register: %v\n", err)
			return ExitUsage
		}
		if _, err := os.Stat(dir); err != nil {
			// Named, with the download that would fill it. The alternative is
			// a deployment that applies cleanly and then sits in `staging`
			// forever with the reason buried in a heartbeat.
			fmt.Fprintf(e.stderr, "nodary model register: no weights at %s\n", dir)
			// Named for the layout this backend declares. Telling somebody
			// with a GGUF to place `config.json and the tensor files` sends
			// them looking for files their model does not have.
			switch layout {
			case "single-file":
				fmt.Fprintf(e.stderr,
					"  %s serves a %s model, so place the one file there — a .gguf and nothing\n"+
						"  else — or register --source remote --manifest FILE to have a node fetch it.\n",
					*backendName, layout)
			default:
				fmt.Fprintf(e.stderr,
					"  Place them there — flat, as config.json and the tensor files, not a\n"+
						"  blobs/ and snapshots/ cache — or run\n"+
						"    scripts/stage-model.sh %s\n"+
						"  or register --source remote --manifest FILE to have a node fetch them.\n", id)
			}
			return ExitFailure
		}
		var files int
		sum, files, total, err = agent.WriteManifest(dir)
		if err != nil {
			fmt.Fprintf(e.stderr, "nodary model register: %v\n", err)
			return ExitFailure
		}
		fmt.Fprintf(e.stdout, "%s %-18s %d file(s), %d bytes, manifest %s\n",
			mark(preflight.LevelOK), "weights", files, total, sum[:12])
	}

	// **8001 is a starting point, not the answer.** Two deployments on one node
	// publishing the same loopback port is not a loud failure: the second
	// container never binds while the first keeps serving, so the gateway's
	// route for the second model reaches the *first model's* server — a request
	// for one model answered by another, metered against the wrong one. A fixed
	// default made that the outcome of registering a second model on a node
	// without thinking about ports, which is the ordinary thing to do.
	//
	// config.Apply refuses the collision either way (checkPorts), for the
	// hand-written document this cannot see. This is so an operator never meets
	// that refusal for a detail they have no reason to care about: the port is
	// published on loopback and nothing outside the box ever names it.
	if *out == "" && !flagWasSet(fs, "port") {
		if free, ok := freePortOn(e, dbPath, *node, *port); ok && free != *port {
			fmt.Fprintf(e.stdout, "%s %-18s %d is taken on %s; using %d\n",
				mark(preflight.LevelOK), "port", *port, *node, free)
			*port = free
		}
	}

	pinned := *image
	if pinned == "" {
		if pinned, ok = pinnedImage(e, *backendName); !ok {
			return ExitFailure
		}
	}

	params := map[string]any{"served_name": name, "gpu_memory_fraction": *gpuMemory}
	raw, err := json.Marshal(params)
	if err != nil {
		fmt.Fprintf(e.stderr, "nodary model register: %v\n", err)
		return ExitFailure
	}
	if *envJSON != "" {
		var probe map[string]string
		if err := json.Unmarshal([]byte(*envJSON), &probe); err != nil {
			fmt.Fprintf(e.stderr, "nodary model register: --env is not a JSON object of strings: %v\n", err)
			return ExitUsage
		}
	}

	want := &config.Snapshot{
		Models: []config.Model{{
			ID: id, Backend: *backendName, Source: *source, Artifact: layout,
			OriginOrg: *originOrg, OriginCountry: *originCountry, License: *license,
			ManifestSHA256: sum, TotalBytes: total, ManifestBody: manifestBody,
		}},
		Deployments: []config.Deployment{{
			ID: name + "-" + *node, ModelID: id, NodeName: *node, Backend: *backendName,
			Image: pinned, GPUs: indices, Params: string(raw), Env: *envJSON, Port: *port,
		}},
		Routes: []config.Route{{
			Name: name, Strategy: "round-robin",
			Members: []config.RouteMember{{DeploymentID: name + "-" + *node, Weight: 1}},
		}},
	}
	// docs/specs/06-gateway.md §2 is deny-by-default, so a route with no grant
	// is one nobody may call. Doing it here keeps a working model one command
	// away instead of one command plus a hand-written TOML fragment — and it is
	// the same applier and the same revision either way, so nothing is granted
	// without an author and a record.
	for _, u := range splitComma(*grant) {
		if u = strings.TrimSpace(u); u != "" {
			want.Grants = append(want.Grants, config.Grant{User: u, Route: name})
		}
	}

	if *out != "" {
		body, err := config.RenderTOML(want)
		if err != nil {
			fmt.Fprintf(e.stderr, "nodary model register: %v\n", err)
			return ExitFailure
		}
		if err := os.WriteFile(*out, body, 0o644); err != nil {
			fmt.Fprintf(e.stderr, "nodary model register: %v\n", err)
			return ExitFailure
		}
		fmt.Fprintf(e.stderr, "Wrote %s. Apply it with `nodary config apply -f %s`.\n", *out, *out)
		return ExitOK
	}

	code := applySnapshot(e, "model register", want, false, *noSync, cer, dbPath, keyPath, credsPath)
	if code == ExitOK && !*cer.dryRun {
		fmt.Fprintf(e.stderr,
			"\nClients ask for it as %q. `nodary node show %s` follows it from starting to ready.\n",
			name, *node)
		if *grant == "" {
			fmt.Fprintf(e.stderr,
				"  Nobody may call it yet: access is per user and denied by default.\n"+
					"  Re-run with --grant NAME, or apply a [[grant]] block.\n")
		}
	}
	return code
}

// readRemoteManifest reads and validates a manifest for `--source remote`.
//
// Validated here, at registration, rather than trusted through to the agent:
// a malformed file should refuse in front of the person who can fix it, not
// surface three hops later as a node reporting a deployment `corrupt` for a
// reason that names neither this flag nor this file.
func readRemoteManifest(e env, path string) (sum, body string, ok bool) {
	if path == "" {
		fmt.Fprintf(e.stderr,
			"nodary model register: --manifest is required for --source remote\n"+
				"  scripts/stage-model.sh writes one as a side effect of downloading — run it once\n"+
				"  anywhere to produce nodary-manifest.sha256, without needing to place the result\n"+
				"  on the node that will actually serve this model.\n")
		return "", "", false
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintf(e.stderr, "nodary model register: %v\n", err)
		return "", "", false
	}
	entries, err := agent.ParseManifest(raw)
	if err != nil {
		fmt.Fprintf(e.stderr, "nodary model register: %v\n", err)
		return "", "", false
	}
	if len(entries) == 0 {
		fmt.Fprintf(e.stderr, "nodary model register: %s lists no files\n", path)
		return "", "", false
	}
	digest := sha256.Sum256(raw)
	fmt.Fprintf(e.stdout, "%s %-18s %d file(s) named, manifest %s\n",
		mark(preflight.LevelOK), "manifest", len(entries), hex.EncodeToString(digest[:])[:12])
	return hex.EncodeToString(digest[:]), string(raw), true
}

// pinnedImage is the digest this build pins for a backend on this platform.
//
// Pinned rather than left to the descriptor's default, which is a *tag*: the
// manifest's entry is the version this release was tested against, and on a new
// GPU generation the difference between them is the whole run.
func pinnedImage(e env, backend string) (string, bool) {
	m, ok := loadManifest(e)
	if !ok {
		return "", false
	}
	img, err := imageFor(m, backend, buildinfo.Platform())
	if err != nil {
		fmt.Fprintf(e.stderr, "nodary model register: %v\n", err)
		fmt.Fprintf(e.stderr, "  pass --image to name one yourself\n")
		return "", false
	}
	return img, true
}

func parseGPUList(e env, spec string) ([]int, bool) {
	var out []int
	for _, raw := range splitComma(spec) {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		n, err := strconv.Atoi(raw)
		if err != nil || n < 0 {
			fmt.Fprintf(e.stderr, "nodary model register: --gpu %q is not a list of indices\n", spec)
			return nil, false
		}
		out = append(out, n)
	}
	if len(out) == 0 {
		fmt.Fprintf(e.stderr, "nodary model register: --gpu names no card\n")
		return nil, false
	}
	return out, true
}

// flagWasSet reports whether a flag was named on the command line, as opposed
// to holding its default. `--port 8001` means "8001, and I mean it".
func flagWasSet(fs *flag.FlagSet, name string) bool {
	seen := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == name {
			seen = true
		}
	})
	return seen
}

// freePortOn is the first port at or above `from` that nothing on this node
// already publishes.
//
// Best effort: a database that cannot be opened or read leaves the default in
// place and lets the apply refuse, which is the same answer with a worse
// message rather than a different outcome. `model register` opens the database
// again a moment later through openSession, so a failure here is a failure
// there too.
func freePortOn(e env, dbPath *string, node string, from int) (int, bool) {
	path, _ := resolveDBIn(e, *dbPath)
	db, err := store.OpenReadOnly(context.Background(), path)
	if err != nil {
		return 0, false
	}
	defer db.Close()
	snap, err := config.Read(context.Background(), db.Read())
	if err != nil {
		return 0, false
	}
	taken := map[int]bool{}
	for _, d := range snap.Deployments {
		if d.NodeName == node {
			taken[d.Port] = true
		}
	}
	// 0006_fleet.sql bounds a deployment's port to an unprivileged one.
	for p := from; p < 65536; p++ {
		if !taken[p] {
			return p, true
		}
	}
	return 0, false
}
