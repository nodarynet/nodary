package cli

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/nodarynet/nodary/internal/agent"
	"github.com/nodarynet/nodary/internal/buildinfo"
	"github.com/nodarynet/nodary/internal/config"
	"github.com/nodarynet/nodary/internal/preflight"
)

// modelVerbs that this release does not implement, listed rather than falling
// through to "unknown" for the reason nodeVerbs gives.
var modelVerbs = map[string]string{
	"list":    "the catalog, from an operator workstation",
	"show":    "one model in detail",
	"enable":  "directing a node to start a deployment",
	"disable": "directing a node to stop one",
	"restart": "directing a node to restart one",
	"stage":   "re-triggering staging on a model that already has a deployment",
	"unstage": "directing a node to discard them",
	"restage": "re-verifying weights already placed",
}

func cmdModel(e env, args []string) int {
	if len(args) == 0 {
		fmt.Fprintf(e.stderr, "nodary model: expected a subcommand (register)\n")
		return ExitUsage
	}
	if args[0] == "register" {
		return cmdModelRegister(e, args[1:])
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
	port := fs.Int("port", 8001, "loopback port the deployment publishes")
	route := fs.String("route", "", "the name clients ask for (default: the model's name, lowercased)")
	backend := fs.String("backend", "vllm", "backend descriptor")
	modelsDir := fs.String("models-dir", "", "where weights are staged (default "+agent.DefaultModelsDir()+")")
	image := fs.String("image", "", "container image (default: the digest this build pins)")
	gpuMemory := fs.Float64("gpu-memory", 0.80, "fraction of each card's VRAM to reserve")
	envJSON := fs.String("env", "", "container environment, a JSON object")
	grant := fs.String("grant", "", "users who may call this route, comma-separated")
	source := fs.String("source", "local", "local (weights already on this box) or remote (the agent fetches them)")
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
		dir, err := agent.ModelDir(orElse(*modelsDir, agent.DefaultModelsDir()), "hf-cache", id)
		if err != nil {
			fmt.Fprintf(e.stderr, "nodary model register: %v\n", err)
			return ExitUsage
		}
		if _, err := os.Stat(dir); err != nil {
			// Named, with the download that would fill it. The alternative is
			// a deployment that applies cleanly and then sits in `staging`
			// forever with the reason buried in a heartbeat.
			fmt.Fprintf(e.stderr, "nodary model register: no weights at %s\n", dir)
			fmt.Fprintf(e.stderr,
				"  Place them there — flat, as config.json and the tensor files, not a\n"+
					"  blobs/ and snapshots/ cache — or run\n"+
					"    scripts/stage-model.sh %s\n"+
					"  or register --source remote --manifest FILE to have a node fetch them.\n", id)
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

	pinned := *image
	if pinned == "" {
		if pinned, ok = pinnedImage(e, *backend); !ok {
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
			ID: id, Backend: *backend, Source: *source, Artifact: "hf-cache",
			ManifestSHA256: sum, TotalBytes: total, ManifestBody: manifestBody,
		}},
		Deployments: []config.Deployment{{
			ID: name + "-" + *node, ModelID: id, NodeName: *node, Backend: *backend,
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
