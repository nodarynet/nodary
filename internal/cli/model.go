package cli

import (
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
	"stage":   "directing a node to fetch weights (R4-33)",
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

// cmdModelRegister turns weights already on disk into a served route.
//
// **This is the step that was a shell script, and the script is not installed
// anywhere.** docs/specs/05-catalog.md §3 makes `source: local` the air-gapped
// path and a first-class one, so placing weights by hand is the supported flow
// — but everything *after* placing them is arithmetic: digest every file, hash
// the list, look up the pinned image for this platform, and write a
// configuration document naming a model, a deployment and a route. Getting any
// of it wrong fails minutes later inside a container, and an operator was
// expected to do all of it in TOML by hand.
//
// It downloads nothing. R4-33 (`source: remote`) is unbuilt and this is not it:
// the weights must already be at the layout's path, and the verb says where
// that is when they are not.
//
// The document goes through the same applier `config apply` uses, so a model
// registered here records a revision exactly like a hand-written one. There is
// no second write path to disagree with the first.
func cmdModelRegister(e env, args []string) int {
	fs := newFlagSet(e, "model register")
	dbPath, keyPath, credsPath := stateFlags(fs)
	cer := attestFlags(fs)
	node := fs.String("node", "", "the node to place it on (`nodary node list` names them)")
	gpus := fs.String("gpu", "0", "GPU indices on that node, comma-separated")
	port := fs.Int("port", 8001, "loopback port the deployment publishes")
	route := fs.String("route", "", "the name clients ask for (default: the model's name, lowercased)")
	backend := fs.String("backend", "vllm", "backend descriptor")
	modelsDir := fs.String("models-dir", "", "where weights are staged (default "+agent.DefaultModelsDir()+")")
	image := fs.String("image", "", "container image (default: the digest this build pins)")
	gpuMemory := fs.Float64("gpu-memory", 0.80, "fraction of each card's VRAM to reserve")
	envJSON := fs.String("env", "", "container environment, a JSON object")
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
	indices, ok := parseGPUList(e, *gpus)
	if !ok {
		return ExitUsage
	}
	name := *route
	if name == "" {
		name = strings.ToLower(id[strings.LastIndex(id, "/")+1:])
	}

	dir, err := agent.ModelDir(orElse(*modelsDir, agent.DefaultModelsDir()), "hf-cache", id)
	if err != nil {
		fmt.Fprintf(e.stderr, "nodary model register: %v\n", err)
		return ExitUsage
	}
	if _, err := os.Stat(dir); err != nil {
		// Named, with the download that would fill it. The alternative is a
		// deployment that applies cleanly and then sits in `staging` forever
		// with the reason buried in a heartbeat.
		fmt.Fprintf(e.stderr, "nodary model register: no weights at %s\n", dir)
		fmt.Fprintf(e.stderr,
			"  nodary does not download them (R4-33 is unbuilt). Place them there — flat, as\n"+
				"  config.json and the tensor files, not a blobs/ and snapshots/ cache — or run\n"+
				"    scripts/stage-model.sh %s\n", id)
		return ExitFailure
	}

	sum, files, total, err := agent.WriteManifest(dir)
	if err != nil {
		fmt.Fprintf(e.stderr, "nodary model register: %v\n", err)
		return ExitFailure
	}
	fmt.Fprintf(e.stdout, "%s %-18s %d file(s), %d bytes, manifest %s\n",
		mark(preflight.LevelOK), "weights", files, total, sum[:12])

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
			ID: id, Backend: *backend, Source: "local", Artifact: "hf-cache",
			ManifestSHA256: sum, TotalBytes: total,
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
	}
	return code
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
