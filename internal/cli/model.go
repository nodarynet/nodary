package cli

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/nodarynet/nodary/internal/agent"
	"github.com/nodarynet/nodary/internal/backend"
	"github.com/nodarynet/nodary/internal/buildinfo"
	"github.com/nodarynet/nodary/internal/config"
	"github.com/nodarynet/nodary/internal/fleet"
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
	server := serverFlag(fs)
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
	rem, code := remoteFor(e, "model register", *server, *credsPath, *dbPath, *keyPath)
	if code >= 0 {
		return code
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
	// Through the registry, not only the built-ins: a model registered against
	// an operator's own backend has to resolve that backend's weights_layout
	// or it is stamped with the wrong artifact kind and refused by the
	// applier. Over --server the registry is on the far side, so the same
	// endpoint `backend show` reads answers it here.
	layout, ok := weightsLayoutFor(e, rem, *dbPath, *backendName)
	if !ok {
		return ExitUsage
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
			if rem != nil {
				// Over --server that path is on *this* machine, not on the
				// node — and saying "no weights at /var/lib/nodary/models"
				// without saying whose is how an operator ends up looking at
				// the right directory on the wrong box.
				fmt.Fprintf(e.stderr,
					"  That path is on this machine. --source local means the node already\n"+
						"  has the weights and this command only hashes an identical copy to\n"+
						"  build the manifest from; --source remote --manifest FILE asks the\n"+
						"  node to fetch its own, and needs no copy here at all.\n")
			}
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
		if free, ok := freePortOn(e, rem, dbPath, *node, *port); ok && free != *port {
			fmt.Fprintf(e.stdout, "%s %-18s %d is taken on %s; using %d\n",
				mark(preflight.LevelOK), "port", *port, *node, free)
			*port = free
		}
	}

	pinned := *image
	if pinned == "" {
		if pinned, ok = pinnedImage(e, rem, *dbPath, *backendName, *node, indices); !ok {
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

	// **The same document either way.** Over --server this renders exactly what
	// `-o FILE` writes and posts it to the applier the declarative route
	// already uses, so there is no second way into the catalog and no second
	// action in the chain: both roads record `config.apply`. It is also what
	// makes R4-32's origin check unavoidable — that control lives in
	// config.applyModels rather than in this verb, precisely so that neither
	// road can walk past it.
	if rem != nil {
		body, err := config.RenderTOML(want)
		if err != nil {
			fmt.Fprintf(e.stderr, "nodary model register: %v\n", err)
			return ExitFailure
		}
		code = remoteApply(e, rem, "model register",
			remoteAct{method: "POST", path: "/config/apply", body: rawTOML(body)}, *noSync, cer)
	} else {
		code = applySnapshot(e, "model register", want, false, *noSync, cer, dbPath, keyPath, credsPath)
	}
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
// weightsLayoutFor resolves what a backend reads, from whichever side this
// invocation is registering against.
func weightsLayoutFor(e env, rem *remote, dbPath, name string) (string, bool) {
	var rep backend.Report
	if rem != nil {
		if _, err := rem.get("/backends/"+url.PathEscape(name), &rep); err != nil {
			fmt.Fprintf(e.stderr, "nodary model register: %v\n", err)
			return "", false
		}
		return rep.WeightsLayout, true
	}
	if db, ok := registryDB(e, "model register", dbPath); ok {
		defer db.Close()
		rep, err := config.BackendReport(context.Background(), db.Read(), name)
		if err != nil {
			fmt.Fprintf(e.stderr, "nodary model register: %v\n", err)
			return "", false
		}
		return rep.WeightsLayout, true
	}
	d, err := backend.Get(name)
	if err != nil {
		fmt.Fprintf(e.stderr, "nodary model register: %v\n", err)
		return "", false
	}
	return d.Backend.WeightsLayout, true
}

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

// pinnedImage is the digest this build pins for a backend on the node it is
// being placed on.
//
// Pinned rather than left to the descriptor's default, which is a *tag*: the
// manifest's entry is the version this release was tested against, and on a new
// GPU generation the difference between them is the whole run.
//
// **On the node's platform and GPU vendor, not this machine's.** Until a fleet
// could hold two vendors every node's answer was the control plane's, so
// buildinfo.Platform() was right by accident; it resolves the image for
// whichever box the operator typed the command on. That was already wrong for
// an arm64 node placed from an amd64 control plane — quietly, as an image that
// will not run — and a vendor axis makes it wrong in a second direction.
func pinnedImage(e env, rem *remote, dbPath, backend, node string, gpus []int) (string, bool) {
	// **A derive's image is whatever its build produced**, so it is not in the
	// component manifest and never will be — the manifest pins what a release
	// ships, and this was made on this site. Read through the report so the
	// answer is the same over --server, where there is no database to ask.
	if b, ok := backendReport(e, rem, dbPath, backend); ok && b.Recipe != nil {
		if b.Built == nil {
			fmt.Fprintf(e.stderr, "nodary model register: %s is a derived image and nothing "+
				"has been built for it yet.\n  Run `nodary backend build %s` first, or pass "+
				"--image to name one yourself.\n", backend, backend)
			return "", false
		}
		// The digest and not the tag: a rebuild may reuse the tag, and a
		// deployment that followed it would move to an image nobody approved
		// for it. §5 has deployments on the previous digest keep serving.
		return b.Built.Digest, true
	}
	m, ok := loadManifest(e)
	if !ok {
		return "", false
	}
	plat, vendor, ok := nodeTarget(e, rem, dbPath, node, gpus)
	if !ok {
		return "", false
	}
	img, err := imageFor(m, backend, plat, vendor)
	if err != nil {
		fmt.Fprintf(e.stderr, "nodary model register: %v\n", err)
		fmt.Fprintf(e.stderr, "  pass --image to name one yourself\n")
		return "", false
	}
	return img, true
}

// nodeTarget is the platform and GPU vendor an image has to run on.
//
// The offer is the authority on the vendor, and it is deliberately not in
// config.Snapshot — readNodes selects four columns and not offer_json, which is
// why adding a vendor to it invalidated no revision chain
// (docs/plans/R6a-a-second-gpu-vendor.md §4). So this reads fleet.Node, which
// carries the offer and is already served both ways by `node list`.
//
// **An unknown node falls back to this machine's platform**, which is what
// every release before this one did for every node. Registering onto a node the
// control plane has never heard of is refused by the applier a moment later,
// with a better message than anything this function could give; failing here
// instead would turn `--out`, which applies nothing, into a verb that needs a
// fleet.
func nodeTarget(e env, rem *remote, dbPath, node string, gpus []int) (string, string, bool) {
	n, ok := fleetNode(e, rem, dbPath, node)
	if !ok {
		return buildinfo.Platform(), "", true
	}
	plat := buildinfo.Platform()
	// A node that enrolled but has never reported leaves both empty, and
	// "linux/" is not a manifest key. Half an answer is not one.
	if n.OS != "" && n.Arch != "" {
		plat = n.OS + "/" + n.Arch
	}

	var offer agent.Offer
	_ = json.Unmarshal(n.Offer, &offer)
	want := map[int]bool{}
	for _, idx := range gpus {
		want[idx] = true
	}
	vendors := map[string]bool{}
	for _, g := range offer.GPUs {
		if want[g.Index] {
			vendors[g.VendorName()] = true
		}
	}
	// **A mixed host is refused rather than resolved.** Two vendors among the
	// assigned cards means two images, and there is one image per deployment —
	// so picking either one pins a container that cannot drive half the GPUs it
	// was given. docs/plans/R6a-a-second-gpu-vendor.md §9 leaves the general
	// case open; this is the one path that has to answer it today.
	if len(vendors) > 1 {
		names := make([]string, 0, len(vendors))
		for v := range vendors {
			names = append(names, v)
		}
		sort.Strings(names)
		idx := make([]string, len(gpus))
		for i, n := range gpus {
			idx[i] = strconv.Itoa(n)
		}
		fmt.Fprintf(e.stderr, "nodary model register: GPUs %s on %s are %s cards, and one "+
			"deployment runs one image.\n  Register separately per vendor, or pass --image.\n",
			strings.Join(idx, ","), node, strings.Join(names, " and "))
		return "", "", false
	}
	for v := range vendors {
		return plat, v, true
	}
	// No assigned GPU is in the offer. unitFor refuses that on the node with
	// the index it names, which is the message worth getting; the base entry is
	// what every release pinned before there was a vendor axis at all.
	return plat, "", true
}

// fleetNode reads one node from whichever fleet this invocation is acting
// against, the same two ways `node list` does.
func fleetNode(e env, rem *remote, dbPath, name string) (fleet.Node, bool) {
	var nodes []fleet.Node
	var err error
	if rem != nil {
		nodes, err = remoteList[fleet.Node](rem, "/nodes", "nodes", nil)
	} else {
		path, _ := resolveDBIn(e, dbPath)
		var db *store.DB
		if db, err = store.OpenReadOnly(context.Background(), path); err == nil {
			defer db.Close()
			nodes, err = fleet.Nodes(context.Background(), db.Read(), time.Now())
		}
	}
	if err != nil {
		return fleet.Node{}, false
	}
	for _, n := range nodes {
		if n.Name == name {
			return n, true
		}
	}
	return fleet.Node{}, false
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
func freePortOn(e env, rem *remote, dbPath *string, node string, from int) (int, bool) {
	// Whichever configuration this invocation is acting against. Reading the
	// local one while registering against a control plane would pick a port
	// from the wrong fleet — and picking a *taken* one is the collision this
	// exists to avoid, silently: the second container never binds, the first
	// keeps serving, and the new model's route answers with the old model.
	var snap *config.Snapshot
	var err error
	if rem != nil {
		snap, err = remoteSnapshot(rem, 0)
	} else {
		path, _ := resolveDBIn(e, *dbPath)
		var db *store.DB
		if db, err = store.OpenReadOnly(context.Background(), path); err == nil {
			defer db.Close()
			snap, err = config.Read(context.Background(), db.Read())
		}
	}
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
