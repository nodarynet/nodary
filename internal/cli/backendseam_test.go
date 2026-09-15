package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nodarynet/nodary/internal/agent"
	"github.com/nodarynet/nodary/internal/api"
	"github.com/nodarynet/nodary/internal/backend"
	"github.com/nodarynet/nodary/internal/config"
)

// TestEveryBackendRegistersIntoADeploymentANodeWillRun crosses the seam that
// let three fatal defects ship: `model register` writes a document, the applier
// accepts it, and the *node* is what turns it into a container — and nothing
// tested those three against each other.
//
// What that cost, all of it measured on real images rather than reasoned about:
//
//   - `model register` wrote `gpu_memory_fraction` on every registration, which
//     neither sglang nor llama-cpp declared. plan.go refuses a deployment whose
//     parameters were dropped, so both backends produced a document that applied
//     cleanly and a node that would not render it.
//   - `lmsysorg/sglang` declares no command and its entrypoint ends in
//     `exec "$@"`, so the argv nodary rendered exited with
//     `exec: --: invalid option`. SGLang had never started, on any host.
//   - SGLang and llama.cpp both bind 127.0.0.1 by default, and the unit
//     publishes `-p 127.0.0.1:host:container` from an isolated bridge, so
//     neither was reachable even once it started.
//
// Every one of those is invisible to a test that stops at the document, and
// every one of them is caught here.
func TestEveryBackendRegistersIntoADeploymentANodeWillRun(t *testing.T) {
	names, err := backend.Builtins()
	if err != nil {
		t.Fatal(err)
	}

	for _, name := range backend.Names(names) {
		t.Run(name, func(t *testing.T) {
			a := newAppliance(t)
			a.enrolledAs("gpu-01", "linux", "amd64", offerOf("nvidia"))
			a.addUser("alice", "operator")

			desc, err := backend.Get(name)
			if err != nil {
				t.Fatal(err)
			}
			layout := desc.Backend.WeightsLayout

			// The weights in whatever shape this backend reads.
			models := t.TempDir()
			dir, err := agent.ModelDir(models, layout, "acme/tiny")
			if err != nil {
				t.Fatal(err)
			}
			if err := os.MkdirAll(dir, 0o755); err != nil {
				t.Fatal(err)
			}
			file := "config.json"
			if layout == "single-file" {
				file = "tiny-q4_k_m.gguf"
			}
			if err := os.WriteFile(filepath.Join(dir, file), []byte("{}"), 0o644); err != nil {
				t.Fatal(err)
			}

			doc := filepath.Join(t.TempDir(), "out.toml")
			code, _, stderr := a.run("model", "register", "acme/tiny",
				"--node", "gpu-01", "--models-dir", models, "--backend", name,
				"-o", doc, "--yes", "--justify", "the seam")
			if code != ExitOK {
				t.Fatalf("register: exit %d: %s", code, stderr)
			}

			raw, err := os.ReadFile(doc)
			if err != nil {
				t.Fatal(err)
			}
			snap, err := config.DecodeTOML(raw)
			if err != nil {
				t.Fatal(err)
			}
			if len(snap.Deployments) != 1 {
				t.Fatalf("the document holds %d deployments", len(snap.Deployments))
			}
			d := snap.Deployments[0]

			// The node's half, against the document the verb just wrote.
			p, err := agent.Build(api.Desired{
				Rev: 1, Node: "gpu-01",
				Deployments: []api.DesiredDeployment{{
					ID: d.ID, Model: d.ModelID, Backend: d.Backend, Image: d.Image,
					GPUs: d.GPUs, Params: json.RawMessage(d.Params), Port: d.Port,
					Network: api.IsolatedNetwork, State: "ready",
				}},
				Staging: []api.DesiredStaging{{Model: "acme/tiny", Source: "local",
					Layout: layout, ManifestSHA256: snap.Models[0].ManifestSHA256}},
			}, agent.PlanOptions{ModelsDir: models, Present: []agent.GPU{{Index: 0}}, Verify: true})
			if err != nil {
				t.Fatal(err)
			}
			if len(p.Units) != 1 {
				t.Fatalf("the node would not run what register wrote: %+v", p.Refused)
			}

			argv := ""
			for _, v := range p.Units[0].Env {
				if v.Key == "NODARY_ARGS" {
					argv = v.Value
				}
			}
			// Reachable through the published port. The container is on an
			// isolated bridge, so a server on the container's own loopback
			// answers nobody — and two of the three backends default to it.
			if _, declared := desc.Backend.Args["host"]; declared {
				if !strings.Contains(argv, "0.0.0.0") {
					t.Errorf("%s is not told to listen on every interface: %s", name, argv)
				}
			}
			// A command for an image that declares none, and none for an image
			// that starts itself.
			if cmd := desc.Backend.Command; cmd != "" && !strings.HasPrefix(argv, cmd) {
				t.Errorf("%s does not lead with the command its image needs: %s", name, argv)
			}
		})
	}
}
