package api_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/nodarynet/nodary/internal/api"
	"github.com/nodarynet/nodary/internal/audit"
	"github.com/nodarynet/nodary/internal/config"
	"github.com/nodarynet/nodary/internal/identity"
)

const acmeDescriptor = `[backend]
name           = "acme-serve"
api            = "openai"
weights_layout = "hf-cache"
mount_path     = "/weights"
container_port = 9000
silicon = ["nvidia"]
image_default  = "acme/serve:1"

[backend.capabilities]
tensor_parallel = false
expert_parallel = false
quantization    = ["awq"]
lora            = false
cpu_offload     = false

[backend.args]
model_path = "--model={v}"
port       = "--port={v}"

[backend.probe]
health          = "/healthz"
ready           = "/healthz"
ready_timeout_s = 300
`

// registerAndPlace registers an operator descriptor and puts a deployment on
// it, through the applier both front ends use.
func (f *fixture) registerAndPlace(node, deployment, backendName string) {
	f.t.Helper()
	ctx := context.Background()
	root := identity.LocalRoot()
	root.Actor.ID = "test"
	if _, err := f.log.Act(ctx, audit.Request{Actor: root.Actor, Action: "config.apply"},
		func(m audit.Mutation) error {
			snap, err := config.Read(ctx, m.Tx())
			if err != nil {
				return err
			}
			snap.Backends = append(snap.Backends,
				config.Backend{Name: "acme-serve", Source: acmeDescriptor})
			snap.Models = append(snap.Models, config.Model{
				ID: "acme/tiny", Backend: backendName, Source: "local", Artifact: "hf-cache"})
			snap.Deployments = append(snap.Deployments, config.Deployment{
				ID: deployment, ModelID: "acme/tiny", NodeName: node, Backend: backendName,
				Image: "registry.invalid/acme@sha256:" + hex64, GPUs: []int{0}, Port: 8001,
			})
			if _, err := config.Apply(ctx, m, time.Now(), snap, config.Options{}); err != nil {
				return err
			}
			_, err = config.Record(ctx, m, time.Now(), "test", "a custom backend")
			return err
		}); err != nil {
		f.t.Fatalf("registering and placing: %v", err)
	}
}

// R6-07: a registered descriptor reaches the node that needs it, because there
// is nowhere else it could come from — 03 §1 gives the control plane no way to
// push, so this document is the only channel.
func TestARegisteredDescriptorTravelsToTheNodeThatUsesIt(t *testing.T) {
	f := newFixture(t)
	n := f.join("gpu-01")
	f.registerAndPlace("gpu-01", "dep_one", "acme-serve")
	if status, body := f.do(http.MethodPost, "/nodes/gpu-01/approve", f.admin, nil,
		map[string]string{api.HeaderJustify: "the node in the rack we ordered"}); status != http.StatusOK {
		t.Fatalf("approve: %d %v", status, body)
	}

	doc := n.desired(t, f, "")
	if len(doc.Backends) != 1 {
		t.Fatalf("backends = %+v, want the one this node's deployment uses", doc.Backends)
	}
	got := doc.Backends[0]
	if got.Name != "acme-serve" {
		t.Errorf("name = %q", got.Name)
	}
	// The bytes, so the agent parses what the operator wrote on the version of
	// the code that is about to act on it.
	if got.Source != acmeDescriptor {
		t.Error("the descriptor arrived re-serialized rather than as the file")
	}
	sum := sha256.Sum256([]byte(acmeDescriptor))
	if got.SHA256 != hex.EncodeToString(sum[:]) {
		t.Errorf("sha256 = %q, want the digest of what was sent", got.SHA256)
	}
}

// Built-ins do not travel: they are compiled into the agent's own binary and
// are the same on every host, so sending them would be sending the build.
func TestBuiltInDescriptorsDoNotTravel(t *testing.T) {
	f := newFixture(t)
	n := f.join("gpu-01")
	f.place("gpu-01", "dep_one", 0)
	if status, body := f.do(http.MethodPost, "/nodes/gpu-01/approve", f.admin, nil,
		map[string]string{api.HeaderJustify: "the node in the rack we ordered"}); status != http.StatusOK {
		t.Fatalf("approve: %d %v", status, body)
	}

	doc := n.desired(t, f, "")
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "vllm/vllm-openai") {
		t.Errorf("a built-in descriptor was sent to the node:\n%s", raw)
	}
	if len(doc.Backends) != 0 {
		t.Errorf("backends = %+v, want none for a deployment on a built-in", doc.Backends)
	}
}

// A registry the node does not draw on stays where it is. A fleet with twenty
// operator backends and a node running one should be sent one — the document
// is the size of this node's work, not of the fleet's catalog.
func TestOnlyTheDescriptorsThisNodeUsesTravel(t *testing.T) {
	f := newFixture(t)
	n := f.join("gpu-01")
	// acme-serve is registered; this node's deployment runs on vllm.
	f.registerAndPlace("gpu-01", "dep_one", "vllm")
	if status, body := f.do(http.MethodPost, "/nodes/gpu-01/approve", f.admin, nil,
		map[string]string{api.HeaderJustify: "the node in the rack we ordered"}); status != http.StatusOK {
		t.Fatalf("approve: %d %v", status, body)
	}

	doc := n.desired(t, f, "")
	if len(doc.Backends) != 0 {
		t.Errorf("backends = %+v, want none: this node uses a built-in, and the registered "+
			"descriptor is nothing to do with it", doc.Backends)
	}
}
