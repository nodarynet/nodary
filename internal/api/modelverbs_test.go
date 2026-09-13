package api_test

import (
	"net/http"
	"testing"

	"github.com/nodarynet/nodary/internal/api"
)

// ready is a node with a deployment on it, which is the least these verbs need.
func (f *fixture) ready(t *testing.T) {
	t.Helper()
	f.join("gpu-01")
	if code, doc := f.do(http.MethodPost, "/nodes/gpu-01/approve", f.admin, nil,
		map[string]string{api.HeaderJustify: "a GPU host"}); code != http.StatusOK {
		t.Fatalf("approve: %d %v", code, doc)
	}
	f.place("gpu-01", "tiny-gpu-01", 0)
}

func (f *fixture) disabledCount() int {
	f.t.Helper()
	var n int
	if err := f.db.Read().QueryRow(
		`SELECT count(*) FROM deployment WHERE model_id = 'acme/tiny' AND disabled = 1`).Scan(&n); err != nil {
		f.t.Fatal(err)
	}
	return n
}

// R2-28's remaining endpoints. The capability has existed since R4-35/36 as CLI
// verbs; what was missing was the HTTP surface, which is what an administrator
// who is not root on the control plane has to reach it through.
func TestDisableAndEnableOverTheAPI(t *testing.T) {
	f := newFixture(t)
	f.ready(t)

	code, doc := f.do(http.MethodPost, "/models/acme%2Ftiny/disable", f.admin, nil,
		map[string]string{api.HeaderJustify: "taking it out of service"})
	if code != http.StatusOK {
		t.Fatalf("disable: %d %v", code, doc)
	}
	if n := f.disabledCount(); n != 1 {
		t.Errorf("%d deployments disabled, want 1", n)
	}
	// Its own action, not config.apply: the chain has to answer "who stopped
	// this model" with the verb somebody used.
	if doc["action"] != "model.disable" {
		t.Errorf("action = %v, want model.disable", doc["action"])
	}

	if code, doc := f.do(http.MethodPost, "/models/acme%2Ftiny/enable", f.admin, nil,
		map[string]string{api.HeaderJustify: "back into service"}); code != http.StatusOK {
		t.Fatalf("enable: %d %v", code, doc)
	}
	if n := f.disabledCount(); n != 0 {
		t.Errorf("%d deployments still disabled after enable", n)
	}
}

// A model nobody has deployed is a 404 naming it, not a successful no-op that
// leaves an operator believing something was stopped.
func TestDisablingAModelWithNoDeploymentIsRefused(t *testing.T) {
	f := newFixture(t)
	f.ready(t)
	code, doc := f.do(http.MethodPost, "/models/acme%2Fnothing/disable", f.admin, nil,
		map[string]string{api.HeaderJustify: "checking"})
	if code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404: %v", code, doc)
	}
}

func TestRestartOverTheAPIQueuesItForTheNode(t *testing.T) {
	f := newFixture(t)
	f.ready(t)

	// A restart is a single node's act, so the node is required rather than
	// guessed at.
	if code, doc := f.do(http.MethodPost, "/models/acme%2Ftiny/restart", f.admin, nil,
		map[string]string{api.HeaderJustify: "cycling it"}); code != http.StatusBadRequest {
		t.Fatalf("restart without a node: %d %v", code, doc)
	}

	code, doc := f.do(http.MethodPost, "/models/acme%2Ftiny/restart?node=gpu-01", f.admin, nil,
		map[string]string{api.HeaderJustify: "cycling it"})
	if code != http.StatusOK {
		t.Fatalf("restart: %d %v", code, doc)
	}
	var n int
	if err := f.db.Read().QueryRow(
		`SELECT count(*) FROM deployment_restart WHERE node_name = 'gpu-01'`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Errorf("%d restart requests queued, want 1", n)
	}
}

// A disabled replica is skipped rather than failing the whole request — and the
// caller is told which, or they are left counting replicas that did not cycle.
func TestARestartNamesTheReplicasItSkipped(t *testing.T) {
	f := newFixture(t)
	f.ready(t)
	if code, doc := f.do(http.MethodPost, "/models/acme%2Ftiny/disable", f.admin, nil,
		map[string]string{api.HeaderJustify: "off for now"}); code != http.StatusOK {
		t.Fatalf("disable: %d %v", code, doc)
	}

	code, doc := f.do(http.MethodPost, "/models/acme%2Ftiny/restart?node=gpu-01", f.admin, nil,
		map[string]string{api.HeaderJustify: "cycling it"})
	if code != http.StatusOK {
		t.Fatalf("restart: %d %v", code, doc)
	}
	result, _ := doc["result"].(map[string]any)
	skipped, _ := result["skipped_disabled"].([]any)
	if len(skipped) != 1 {
		t.Errorf("skipped = %v, want the disabled deployment named", result)
	}
	var n int
	if err := f.db.Read().QueryRow(`SELECT count(*) FROM deployment_restart`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Errorf("%d restarts queued for a disabled deployment", n)
	}
}

// docs/specs/07-identity-audit.md §1 gives enable and disable to an operator.
// A viewer reads the fleet and changes nothing in it.
func TestAViewerCannotDisableAModel(t *testing.T) {
	f := newFixture(t)
	f.ready(t)
	f.addUser("frank", "viewer")
	_, minted, _ := f.mintToken("frank", "")
	viewer := secretOf(minted)
	if viewer == "" {
		t.Fatalf("no token: %v", minted)
	}

	code, doc := f.do(http.MethodPost, "/models/acme%2Ftiny/disable", viewer, nil,
		map[string]string{api.HeaderJustify: "trying it on"})
	if code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403: %v", code, doc)
	}
	if n := f.disabledCount(); n != 0 {
		t.Error("a viewer disabled a deployment")
	}
}

// ?node= narrows the act to one machine. Without it every deployment of the
// model stops, which is a very different thing to have meant.
func TestDisablingCanBeNarrowedToOneNode(t *testing.T) {
	f := newFixture(t)
	f.ready(t)
	f.join("gpu-02")
	if code, doc := f.do(http.MethodPost, "/nodes/gpu-02/approve", f.admin, nil,
		map[string]string{api.HeaderJustify: "a second host"}); code != http.StatusOK {
		t.Fatalf("approve: %d %v", code, doc)
	}
	f.place("gpu-02", "tiny-gpu-02", 0)

	if code, doc := f.do(http.MethodPost, "/models/acme%2Ftiny/disable?node=gpu-01", f.admin, nil,
		map[string]string{api.HeaderJustify: "draining one host"}); code != http.StatusOK {
		t.Fatalf("disable: %d %v", code, doc)
	}
	if n := f.disabledCount(); n != 1 {
		t.Fatalf("%d deployments disabled, want only the one on gpu-01", n)
	}
	var disabled string
	if err := f.db.Read().QueryRow(
		`SELECT id FROM deployment WHERE disabled = 1`).Scan(&disabled); err != nil {
		t.Fatal(err)
	}
	if disabled != "tiny-gpu-01" {
		t.Errorf("disabled %q, want tiny-gpu-01", disabled)
	}
}
