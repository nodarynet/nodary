package cli

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// registerModelOnGPU is registerModel with an explicit GPU index, for a
// second deployment on the same node — registerModel always claims GPU 0,
// which two deployments on one node cannot share.
func (a *appliance) registerModelOnGPU(t *testing.T, id, node string, gpu int) {
	t.Helper()
	models := t.TempDir()
	dir := filepath.Join(models, "hub", "models--"+strings.ReplaceAll(id, "/", "--"))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "config.json"), []byte(`{}`), 0o644); err != nil {
		t.Fatal(err)
	}
	// No --port: two deployments on one node may not publish the same loopback
	// port, and picking the free one is register's job. This fixture used to
	// pass 8000+gpu, which collides with registerModel's 8001 at gpu 1 — the
	// exact bug config.Apply's checkPorts now refuses.
	code, _, stderr := a.run("model", "register", id, "--node", node, "--models-dir", models,
		"--gpu", strconv.Itoa(gpu), "--yes", "--justify", "test fixture")
	if code != ExitOK {
		t.Fatalf("registering %s on gpu %d: exit %d: %s", id, gpu, code, stderr)
	}
}

func TestRouteListAndShowReadWhatRegisterCreated(t *testing.T) {
	a := newAppliance(t)
	a.enrolled("fractal")
	a.addUser("alice", "operator")
	a.registerModel(t, "acme/tiny", "fractal")

	code, stdout, stderr := a.run("route", "list")
	if code != ExitOK {
		t.Fatalf("route list: exit %d: %s", code, stderr)
	}
	if !strings.Contains(stdout, "tiny") {
		t.Errorf("stdout = %q, want the route register created (named after the model, lowercased)", stdout)
	}

	code, stdout, stderr = a.run("route", "show", "tiny")
	if code != ExitOK {
		t.Fatalf("route show: exit %d: %s", code, stderr)
	}
	if !strings.Contains(stdout, "round-robin") || !strings.Contains(stdout, "tiny-fractal") {
		t.Errorf("stdout = %q, want the default strategy and register's own deployment", stdout)
	}
}

func TestRouteShowRefusesAnUnknownName(t *testing.T) {
	a := newAppliance(t)
	a.enrolled("fractal")
	a.addUser("alice", "operator")

	code, _, stderr := a.run("route", "show", "nope")
	if code == ExitOK {
		t.Fatal("route show succeeded for a route that does not exist")
	}
	if !strings.Contains(stderr, "no route named") {
		t.Errorf("stderr = %q, want it to say so", stderr)
	}
}

// The asymmetric case docs/specs/05-catalog.md §5 names: canarying a second
// backend onto an existing route without touching the first. Both
// deployments have to be real, registered rows — routes may only name a
// deployment this control plane actually has.
func TestRouteSetAddsAndRemovesMembers(t *testing.T) {
	a := newAppliance(t)
	a.enrolled("fractal")
	a.addUser("alice", "operator")
	a.registerModel(t, "acme/tiny", "fractal")
	a.registerModelOnGPU(t, "acme/other", "fractal", 1)

	code, _, stderr := a.run("route", "set", "tiny", "--add", "other-fractal",
		"--yes", "--justify", "canary a second backend")
	if code != ExitOK {
		t.Fatalf("route set --add: exit %d: %s", code, stderr)
	}
	_, stdout, _ := a.run("route", "show", "tiny")
	if !strings.Contains(stdout, "other-fractal") || !strings.Contains(stdout, "tiny-fractal") {
		t.Errorf("stdout = %q, want both the original deployment and the canary", stdout)
	}

	code, _, stderr = a.run("route", "set", "tiny", "--remove", "other-fractal",
		"--yes", "--justify", "canary done")
	if code != ExitOK {
		t.Fatalf("route set --remove: exit %d: %s", code, stderr)
	}
	_, stdout, _ = a.run("route", "show", "tiny")
	if strings.Contains(stdout, "other-fractal") {
		t.Errorf("stdout = %q, want the canary removed", stdout)
	}
	if !strings.Contains(stdout, "tiny-fractal") {
		t.Errorf("stdout = %q, want the original deployment to have survived both edits", stdout)
	}
}

func TestRouteSetCreatesARouteThatDidNotExist(t *testing.T) {
	a := newAppliance(t)
	a.enrolled("fractal")
	a.addUser("alice", "operator")
	a.registerModel(t, "acme/tiny", "fractal")

	code, _, stderr := a.run("route", "set", "brand-new", "--add", "tiny-fractal",
		"--yes", "--justify", "a manual route")
	if code != ExitOK {
		t.Fatalf("route set: exit %d: %s", code, stderr)
	}
	_, stdout, _ := a.run("route", "show", "brand-new")
	if !strings.Contains(stdout, "tiny-fractal") {
		t.Errorf("stdout = %q, want tiny-fractal on the newly created route", stdout)
	}
}

func TestRouteSetRefusesAnUnknownDeployment(t *testing.T) {
	a := newAppliance(t)
	a.enrolled("fractal")
	a.addUser("alice", "operator")
	a.registerModel(t, "acme/tiny", "fractal")

	code, _, stderr := a.run("route", "set", "tiny", "--add", "not-a-real-deployment",
		"--yes", "--justify", "x")
	if code == ExitOK {
		t.Fatal("route set succeeded naming a deployment this control plane does not have")
	}
	if !strings.Contains(stderr, "does not have") {
		t.Errorf("stderr = %q, want it to name the missing deployment", stderr)
	}
}

func TestRouteSetRequiresAddRemoveOrStrategy(t *testing.T) {
	a := newAppliance(t)
	a.enrolled("fractal")
	a.addUser("alice", "operator")

	if code, _, _ := a.run("route", "set", "tiny", "--yes", "--justify", "x"); code != ExitUsage {
		t.Errorf("route set with nothing to change: exit %d, want ExitUsage", code)
	}
}

// `model register` defaults --port to 8001, and a fixed default made
// registering a second model on a node produce two deployments publishing the
// same loopback port — which is not a loud failure, but a route for one model
// answered by another model's server. The default is now a starting point.
func TestRegisteringASecondModelPicksAFreePort(t *testing.T) {
	a := newAppliance(t)
	a.enrolled("fractal")
	a.registerModel(t, "acme/tiny", "fractal") // explicit --port 8001
	a.registerModelOnGPU(t, "acme/other", "fractal", 1)

	_, stdout, _ := a.run("node", "show", "fractal")
	for _, want := range []string{"8001", "8002"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("node show does not report port %s:\n%s", want, stdout)
		}
	}
}

// An explicit --port is not a suggestion. Somebody who names a port that is
// already taken has made a mistake worth refusing, and the refusal names both
// deployments because they are about to change one of them.
func TestAnExplicitPortThatIsTakenIsRefused(t *testing.T) {
	a := newAppliance(t)
	a.enrolled("fractal")
	a.registerModel(t, "acme/tiny", "fractal")

	models := t.TempDir()
	dir := filepath.Join(models, "hub", "models--acme--other")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "config.json"), []byte(`{}`), 0o644); err != nil {
		t.Fatal(err)
	}
	code, _, stderr := a.run("model", "register", "acme/other", "--node", "fractal",
		"--models-dir", models, "--gpu", "1", "--port", "8001",
		"--yes", "--justify", "the same port on purpose")
	if code == ExitOK {
		t.Fatal("a second deployment took a port that was already published")
	}
	for _, want := range []string{"tiny-fractal", "8001"} {
		if !strings.Contains(stderr, want) {
			t.Errorf("the refusal does not name %s: %s", want, stderr)
		}
	}
}
