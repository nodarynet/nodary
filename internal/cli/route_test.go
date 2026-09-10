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
	code, _, stderr := a.run("model", "register", id, "--node", node, "--models-dir", models,
		"--gpu", strconv.Itoa(gpu), "--port", strconv.Itoa(8000+gpu), "--yes", "--justify", "test fixture")
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
