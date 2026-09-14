package cli

import (
	"context"
	"strings"
	"testing"

	"github.com/nodarynet/nodary/internal/store"
)

// deploymentDisabled reads the persisted disabled flag directly, the way
// stageResetRows reads stage_reset — a fact only the database holds.
func (a *appliance) deploymentDisabled(t *testing.T, modelID string) bool {
	t.Helper()
	db, err := store.Open(context.Background(), a.db)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var disabled bool
	if err := db.Read().QueryRowContext(context.Background(),
		`SELECT disabled FROM deployment WHERE model_id = ?`, modelID).Scan(&disabled); err != nil {
		t.Fatal(err)
	}
	return disabled
}

func TestDisableThenEnableRoundTrips(t *testing.T) {
	a := newAppliance(t)
	a.enrolled("fractal")
	a.addUser("alice", "operator")
	a.registerModel(t, "acme/tiny", "fractal")

	if code, _, stderr := a.run("model", "disable", "acme/tiny",
		"--yes", "--justify", "maintenance"); code != ExitOK {
		t.Fatalf("disable: exit %d: %s", code, stderr)
	}
	if !a.deploymentDisabled(t, "acme/tiny") {
		t.Error("disabled = false after `model disable`, want true")
	}

	if code, _, stderr := a.run("model", "enable", "acme/tiny",
		"--yes", "--justify", "maintenance over"); code != ExitOK {
		t.Fatalf("enable: exit %d: %s", code, stderr)
	}
	if a.deploymentDisabled(t, "acme/tiny") {
		t.Error("disabled = true after `model enable`, want false")
	}
}

// --node is optional (docs/specs/05-catalog.md §4's own example brackets it),
// but when given it must actually filter — not simply be ignored.
func TestDisableAcceptsAnExplicitNode(t *testing.T) {
	a := newAppliance(t)
	a.enrolled("fractal")
	a.addUser("alice", "operator")
	a.registerModel(t, "acme/tiny", "fractal")

	if code, _, stderr := a.run("model", "disable", "acme/tiny", "--node", "fractal",
		"--yes", "--justify", "maintenance"); code != ExitOK {
		t.Fatalf("disable: exit %d: %s", code, stderr)
	}
	if !a.deploymentDisabled(t, "acme/tiny") {
		t.Error("disabled = false after `model disable --node fractal`, want true")
	}
}

func TestDisableRefusesWithNoMatchingDeployment(t *testing.T) {
	a := newAppliance(t)
	a.enrolled("fractal")
	a.addUser("alice", "operator")

	code, _, stderr := a.run("model", "disable", "acme/tiny", "--yes", "--justify", "x")
	if code == ExitOK {
		t.Fatal("disable succeeded against a model with no deployment at all")
	}
	if !strings.Contains(stderr, "no deployment") {
		t.Errorf("stderr = %q, want it to say there is nothing to disable", stderr)
	}
}

func TestDisableRefusesWhenTheNodeDoesNotMatch(t *testing.T) {
	a := newAppliance(t)
	a.enrolled("fractal")
	a.addUser("alice", "operator")
	a.registerModel(t, "acme/tiny", "fractal")

	code, _, stderr := a.run("model", "disable", "acme/tiny", "--node", "elsewhere",
		"--yes", "--justify", "x")
	if code == ExitOK {
		t.Fatal("disable succeeded against a node this model is not deployed on")
	}
	if !strings.Contains(stderr, "no deployment") {
		t.Errorf("stderr = %q, want it to say there is nothing to disable on that node", stderr)
	}
}

// A state that can be set and not seen is a state an operator cannot trust.
// `stopped` alone is also what `systemctl stop` produces and what a node that
// has not polled yet still reports, so the one table both appear in has to say
// which of them this is.
func TestNodeShowSaysWhichStoppedDeploymentsWereDisabled(t *testing.T) {
	a := newAppliance(t)
	a.enrolled("gpu-01")
	if code, _, stderr := a.run("node", "approve", "gpu-01", "--yes",
		"--justify", "test fixture"); code != ExitOK {
		t.Fatalf("node approve: exit %d, %s", code, stderr)
	}
	a.registerModel(t, "acme/tiny", "gpu-01")

	code, out, _ := a.run("node", "show", "gpu-01")
	if strings.Contains(out, "disabled") {
		t.Fatalf("a deployment nobody disabled is reported as disabled:\n%s", out)
	}

	if code, _, stderr := a.run("model", "disable", "acme/tiny", "--yes",
		"--justify", "taking it out of service"); code != ExitOK {
		t.Fatalf("model disable: exit %d, %s", code, stderr)
	}

	code, out, stderr := a.run("node", "show", "gpu-01")
	if code != ExitOK {
		t.Fatalf("node show: exit %d, %s", code, stderr)
	}
	if !strings.Contains(out, "(disabled)") {
		t.Errorf("node show does not say the deployment is disabled:\n%s", out)
	}
	// And the card it still holds is named, because disabling stops the unit
	// and does not give the GPU back.
	if !strings.Contains(stderr, "still holds") {
		t.Errorf("node show does not say the disabled deployment still holds its GPU:\n%s", stderr)
	}

	code, out, stderr = a.run("node", "show", "gpu-01", "--format", "json")
	if code != ExitOK {
		t.Fatalf("node show --format json: exit %d, %s", code, stderr)
	}
	if !strings.Contains(out, `"disabled": true`) {
		t.Errorf("the json schema does not carry it:\n%s", out)
	}
}
