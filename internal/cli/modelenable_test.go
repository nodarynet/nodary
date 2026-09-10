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
