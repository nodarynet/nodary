package cli

import (
	"context"
	"strings"
	"testing"

	"github.com/nodarynet/nodary/internal/store"
)

func (a *appliance) restartRows(t *testing.T) []string {
	t.Helper()
	db, err := store.Open(context.Background(), a.db)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	rows, err := db.Read().QueryContext(context.Background(), `SELECT deployment_id FROM deployment_restart`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			t.Fatal(err)
		}
		out = append(out, id)
	}
	return out
}

func TestRestartWritesADeploymentRestartRow(t *testing.T) {
	a := newAppliance(t)
	a.enrolled("fractal")
	a.addUser("alice", "operator")
	a.registerModel(t, "acme/tiny", "fractal")

	code, _, stderr := a.run("model", "restart", "acme/tiny", "--node", "fractal",
		"--yes", "--justify", "picking up a config change")
	if code != ExitOK {
		t.Fatalf("restart: exit %d: %s", code, stderr)
	}
	if rows := a.restartRows(t); len(rows) != 1 {
		t.Errorf("deployment_restart = %v, want exactly one row", rows)
	}
}

func TestRestartRequiresANode(t *testing.T) {
	a := newAppliance(t)
	a.enrolled("fractal")
	a.addUser("alice", "operator")
	a.registerModel(t, "acme/tiny", "fractal")

	if code, _, _ := a.run("model", "restart", "acme/tiny", "--yes", "--justify", "x"); code != ExitUsage {
		t.Errorf("restart with no --node: exit %d, want ExitUsage", code)
	}
}

func TestRestartRefusesWithNoMatchingDeployment(t *testing.T) {
	a := newAppliance(t)
	a.enrolled("fractal")
	a.addUser("alice", "operator")

	code, _, stderr := a.run("model", "restart", "acme/tiny", "--node", "fractal",
		"--yes", "--justify", "x")
	if code == ExitOK {
		t.Fatal("restart succeeded against a model with no deployment on that node")
	}
	if !strings.Contains(stderr, "no deployment") {
		t.Errorf("stderr = %q, want it to say there is nothing to restart", stderr)
	}
}

// A disabled deployment is skipped, not a reason to fail the whole request —
// restart is for something an operator expects to be running.
func TestRestartSkipsADisabledDeployment(t *testing.T) {
	a := newAppliance(t)
	a.enrolled("fractal")
	a.addUser("alice", "operator")
	a.registerModel(t, "acme/tiny", "fractal")
	if code, _, stderr := a.run("model", "disable", "acme/tiny", "--yes", "--justify", "x"); code != ExitOK {
		t.Fatalf("disable: exit %d: %s", code, stderr)
	}

	code, _, stderr := a.run("model", "restart", "acme/tiny", "--node", "fractal",
		"--yes", "--justify", "x")
	if code != ExitOK {
		t.Fatalf("restart: exit %d: %s", code, stderr)
	}
	if !strings.Contains(stderr, "disabled") {
		t.Errorf("stderr = %q, want it to name the skipped, disabled deployment", stderr)
	}
	if rows := a.restartRows(t); len(rows) != 0 {
		t.Errorf("deployment_restart = %v, want nothing written for a disabled deployment", rows)
	}
}
