package cli

import (
	"context"
	"database/sql"
	"strings"
	"testing"

	"github.com/nodarynet/nodary/internal/store"
)

// refused writes the refusal row a heartbeat would, so the display can be
// tested without a live agent — the same shortcut markCorrupt takes for
// staging state.
func (a *appliance) refused(t *testing.T, node, deployment, reason string) {
	t.Helper()
	db, err := store.Open(context.Background(), a.db)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.WriteTx(context.Background(), func(tx *sql.Tx) error {
		_, err := tx.ExecContext(context.Background(),
			`INSERT INTO refusal (node_name, deployment_id, rev, reason, updated_at)
			 VALUES (?, ?, 4, ?, '2026-09-11T00:00:00.000000000Z')`, node, deployment, reason)
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

// R4-15: "Refusals are recorded, surfaced against the node, and not
// retried." A refused deployment sits in `defined` forever with every other
// column looking healthy, so without this the operator's only clue is on the
// node's own journal, on a machine they may not have a shell on.
func TestNodeShowSurfacesARefusalAndWhatToDo(t *testing.T) {
	a := newAppliance(t)
	a.enrolled("fractal")
	a.addUser("alice", "operator")
	a.registerModel(t, "acme/tiny", "fractal")
	a.refused(t, "fractal", "tiny-fractal", "GPU 3 is not on this node's offer")

	code, stdout, stderr := a.run("node", "show", "fractal")
	if code != ExitOK {
		t.Fatalf("node show: exit %d: %s", code, stderr)
	}
	if !strings.Contains(stdout, "GPU 3 is not on this node's offer") {
		t.Errorf("stdout = %q, want the reason the node gave", stdout)
	}
	if !strings.Contains(stdout, "tiny-fractal") {
		t.Errorf("stdout = %q, want the refused deployment named", stdout)
	}
	// Naming the problem is half of it; docs/specs/12-node-guardrails.md §1
	// says nothing retries, so the operator has to know it is on them.
	if !strings.Contains(stderr, "not retrying") {
		t.Errorf("stderr = %q, want it to say nothing is retrying this", stderr)
	}

	// And it travels in the machine-readable form too, for anything watching
	// a fleet rather than reading one node.
	code, stdout, stderr = a.run("node", "show", "fractal", "--format", "json")
	if code != ExitOK {
		t.Fatalf("node show --format json: exit %d: %s", code, stderr)
	}
	if !strings.Contains(stdout, `"refusals"`) || !strings.Contains(stdout, "not on this node's offer") {
		t.Errorf("stdout = %q, want refusals in the JSON form", stdout)
	}
}

// A healthy node shows no refusal section at all — an empty table headed
// REFUSED would read as a problem.
func TestNodeShowSaysNothingAboutRefusalsWhenThereAreNone(t *testing.T) {
	a := newAppliance(t)
	a.enrolled("fractal")
	a.addUser("alice", "operator")
	a.registerModel(t, "acme/tiny", "fractal")

	_, stdout, stderr := a.run("node", "show", "fractal")
	if strings.Contains(stdout, "REFUSED") || strings.Contains(stderr, "not retrying") {
		t.Errorf("a node refusing nothing mentioned refusals:\n%s\n%s", stdout, stderr)
	}
}
