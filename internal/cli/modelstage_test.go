package cli

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nodarynet/nodary/internal/store"
)

// registerModel puts a model, deployment, route and grant on the given node
// through the real CLI verb, the way TestModelRegisterTurnsPlacedWeightsIntoAServedRoute
// does — so the fixtures these tests build on are exactly what an operator's
// own `model register` produces, not a shortcut that could drift from it.
func (a *appliance) registerModel(t *testing.T, id, node string) {
	t.Helper()
	models := t.TempDir()
	dir := filepath.Join(models, "hub", "models--"+strings.ReplaceAll(id, "/", "--"))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "config.json"), []byte(`{}`), 0o644); err != nil {
		t.Fatal(err)
	}
	code, _, stderr := a.run("model", "register", id,
		"--node", node, "--models-dir", models, "--port", "8001", "--yes", "--justify", "test fixture")
	if code != ExitOK {
		t.Fatalf("registering %s: exit %d: %s", id, code, stderr)
	}
}

// modelWithNoDeployment writes a catalog entry directly, the way `enrolled`
// puts a node in the database: unstage's whole precondition is "nothing
// deploys this model here", and `model register` cannot produce that shape
// on its own — it always creates a deployment alongside the model.
func (a *appliance) modelWithNoDeployment(t *testing.T, id, source string) {
	t.Helper()
	db, err := store.Open(context.Background(), a.db)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.WriteTx(context.Background(), func(tx *sql.Tx) error {
		_, err := tx.ExecContext(context.Background(),
			`INSERT INTO model (id, backend, source, artifact, created_at)
			 VALUES (?, 'vllm', ?, 'hf-cache', '2026-09-08T00:00:00.000000000Z')`, id, source)
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

// markCorrupt writes the observed staging row a heartbeat would, the way
// restage's precondition expects to find one — without a live agent to
// report it.
func (a *appliance) markCorrupt(t *testing.T, node, model string) {
	t.Helper()
	db, err := store.Open(context.Background(), a.db)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.WriteTx(context.Background(), func(tx *sql.Tx) error {
		_, err := tx.ExecContext(context.Background(),
			`INSERT INTO staging (model_id, node_name, state, error, updated_at)
			 VALUES (?, ?, 'corrupt', 'a byte did not match', '2026-09-08T00:00:00.000000000Z')`,
			model, node)
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

func (a *appliance) stageResetRows(t *testing.T) []string {
	t.Helper()
	db, err := store.Open(context.Background(), a.db)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	rows, err := db.Read().QueryContext(context.Background(), `SELECT model_id FROM stage_reset`)
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

func TestUnstageRefusesWithALiveDeployment(t *testing.T) {
	a := newAppliance(t)
	a.enrolled("fractal")
	a.addUser("alice", "operator")
	a.registerModel(t, "acme/tiny", "fractal")

	code, _, stderr := a.run("model", "unstage", "acme/tiny", "--node", "fractal",
		"--yes", "--justify", "reclaim space")
	if code == ExitOK {
		t.Fatal("unstage succeeded against a model with a live deployment")
	}
	if !strings.Contains(stderr, "still deployed") {
		t.Errorf("stderr = %q, want it to name the live deployment", stderr)
	}
	if rows := a.stageResetRows(t); len(rows) != 0 {
		t.Errorf("stage_reset = %v, want nothing written on refusal", rows)
	}
}

func TestUnstageSucceedsWithNoDeployment(t *testing.T) {
	a := newAppliance(t)
	a.enrolled("fractal")
	a.addUser("alice", "operator")
	a.modelWithNoDeployment(t, "acme/tiny", "local")

	code, _, stderr := a.run("model", "unstage", "acme/tiny", "--node", "fractal",
		"--yes", "--justify", "reclaim space")
	if code != ExitOK {
		t.Fatalf("unstage: exit %d: %s", code, stderr)
	}
	if rows := a.stageResetRows(t); len(rows) != 1 || rows[0] != "acme/tiny" {
		t.Errorf("stage_reset = %v, want [acme/tiny]", rows)
	}
}

func TestRestageRefusesForLocalSource(t *testing.T) {
	a := newAppliance(t)
	a.enrolled("fractal")
	a.addUser("alice", "operator")
	a.registerModel(t, "acme/tiny", "fractal") // source: local, the default

	code, _, stderr := a.run("model", "restage", "acme/tiny", "--node", "fractal",
		"--yes", "--justify", "retry")
	if code == ExitOK {
		t.Fatal("restage succeeded for a source: local model")
	}
	if !strings.Contains(stderr, "source: local") {
		t.Errorf("stderr = %q, want it to name why local is refused", stderr)
	}
}

func TestRestageRefusesUnlessCorrupt(t *testing.T) {
	a := newAppliance(t)
	a.enrolled("fractal")
	a.addUser("alice", "operator")
	a.modelWithNoDeployment(t, "acme/tiny", "remote")

	code, _, stderr := a.run("model", "restage", "acme/tiny", "--node", "fractal",
		"--yes", "--justify", "retry")
	if code == ExitOK {
		t.Fatal("restage succeeded with no corrupt staging state on record")
	}
	if !strings.Contains(stderr, "not corrupt") {
		t.Errorf("stderr = %q, want it to say restage is only for the stuck state", stderr)
	}
}

func TestRestageSucceedsWhenCorrupt(t *testing.T) {
	a := newAppliance(t)
	a.enrolled("fractal")
	a.addUser("alice", "operator")
	a.modelWithNoDeployment(t, "acme/tiny", "remote")
	a.markCorrupt(t, "fractal", "acme/tiny")

	code, _, stderr := a.run("model", "restage", "acme/tiny", "--node", "fractal",
		"--yes", "--justify", "retry")
	if code != ExitOK {
		t.Fatalf("restage: exit %d: %s", code, stderr)
	}
	if rows := a.stageResetRows(t); len(rows) != 1 || rows[0] != "acme/tiny" {
		t.Errorf("stage_reset = %v, want [acme/tiny]", rows)
	}
}

func TestUnstageAndRestageRequireANode(t *testing.T) {
	a := newAppliance(t)
	a.enrolled("fractal")
	a.addUser("alice", "operator")

	for _, verb := range []string{"unstage", "restage"} {
		if code, _, _ := a.run("model", verb, "acme/tiny", "--yes", "--justify", "x"); code != ExitUsage {
			t.Errorf("%s with no --node: exit %d, want ExitUsage", verb, code)
		}
	}
}

// An operator removes a model the way they remove anything: export the
// configuration, delete the block, apply with `--prune`. It did not work.
//
// Two causes, one shape. Objects were pruned in creation order, so the model
// row went before the deployment still pointing at it; and every row an agent
// had ever written *about* a model — a staging observation, a pending reset —
// pinned it forever, because those references deliberately do not cascade.
// Either way what came back was SQLite's own `FOREIGN KEY constraint failed
// (787)`, which is not a refusal at all: nothing wraps it, so an API client
// got a 500 with the message withheld.
func TestPruningAModelTakesEverythingHangingOffItToo(t *testing.T) {
	a := newAppliance(t)
	a.enrolled("gpu-01")
	a.registerModel(t, "acme/tiny", "gpu-01")
	// The rows that pinned it: an observation and two pending requests.
	// Written directly, the way markCorrupt writes the staging row — the
	// verbs that produce them each have preconditions of their own, and what
	// is under test is the prune, not how a mailbox came to have mail in it.
	a.markCorrupt(t, "gpu-01", "acme/tiny")
	a.execSQL(`INSERT INTO stage_reset (node_name, model_id, requested_at)
	           VALUES ('gpu-01', 'acme/tiny', '2026-09-08T00:00:00.000000000Z')`)
	a.execSQL(`INSERT INTO deployment_restart (node_name, deployment_id, requested_at)
	           SELECT 'gpu-01', id, '2026-09-08T00:00:00.000000000Z' FROM deployment`)
	if len(a.stageResetRows(t)) == 0 || len(a.restartRows(t)) == 0 {
		t.Fatal("the fixture wrote no pending requests, so this proves nothing")
	}

	// Everything but the node, which cannot be created from a document anyway.
	path := filepath.Join(t.TempDir(), "node-only.toml")
	if err := os.WriteFile(path,
		[]byte("[[node]]\nname = \"gpu-01\"\nstate = \"approved\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	code, out, stderr := a.run("config", "apply", "-f", path, "--prune",
		"--yes", "--justify", "retiring the model")
	if code != ExitOK {
		t.Fatalf("a model could not be removed from the configuration: exit %d\n%s", code, stderr)
	}
	for _, want := range []string{"- model acme/tiny", "- deployment", "- route"} {
		if !strings.Contains(out, want) {
			t.Errorf("the change list does not say %q:\n%s", want, out)
		}
	}
	if rows := a.stageResetRows(t); len(rows) != 0 {
		t.Errorf("stage_reset still holds %v for a model that no longer exists", rows)
	}
	if rows := a.restartRows(t); len(rows) != 0 {
		t.Errorf("deployment_restart still holds %v for a deployment that no longer exists", rows)
	}
	if left := a.scalar(t, `SELECT count(*) FROM staging`); left != "0" {
		t.Errorf("staging still holds %s row(s) for a model that no longer exists", left)
	}
}
