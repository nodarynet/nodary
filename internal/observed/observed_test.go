package observed

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"github.com/nodarynet/nodary/internal/audit"
	"github.com/nodarynet/nodary/internal/store"
)

// TestHeartbeatConsumesAnAckedResetRequest is R4-35/R4-36's ack half:
// `nodary model restage`/`unstage` leaves a row in `stage_reset` for the
// agent to act on, and the agent reports back which models it actually
// discarded on its next heartbeat. That report should consume exactly the
// rows it names, leaving an unrelated one untouched.
func TestHeartbeatConsumesAnAckedResetRequest(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(ctx, filepath.Join(t.TempDir(), "nodary.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Migrate(ctx); err != nil {
		t.Fatal(err)
	}

	now := time.Now().UTC().Format(audit.TimeFormat)
	if err := db.WriteTx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO node (name, state, created_at) VALUES (?, 'approved', ?)`, "gpu-01", now); err != nil {
			return err
		}
		for _, id := range []string{"acme/tiny", "acme/other"} {
			if _, err := tx.ExecContext(ctx,
				`INSERT INTO model (id, backend, source, artifact, created_at) VALUES (?, 'vllm', 'remote', 'hf-cache', ?)`,
				id, now); err != nil {
				return err
			}
			if _, err := tx.ExecContext(ctx,
				`INSERT INTO stage_reset (node_name, model_id, requested_at) VALUES (?, ?, ?)`,
				"gpu-01", id, now); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	if err := Heartbeat(ctx, db, "gpu-01", NodeReport{ResetDone: []string{"acme/tiny"}}, time.Now()); err != nil {
		t.Fatal(err)
	}

	var left []string
	rows, err := db.Read().QueryContext(ctx, `SELECT model_id FROM stage_reset WHERE node_name = ?`, "gpu-01")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			t.Fatal(err)
		}
		left = append(left, id)
	}

	if len(left) != 1 || left[0] != "acme/other" {
		t.Errorf("stage_reset rows left = %v, want only [acme/other]: acme/tiny was acked, acme/other was not", left)
	}
}

// R4-36: `nodary model restart` leaves a row in deployment_restart for the
// agent to act on, acknowledged the same way stage_reset rows are.
func TestHeartbeatConsumesAnAckedRestartRequest(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(ctx, filepath.Join(t.TempDir(), "nodary.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Migrate(ctx); err != nil {
		t.Fatal(err)
	}

	now := time.Now().UTC().Format(audit.TimeFormat)
	if err := db.WriteTx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO node (name, state, created_at) VALUES (?, 'approved', ?)`, "gpu-01", now); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO model (id, backend, source, artifact, created_at) VALUES (?, 'vllm', 'local', 'hf-cache', ?)`,
			"acme/tiny", now); err != nil {
			return err
		}
		for _, id := range []string{"dep_one", "dep_two"} {
			if _, err := tx.ExecContext(ctx,
				`INSERT INTO deployment (id, model_id, node_name, backend, params_json, extra_args_json,
				                         env_json, disabled, state, created_at, updated_at)
				 VALUES (?, 'acme/tiny', 'gpu-01', 'vllm', '{}', '[]', '{}', 0, 'ready', ?, ?)`,
				id, now, now); err != nil {
				return err
			}
			if _, err := tx.ExecContext(ctx,
				`INSERT INTO deployment_restart (node_name, deployment_id, requested_at) VALUES (?, ?, ?)`,
				"gpu-01", id, now); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	if err := Heartbeat(ctx, db, "gpu-01", NodeReport{RestartDone: []string{"dep_one"}}, time.Now()); err != nil {
		t.Fatal(err)
	}

	var left []string
	rows, err := db.Read().QueryContext(ctx, `SELECT deployment_id FROM deployment_restart WHERE node_name = ?`, "gpu-01")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			t.Fatal(err)
		}
		left = append(left, id)
	}
	if len(left) != 1 || left[0] != "dep_two" {
		t.Errorf("deployment_restart rows left = %v, want only [dep_two]: dep_one was acked, dep_two was not", left)
	}
}

// nodeWithTwoDeployments is an approved node carrying dep_one and dep_two.
func nodeWithTwoDeployments(t *testing.T) *store.DB {
	t.Helper()
	ctx := context.Background()
	db, err := store.Open(ctx, filepath.Join(t.TempDir(), "nodary.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if err := db.Migrate(ctx); err != nil {
		t.Fatal(err)
	}

	now := time.Now().UTC().Format(audit.TimeFormat)
	if err := db.WriteTx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO node (name, state, created_at) VALUES (?, 'approved', ?)`, "gpu-01", now); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO model (id, backend, source, artifact, created_at) VALUES (?, 'vllm', 'local', 'hf-cache', ?)`,
			"acme/tiny", now); err != nil {
			return err
		}
		for _, id := range []string{"dep_one", "dep_two"} {
			if _, err := tx.ExecContext(ctx,
				`INSERT INTO deployment (id, model_id, node_name, backend, params_json, extra_args_json,
				                         env_json, disabled, state, created_at, updated_at)
				 VALUES (?, 'acme/tiny', 'gpu-01', 'vllm', '{}', '[]', '{}', 0, 'defined', ?, ?)`,
				id, now, now); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	return db
}

// R4-15 / R2-02: a node reports the complete set of what it is refusing on
// every heartbeat, so the stored set is replaced rather than added to — a
// refusal that stops being reported has stopped applying, and one left on
// display after the configuration was fixed is worse than none.
func TestHeartbeatReplacesTheRefusalSet(t *testing.T) {
	ctx := context.Background()
	db := nodeWithTwoDeployments(t)

	report := NodeReport{Rev: 7, Refusals: []RefusalReport{
		{Deployment: "dep_one", Reason: "GPU 3 is not on this node's offer"},
		{Deployment: "dep_two", Reason: "backend \"sglang\" is not one this build has"},
		// A deployment the configuration does not have: refused by the
		// EXISTS guard, the same way an unknown model's staging row is.
		{Deployment: "dep_ghost", Reason: "invented by a node"},
	}}
	if err := Heartbeat(ctx, db, "gpu-01", report, time.Now()); err != nil {
		t.Fatal(err)
	}

	got := refusalsOf(t, db, "gpu-01")
	if len(got) != 2 || got["dep_one"] == "" || got["dep_two"] == "" {
		t.Fatalf("refusals = %v, want exactly dep_one and dep_two", got)
	}
	if _, invented := got["dep_ghost"]; invented {
		t.Error("a node created a refusal row for a deployment nobody registered")
	}

	// The operator fixes one. The next heartbeat names only the other, and
	// the fixed one must disappear rather than linger.
	if err := Heartbeat(ctx, db, "gpu-01", NodeReport{Rev: 8, Refusals: []RefusalReport{
		{Deployment: "dep_two", Reason: "backend \"sglang\" is not one this build has"},
	}}, time.Now()); err != nil {
		t.Fatal(err)
	}
	if got := refusalsOf(t, db, "gpu-01"); len(got) != 1 || got["dep_two"] == "" {
		t.Errorf("refusals = %v, want only dep_two: dep_one stopped being refused", got)
	}

	// And a heartbeat refusing nothing clears the node.
	if err := Heartbeat(ctx, db, "gpu-01", NodeReport{Rev: 9}, time.Now()); err != nil {
		t.Fatal(err)
	}
	if got := refusalsOf(t, db, "gpu-01"); len(got) != 0 {
		t.Errorf("refusals = %v, want none", got)
	}
}

func refusalsOf(t *testing.T, db *store.DB, node string) map[string]string {
	t.Helper()
	rows, err := db.Read().QueryContext(context.Background(),
		`SELECT deployment_id, reason FROM refusal WHERE node_name = ?`, node)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var id, reason string
		if err := rows.Scan(&id, &reason); err != nil {
			t.Fatal(err)
		}
		out[id] = reason
	}
	return out
}

// R4-37: staging progress is reported as bytes against a total, and this is
// the one hop that actually writes it — everywhere else along the way is a
// field carried from one struct to the next, and this is where it lands in
// the database `nodary node show` reads back.
func TestHeartbeatWritesStagingBytesAgainstTotal(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(ctx, filepath.Join(t.TempDir(), "nodary.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Migrate(ctx); err != nil {
		t.Fatal(err)
	}

	now := time.Now().UTC().Format(audit.TimeFormat)
	if err := db.WriteTx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO node (name, state, created_at) VALUES (?, 'approved', ?)`, "gpu-01", now); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx,
			`INSERT INTO model (id, backend, source, artifact, created_at) VALUES (?, 'vllm', 'remote', 'hf-cache', ?)`,
			"acme/tiny", now)
		return err
	}); err != nil {
		t.Fatal(err)
	}

	report := NodeReport{Staging: []StagingReport{
		{Model: "acme/tiny", State: "staging", BytesDone: 40, BytesTotal: 100},
	}}
	if err := Heartbeat(ctx, db, "gpu-01", report, time.Now()); err != nil {
		t.Fatal(err)
	}

	var done, total int64
	row := db.Read().QueryRowContext(ctx,
		`SELECT bytes_done, bytes_total FROM staging WHERE node_name = ? AND model_id = ?`,
		"gpu-01", "acme/tiny")
	if err := row.Scan(&done, &total); err != nil {
		t.Fatal(err)
	}
	if done != 40 || total != 100 {
		t.Errorf("bytes_done, bytes_total = %d, %d, want 40, 100", done, total)
	}
}

// kindsOf is refusalsOf with the verdict rather than the reason.
func kindsOf(t *testing.T, db *store.DB, node string) map[string]string {
	t.Helper()
	rows, err := db.Read().QueryContext(context.Background(),
		`SELECT deployment_id, kind FROM refusal WHERE node_name = ?`, node)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var id, kind string
		if err := rows.Scan(&id, &kind); err != nil {
			t.Fatal(err)
		}
		out[id] = kind
	}
	return out
}

// R4-16. The two verdicts share a table and a replace, and they must not share
// a meaning: one says nothing is running, the other says something is. A
// placement that moves between them — the operator widens the limit, or
// narrows it under a model that is already up — must end with one row, not two.
func TestHeartbeatKeepsRefusedAndOutOfPolicyApart(t *testing.T) {
	ctx := context.Background()
	db := nodeWithTwoDeployments(t)

	if err := Heartbeat(ctx, db, "gpu-01", NodeReport{Rev: 7,
		Refusals:    []RefusalReport{{Deployment: "dep_one", Reason: "GPU 3 is not on this node's offer"}},
		OutOfPolicy: []RefusalReport{{Deployment: "dep_two", Reason: "node.toml caps max_vram_fraction at 0.5"}},
	}, time.Now()); err != nil {
		t.Fatal(err)
	}
	got := kindsOf(t, db, "gpu-01")
	if got["dep_one"] != KindRefused {
		t.Errorf("dep_one is %q, want %q", got["dep_one"], KindRefused)
	}
	if got["dep_two"] != KindOutOfPolicy {
		t.Errorf("dep_two is %q, want %q", got["dep_two"], KindOutOfPolicy)
	}

	// The deployment stops and the same guardrail now refuses it instead. One
	// row, with the new verdict: the replace is what makes that true, and an
	// upsert keyed on (node, deployment) would have left the old kind behind.
	if err := Heartbeat(ctx, db, "gpu-01", NodeReport{Rev: 8,
		Refusals: []RefusalReport{{Deployment: "dep_two", Reason: "node.toml caps max_vram_fraction at 0.5"}},
	}, time.Now()); err != nil {
		t.Fatal(err)
	}
	got = kindsOf(t, db, "gpu-01")
	if len(got) != 1 || got["dep_two"] != KindRefused {
		t.Errorf("kinds = %v, want dep_two refused and nothing else", got)
	}
}

// egressOf reads the stored verdict for one deployment.
func egressOf(t *testing.T, db *store.DB, id string) (state, reason, at string) {
	t.Helper()
	if err := db.Read().QueryRow(
		`SELECT coalesce(egress_state, ''), coalesce(egress_reason, ''), coalesce(egress_checked_at, '')
		 FROM deployment WHERE id = ?`, id).Scan(&state, &reason, &at); err != nil {
		t.Fatal(err)
	}
	return state, reason, at
}

// R4-29 / R2-26: docs/specs/03-agent.md §5's verdict is reached on a start and
// while it is inconclusive, not on every heartbeat — so most reports carry no
// new answer, and a report carrying none must leave the stored one standing.
// Blanking it would make a node that asserted isolation ten seconds ago
// indistinguishable from one that has never been probed, which is the
// difference `GET /nodes/{name}/verify-egress` exists to report.
func TestHeartbeatKeepsTheLastEgressVerdictUntilANewOneArrives(t *testing.T) {
	ctx := context.Background()
	db := nodeWithTwoDeployments(t)

	first := time.Date(2026, 9, 13, 10, 0, 0, 0, time.UTC)
	if err := Heartbeat(ctx, db, "gpu-01", NodeReport{Deployments: []DeploymentReport{
		{ID: "dep_one", State: "ready", Egress: "compliant"},
		{ID: "dep_two", State: "ready"},
	}}, first); err != nil {
		t.Fatal(err)
	}
	state, _, at := egressOf(t, db, "dep_one")
	if state != "compliant" || at != first.Format(audit.TimeFormat) {
		t.Fatalf("dep_one = %q at %q, want compliant at %v", state, at, first)
	}
	// Never probed, because it has never run: null, not a verdict.
	if state, _, at := egressOf(t, db, "dep_two"); state != "" || at != "" {
		t.Errorf("dep_two = %q at %q, want nothing asserted", state, at)
	}

	// A later heartbeat with no new answer. The unit states move; the verdict
	// does not.
	later := first.Add(15 * time.Second)
	if err := Heartbeat(ctx, db, "gpu-01", NodeReport{Deployments: []DeploymentReport{
		{ID: "dep_one", State: "ready"},
	}}, later); err != nil {
		t.Fatal(err)
	}
	if state, _, at := egressOf(t, db, "dep_one"); state != "compliant" || at != first.Format(audit.TimeFormat) {
		t.Errorf("after a heartbeat with no verdict dep_one = %q at %q, want the first one kept", state, at)
	}

	// And a new answer replaces it, timestamp and reason together.
	newer := later.Add(15 * time.Second)
	if err := Heartbeat(ctx, db, "gpu-01", NodeReport{Deployments: []DeploymentReport{
		{ID: "dep_one", State: "ready", Egress: "non-compliant", EgressReason: "dns: resolved example.com"},
	}}, newer); err != nil {
		t.Fatal(err)
	}
	state, reason, at := egressOf(t, db, "dep_one")
	if state != "non-compliant" || reason != "dns: resolved example.com" || at != newer.Format(audit.TimeFormat) {
		t.Errorf("dep_one = %q/%q at %q, want the new verdict", state, reason, at)
	}
}

// The same rule the deployment, staging and refusal writes follow: a node may
// report on what the configuration placed there and may not invent a row.
func TestAnEgressVerdictForAnotherNodesDeploymentIsIgnored(t *testing.T) {
	ctx := context.Background()
	db := nodeWithTwoDeployments(t)

	now := time.Date(2026, 9, 13, 10, 0, 0, 0, time.UTC)
	if err := db.WriteTx(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx,
			`INSERT INTO node (name, state, created_at) VALUES ('gpu-02', 'approved', ?)`,
			now.Format(audit.TimeFormat))
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := Heartbeat(ctx, db, "gpu-02", NodeReport{Deployments: []DeploymentReport{
		{ID: "dep_one", State: "ready", Egress: "compliant"},
	}}, now); err != nil {
		t.Fatal(err)
	}
	if state, _, _ := egressOf(t, db, "dep_one"); state != "" {
		t.Errorf("dep_one on gpu-01 = %q after gpu-02 reported on it; a node may only report on its own", state)
	}
}
