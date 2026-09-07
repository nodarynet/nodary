package store

import (
	"context"
	"database/sql"
	"strings"
	"testing"
)

// The fleet schema's job is to refuse things (docs/plans/R2a-fleet-schema.md):
// the control plane is about to grow an HTTP surface and an agent protocol, and
// a rule enforced in one handler is a rule the other one does not have. So each
// case below is a write that must fail, and the ones that must succeed are here
// too — a schema that refuses everything would pass a test that only checked
// for errors.

func fleetDB(t *testing.T) *sql.DB {
	t.Helper()
	db := openTemp(t)
	if err := db.Migrate(context.Background()); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db.write
}

// seed puts one node and one model in place, since almost everything references
// them.
func seed(t *testing.T, db *sql.DB) {
	t.Helper()
	for _, s := range []string{
		`INSERT INTO node (name, state, created_at) VALUES ('gpu-1', 'ready', '2026-01-01T00:00:00.000Z')`,
		`INSERT INTO model (id, backend, source, artifact, created_at)
		 VALUES ('llama-3', 'vllm', 'local', '/srv/w', '2026-01-01T00:00:00.000Z')`,
	} {
		if _, err := db.Exec(s); err != nil {
			t.Fatalf("seeding: %v", err)
		}
	}
}

func deploy(t *testing.T, db *sql.DB, id, state string) {
	t.Helper()
	last := sql.NullString{}
	if state == "failed" {
		last = sql.NullString{String: "crash-looped", Valid: true}
	}
	if _, err := db.Exec(`INSERT INTO deployment
		(id, model_id, node_name, backend, state, created_at, updated_at, last_error)
		VALUES (?, 'llama-3', 'gpu-1', 'vllm', ?, '2026-01-01T00:00:00.000Z', '2026-01-01T00:00:00.000Z', ?)`,
		id, state, last); err != nil {
		t.Fatalf("creating deployment %s: %v", id, err)
	}
}

// R2-10, the reason deployment_gpu is a table at all.
func TestTwoDeploymentsCannotClaimOneGPU(t *testing.T) {
	db := fleetDB(t)
	seed(t, db)
	deploy(t, db, "dep-a", "ready")
	deploy(t, db, "dep-b", "defined")

	if _, err := db.Exec(`INSERT INTO deployment_gpu VALUES ('dep-a', 'gpu-1', 0)`); err != nil {
		t.Fatalf("the first claim was refused: %v", err)
	}
	_, err := db.Exec(`INSERT INTO deployment_gpu VALUES ('dep-b', 'gpu-1', 0)`)
	if err == nil {
		t.Fatal("two deployments claimed GPU 0 on the same node")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "unique") {
		t.Errorf("refused, but not by the uniqueness rule: %v", err)
	}

	// A different GPU on the same node, and the same index on another node,
	// both have to work: an exclusivity rule that forbids too much is as broken
	// as one that forbids too little.
	if _, err := db.Exec(`INSERT INTO deployment_gpu VALUES ('dep-b', 'gpu-1', 1)`); err != nil {
		t.Errorf("a second GPU on the same node was refused: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO node (name, state, created_at)
		VALUES ('gpu-2', 'ready', '2026-01-01T00:00:00.000Z')`); err != nil {
		t.Fatal(err)
	}
	deploy(t, db, "dep-c", "ready")
	if _, err := db.Exec(`UPDATE deployment SET node_name = 'gpu-2' WHERE id = 'dep-c'`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO deployment_gpu VALUES ('dep-c', 'gpu-2', 0)`); err != nil {
		t.Errorf("GPU 0 on a different node was refused: %v", err)
	}
}

// Deleting the deployment is what frees its GPUs, and it is an explicit act.
func TestDeletingADeploymentReleasesItsGPUs(t *testing.T) {
	db := fleetDB(t)
	seed(t, db)
	deploy(t, db, "dep-a", "failed")
	if _, err := db.Exec(`INSERT INTO deployment_gpu VALUES ('dep-a', 'gpu-1', 0)`); err != nil {
		t.Fatal(err)
	}

	deploy(t, db, "dep-b", "defined")
	if _, err := db.Exec(`INSERT INTO deployment_gpu VALUES ('dep-b', 'gpu-1', 0)`); err == nil {
		t.Fatal("a failed deployment's GPU was silently reused")
	}

	if _, err := db.Exec(`DELETE FROM deployment WHERE id = 'dep-a'`); err != nil {
		t.Fatalf("deleting: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO deployment_gpu VALUES ('dep-b', 'gpu-1', 0)`); err != nil {
		t.Errorf("the GPU was still held after its deployment was deleted: %v", err)
	}
}

// Every state machine in docs/specs/00-overview.md §3 is a CHECK, so a typo in
// a handler cannot invent a state nothing else knows how to read.
func TestStateMachinesRefuseUnknownStates(t *testing.T) {
	db := fleetDB(t)
	seed(t, db)

	for _, tc := range []struct{ name, stmt string }{
		{"node", `INSERT INTO node (name, state, created_at) VALUES ('n', 'zombie', '2026-01-01T00:00:00.000Z')`},
		{"staging", `INSERT INTO staging (model_id, node_name, state, updated_at)
			VALUES ('llama-3', 'gpu-1', 'downloading', '2026-01-01T00:00:00.000Z')`},
		{"deployment", `INSERT INTO deployment (id, model_id, node_name, backend, state, created_at, updated_at)
			VALUES ('d', 'llama-3', 'gpu-1', 'vllm', 'running', '2026-01-01T00:00:00.000Z', '2026-01-01T00:00:00.000Z')`},
		{"model source", `INSERT INTO model (id, backend, source, artifact, created_at)
			VALUES ('m', 'vllm', 'ftp', '/w', '2026-01-01T00:00:00.000Z')`},
		{"limits subject", `INSERT INTO limits (subject_kind, subject_id, rpm) VALUES ('team', 't', 10)`},
		{"route strategy", `INSERT INTO route (name, strategy, created_at) VALUES ('r', 'random', '2026-01-01T00:00:00.000Z')`},
		{"reboot policy", `INSERT INTO node (name, state, reboot_policy, created_at)
			VALUES ('n2', 'ready', 'whenever', '2026-01-01T00:00:00.000Z')`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := db.Exec(tc.stmt); err == nil {
				t.Error("an unknown state was accepted")
			}
		})
	}
}

// Half a record of an approval is worse than none: docs/specs/02-enrollment.md
// §3 makes approval the step a leaked token cannot skip, and a node approved by
// nobody is exactly the gap it closes.
func TestAnApprovalHasBothAnAuthorAndATimeOrNeither(t *testing.T) {
	db := fleetDB(t)
	if _, err := db.Exec(`INSERT INTO node (name, state, approved_at, created_at)
		VALUES ('n', 'approved', '2026-01-01T00:00:00.000Z', '2026-01-01T00:00:00.000Z')`); err == nil {
		t.Error("a node was approved by nobody")
	}
	if _, err := db.Exec(`INSERT INTO node (name, state, approved_by, created_at)
		VALUES ('n', 'approved', 'usr_x', '2026-01-01T00:00:00.000Z')`); err == nil {
		t.Error("a node was approved at no time")
	}
}

// docs/specs/11-failure-modes.md §2: corrupt is terminal and needs an explicit
// restage, so it always says what went wrong.
func TestTerminalStatesCarryTheirReason(t *testing.T) {
	db := fleetDB(t)
	seed(t, db)

	if _, err := db.Exec(`INSERT INTO staging (model_id, node_name, state, updated_at)
		VALUES ('llama-3', 'gpu-1', 'corrupt', '2026-01-01T00:00:00.000Z')`); err == nil {
		t.Error("a staging row went corrupt with no error")
	}
	if _, err := db.Exec(`INSERT INTO deployment (id, model_id, node_name, backend, state, created_at, updated_at)
		VALUES ('d', 'llama-3', 'gpu-1', 'vllm', 'failed', '2026-01-01T00:00:00.000Z', '2026-01-01T00:00:00.000Z')`); err == nil {
		t.Error("a deployment failed with no error")
	}
	if _, err := db.Exec(`INSERT INTO node (name, state, created_at)
		VALUES ('n', 'departed', '2026-01-01T00:00:00.000Z')`); err == nil {
		t.Error("a node departed at no time")
	}
}

// docs/adr/0006-cui-boundary-and-fips.md makes "nodary records that a request
// happened, never what it said" structural. This is where structural is cashed
// out: the schema is closed, so there is nowhere to write content even by
// mistake.
func TestUsageHasNowhereToPutRequestContent(t *testing.T) {
	db := fleetDB(t)

	rows, err := db.Query(`SELECT name FROM pragma_table_info('usage')`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()

	got := map[string]bool{}
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatal(err)
		}
		got[name] = true
	}
	for _, forbidden := range []string{"prompt", "completion", "body", "content", "request_body", "response", "messages", "text"} {
		if got[forbidden] {
			t.Errorf("usage has a %q column: content has somewhere to go", forbidden)
		}
	}
	// And the columns that must be there, so this test cannot pass against an
	// empty table.
	for _, want := range []string{"prompt_tokens", "completion_tokens", "latency_ms", "status", "partial"} {
		if !got[want] {
			t.Errorf("usage has no %q column", want)
		}
	}
}

// Usage is telemetry, not evidence: no prev_hash and no hash, because 00 §3
// keeps the two chains apart deliberately.
func TestUsageIsNotAChain(t *testing.T) {
	db := fleetDB(t)
	for _, col := range []string{"prev_hash", "hash"} {
		var n int
		if err := db.QueryRow(
			`SELECT count(*) FROM pragma_table_info('usage') WHERE name = ?`, col).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n != 0 {
			t.Errorf("usage has a %s column; it is telemetry, not the audit chain", col)
		}
	}
}

// A deployment's port is published on loopback only, so it is an ordinary
// unprivileged port or it is nothing yet.
func TestDeploymentPortsAreUnprivileged(t *testing.T) {
	db := fleetDB(t)
	seed(t, db)
	for _, port := range []int{0, 80, 1024, 65536, 70000} {
		if _, err := db.Exec(`INSERT INTO deployment (id, model_id, node_name, backend, state, port, created_at, updated_at)
			VALUES ('d', 'llama-3', 'gpu-1', 'vllm', 'defined', ?, '2026-01-01T00:00:00.000Z', '2026-01-01T00:00:00.000Z')`,
			port); err == nil {
			t.Errorf("port %d was accepted", port)
			db.Exec(`DELETE FROM deployment WHERE id = 'd'`)
		}
	}
	if _, err := db.Exec(`INSERT INTO deployment (id, model_id, node_name, backend, state, port, created_at, updated_at)
		VALUES ('d', 'llama-3', 'gpu-1', 'vllm', 'defined', 8000, '2026-01-01T00:00:00.000Z', '2026-01-01T00:00:00.000Z')`); err != nil {
		t.Errorf("an ordinary port was refused: %v", err)
	}
}

// The foreign keys are enforced, not decorative. SQLite disables them per
// connection by default, so a schema full of REFERENCES on a connection that
// never enabled them documents an intention and enforces nothing.
func TestForeignKeysActuallyRefuse(t *testing.T) {
	db := fleetDB(t)
	seed(t, db)

	for _, tc := range []struct{ name, stmt string }{
		{"deployment on an unknown node", `INSERT INTO deployment (id, model_id, node_name, backend, state, created_at, updated_at)
			VALUES ('d', 'llama-3', 'nowhere', 'vllm', 'defined', '2026-01-01T00:00:00.000Z', '2026-01-01T00:00:00.000Z')`},
		{"deployment of an unknown model", `INSERT INTO deployment (id, model_id, node_name, backend, state, created_at, updated_at)
			VALUES ('d', 'nothing', 'gpu-1', 'vllm', 'defined', '2026-01-01T00:00:00.000Z', '2026-01-01T00:00:00.000Z')`},
		{"staging for an unknown model", `INSERT INTO staging (model_id, node_name, state, updated_at)
			VALUES ('nothing', 'gpu-1', 'staged', '2026-01-01T00:00:00.000Z')`},
		{"route member of an unknown route", `INSERT INTO route_member (route_name, deployment_id) VALUES ('nope', 'd')`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := db.Exec(tc.stmt); err == nil {
				t.Error("a dangling reference was accepted")
			}
		})
	}
}

// Removing a route takes its membership with it, so a deleted route cannot
// leave rows pointing at nothing.
func TestRouteMembershipFollowsItsRoute(t *testing.T) {
	db := fleetDB(t)
	seed(t, db)
	deploy(t, db, "dep-a", "ready")
	if _, err := db.Exec(`INSERT INTO route (name, created_at) VALUES ('chat', '2026-01-01T00:00:00.000Z')`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO route_member (route_name, deployment_id) VALUES ('chat', 'dep-a')`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`DELETE FROM route WHERE name = 'chat'`); err != nil {
		t.Fatalf("deleting the route: %v", err)
	}
	var n int
	if err := db.QueryRow(`SELECT count(*) FROM route_member`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Errorf("%d membership rows survived their route", n)
	}
}
