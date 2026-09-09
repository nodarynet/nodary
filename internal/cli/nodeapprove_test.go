package cli

import (
	"context"
	"database/sql"
	"strings"
	"testing"

	"github.com/nodarynet/nodary/internal/store"
)

// enrolled puts a node in the database the way enrolment would, so a test can
// approve one. A node cannot be created from configuration — it joins by
// enrolling — which is exactly why this is SQL and not a fixture verb.
func (a *appliance) enrolled(name string) {
	a.t.Helper()
	db, err := store.Open(context.Background(), a.db)
	if err != nil {
		a.t.Fatal(err)
	}
	defer db.Close()
	if err := db.Migrate(context.Background()); err != nil {
		a.t.Fatal(err)
	}
	if err := db.WriteTx(context.Background(), func(tx *sql.Tx) error {
		_, err := tx.ExecContext(context.Background(), `INSERT INTO node
			(name, state, arch, os, gpus_json, topology_json, offer_json, constraints_json,
			 reboot_policy, protocol, created_at)
			VALUES (?, 'pending', 'amd64', 'linux', '[]', '{}',
			        '{"gpus":[0],"max_deployments":1}', '{}', 'manual-console', 1,
			        '2026-09-08T00:00:00.000000000Z')`, name)
		return err
	}); err != nil {
		a.t.Fatal(err)
	}
}

// TestApprovingANodeFromTheConsole is the verb the install tells an operator to
// run.
//
// `node install` closes with "will receive no work until an administrator runs
// `nodary node approve <name>`", and that was a stub: approval existed only over
// the HTTP API, which on a single box means creating an administrator, minting
// a token and reaching for curl to move a machine already sitting there. Found
// the first time a model was deployed — everything applied, the node stayed
// pending, and the agent correctly had nothing to do.
func TestApprovingANodeFromTheConsole(t *testing.T) {
	a := newAppliance(t)
	a.addUser("alice", "admin")
	a.enrolled("fractal")

	code, _, stderr := a.run("node", "approve", "fractal")
	if code != ExitOK {
		t.Fatalf("approve: exit %d, %s", code, stderr)
	}
	if !strings.Contains(stderr, "pending -> approved") {
		t.Errorf("the transition is not reported: %s", stderr)
	}

	// It is a configuration change, and it has to record a revision. The
	// agent's long-poll compares against that sequence, so without one **an
	// approved node would not learn it had been approved** until something
	// unrelated moved the counter.
	code, revs, _ := a.run("config", "list")
	if code != ExitOK || strings.TrimSpace(revs) == "" {
		t.Errorf("approving recorded no revision, so the agent would not be told:\n%s", revs)
	}
	if code, out, _ := a.run("config", "show"); code != ExitOK ||
		!strings.Contains(out, `state = "approved"`) {
		t.Errorf("the node is not approved in the configuration:\n%s", out)
	}
}

// TestApprovingANodeThatDidNotEnrolIsRefused. A node joins by enrolling, so a
// name nobody has seen is a typo, and it deserves better than a constraint.
func TestApprovingANodeThatDidNotEnrolIsRefused(t *testing.T) {
	a := newAppliance(t)
	a.addUser("alice", "admin")

	code, _, stderr := a.run("node", "approve", "no-such-host")
	if code == ExitOK {
		t.Fatal("a node nobody enrolled was approved")
	}
	if !strings.Contains(stderr, "no-such-host") || !strings.Contains(stderr, "enrolling") {
		t.Errorf("the refusal does not say what is wrong:\n%s", stderr)
	}
}
