package cli

import (
	"context"
	"database/sql"
	"strings"
	"testing"
	"time"

	"github.com/nodarynet/nodary/internal/fleet"
	"github.com/nodarynet/nodary/internal/observed"
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

// --node narrows a roll; omitting it takes every replica of the model.
//
// It used to be required, on the reasoning that a restart is one node's act.
// That is true of cycling a unit and false of the thing dev/specs/03-agent.md
// §7 describes, which iterates over the replicas of a *model* — and the "never
// drops the last ready replica" guarantee only means anything across all of
// them.
func TestRestartWithNoNodeRollsEveryReplica(t *testing.T) {
	a := newAppliance(t)
	for _, n := range []string{"fractal", "second"} {
		a.enrolled(n)
		if code, _, stderr := a.run("node", "approve", n, "--yes",
			"--justify", "test fixture"); code != ExitOK {
			t.Fatalf("node approve %s: exit %d, %s", n, code, stderr)
		}
	}
	a.addUser("alice", "operator")
	a.registerModel(t, "acme/tiny", "fractal")
	a.registerModelOnGPU(t, "acme/tiny", "second", 0)
	a.readyDeployments(t)

	if code, _, stderr := a.run("model", "restart", "acme/tiny", "--yes",
		"--justify", "rolling the model"); code != ExitOK {
		t.Fatalf("restart with no --node: exit %d, %s", code, stderr)
	}
	if rows := a.restartRows(t); len(rows) != 2 {
		t.Errorf("deployment_restart = %v, want a row for each replica", rows)
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

// readyDeployments marks every deployment serving, the way a heartbeat would.
//
// Direct SQL because a heartbeat needs a node agent: what these tests are about
// is the roll's arithmetic, and the state it reads is what a reporting node
// would have written.
func (a *appliance) readyDeployments(t *testing.T) {
	t.Helper()
	db, err := store.Open(context.Background(), a.db)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.WriteTx(context.Background(), func(tx *sql.Tx) error {
		_, err := tx.ExecContext(context.Background(),
			`UPDATE deployment SET state = 'ready', health = 'healthy'`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

// twoReplicas is a model served from two hosts, both ready.
func (a *appliance) twoReplicas(t *testing.T) {
	t.Helper()
	for _, n := range []string{"fractal", "second"} {
		a.enrolled(n)
		if code, _, stderr := a.run("node", "approve", n, "--yes",
			"--justify", "test fixture"); code != ExitOK {
			t.Fatalf("node approve %s: exit %d, %s", n, code, stderr)
		}
	}
	a.registerModel(t, "acme/tiny", "fractal")
	a.registerModelOnGPU(t, "acme/tiny", "second", 0)
	a.readyDeployments(t)
}

// The guarantee of dev/specs/03-agent.md §7, asserted where it is enforced:
// the control plane offers one replica of a roll at a time, so no two nodes
// stop their copy at once.
func TestARollOffersOneReplicaAtATime(t *testing.T) {
	a := newAppliance(t)
	a.twoReplicas(t)

	if code, _, stderr := a.run("model", "restart", "acme/tiny", "--yes",
		"--justify", "rolling the model"); code != ExitOK {
		t.Fatalf("model restart: exit %d, %s", code, stderr)
	}
	if rows := a.restartRows(t); len(rows) != 2 {
		t.Fatalf("deployment_restart = %v, want a row for each replica", rows)
	}

	// Both rows exist; only the first replica's node is told about its own.
	first := a.offeredRestarts(t, "fractal")
	second := a.offeredRestarts(t, "second")
	if len(first) != 1 {
		t.Errorf("the first node was offered %v, want its one replica", first)
	}
	if len(second) != 0 {
		t.Errorf("the second node was offered %v while the first is still rolling", second)
	}

	// The node reports the restart done, which it does only once the
	// deployment is serving again. Now the roll moves on.
	a.ackRestart(t, "fractal")
	if got := a.offeredRestarts(t, "fractal"); len(got) != 0 {
		t.Errorf("the finished replica is still being offered a restart: %v", got)
	}
	if got := a.offeredRestarts(t, "second"); len(got) != 1 {
		t.Errorf("the second node was offered %v after the first came back, want its replica", got)
	}
}

// A replica that does not come back stops the roll where it stands, and the
// remainder keeps serving. Nothing implements that: the row of the replica that
// never became ready is never cleared, so nothing after it is ever offered.
func TestARollHaltsOnAReplicaThatDoesNotComeBack(t *testing.T) {
	a := newAppliance(t)
	a.twoReplicas(t)
	if code, _, stderr := a.run("model", "restart", "acme/tiny", "--yes",
		"--justify", "rolling the model"); code != ExitOK {
		t.Fatalf("model restart: exit %d, %s", code, stderr)
	}

	// The node cycles the unit and the deployment does not come back, so the
	// node never reports it done — which is the whole mechanism.
	a.setDeploymentState(t, "fractal", "failed")
	a.heartbeat(t, "fractal")

	if got := a.offeredRestarts(t, "fractal"); len(got) != 1 {
		t.Errorf("the stuck replica stopped being offered its restart: %v", got)
	}
	if got := a.offeredRestarts(t, "second"); len(got) != 0 {
		t.Errorf("the roll continued past a replica that did not come back: %v", got)
	}
}

// dev/specs/03-agent.md §7: fewer than two replicas requires --allow-downtime.
//
// Not paternalism — restarting a single-replica model is an ordinary thing to
// do. What it prevents is doing it without noticing: the same command is safe
// on a model with four replicas and an outage on a model with one, and which
// you have is not visible in what you typed.
func TestRestartingTheLastServingReplicaNeedsAllowDowntime(t *testing.T) {
	a := newAppliance(t)
	a.enrolled("fractal")
	if code, _, stderr := a.run("node", "approve", "fractal", "--yes",
		"--justify", "test fixture"); code != ExitOK {
		t.Fatalf("node approve: exit %d, %s", code, stderr)
	}
	a.registerModel(t, "acme/tiny", "fractal")
	a.readyDeployments(t)

	code, _, stderr := a.run("model", "restart", "acme/tiny", "--yes", "--justify", "cycling it")
	if code == ExitOK {
		t.Fatal("the last serving replica was restarted without --allow-downtime")
	}
	if !strings.Contains(stderr, "--allow-downtime") {
		t.Errorf("the refusal does not name the flag that accepts it: %q", stderr)
	}
	if rows := a.restartRows(t); len(rows) != 0 {
		t.Errorf("a refused roll queued %v", rows)
	}

	if code, _, stderr = a.run("model", "restart", "acme/tiny", "--allow-downtime",
		"--yes", "--justify", "accepting the gap"); code != ExitOK {
		t.Fatalf("with --allow-downtime: exit %d, %s", code, stderr)
	}
	if rows := a.restartRows(t); len(rows) != 1 {
		t.Errorf("deployment_restart = %v, want the one replica", rows)
	}
}

// A model that is already down is the one somebody most wants to restart, so
// the gate does not stand in front of it.
func TestAModelThatIsAlreadyDownCanBeRestarted(t *testing.T) {
	a := newAppliance(t)
	a.enrolled("fractal")
	if code, _, stderr := a.run("node", "approve", "fractal", "--yes",
		"--justify", "test fixture"); code != ExitOK {
		t.Fatalf("node approve: exit %d, %s", code, stderr)
	}
	a.registerModel(t, "acme/tiny", "fractal")
	a.setDeploymentState(t, "fractal", "failed")

	if code, _, stderr := a.run("model", "restart", "acme/tiny", "--yes",
		"--justify", "getting it back"); code != ExitOK {
		t.Fatalf("restarting a model with nothing serving: exit %d, %s", code, stderr)
	}
}

// offeredRestarts is what this node would actually be told to restart.
//
// fleet.OfferedRestarts rather than a query written here: the rule being tested
// is that rule, and a test that reimplemented it would pass while the endpoint
// offered something else.
func (a *appliance) offeredRestarts(t *testing.T, node string) []string {
	t.Helper()
	db, err := store.Open(context.Background(), a.db)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	got, err := fleet.OfferedRestarts(context.Background(), db.Read(), node)
	if err != nil {
		t.Fatal(err)
	}
	return got
}

// ackRestart reports that this node cycled every unit it was offered, the way
// a heartbeat carrying RestartDone does.
func (a *appliance) ackRestart(t *testing.T, node string) {
	t.Helper()
	a.report(t, node, observed.NodeReport{RestartDone: a.offeredRestarts(t, node)})
}

// heartbeat reports nothing new, which is what makes the control plane look
// again at whether a roll has finished.
func (a *appliance) heartbeat(t *testing.T, node string) {
	t.Helper()
	a.report(t, node, observed.NodeReport{})
}

func (a *appliance) report(t *testing.T, node string, r observed.NodeReport) {
	t.Helper()
	db, err := store.Open(context.Background(), a.db)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := observed.Heartbeat(context.Background(), db, node, r, time.Now()); err != nil {
		t.Fatal(err)
	}
}

func (a *appliance) setDeploymentState(t *testing.T, node, state string) {
	t.Helper()
	db, err := store.Open(context.Background(), a.db)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.WriteTx(context.Background(), func(tx *sql.Tx) error {
		_, err := tx.ExecContext(context.Background(),
			`UPDATE deployment SET state = ?, last_error = 'it did not come back'
			 WHERE node_name = ?`, state, node)
		return err
	}); err != nil {
		t.Fatal(err)
	}
}
