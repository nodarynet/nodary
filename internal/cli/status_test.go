package cli

import (
	"context"
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nodarynet/nodary/internal/fleet"
	"github.com/nodarynet/nodary/internal/install"
	"github.com/nodarynet/nodary/internal/store"
)

// R2-38: the question `nodary status` answers is "is this appliance working",
// and before it the operator had to know which roles the host carries, run
// `server status` and `agent status` for the halves, and then reach for
// systemctl for the part neither of them says — which is the part they asked
// about.
func TestStatusNamesEveryUnitOfEveryRoleThisHostHas(t *testing.T) {
	root := installedTree(t, "server", "node")

	code, stdout, stderr := run(t, "status", "--root", root, "--format", "json")
	if code != ExitOK {
		t.Fatalf("code = %d: %s %s", code, stdout, stderr)
	}
	var doc struct {
		Roles []string             `json:"roles"`
		Units []install.UnitStatus `json:"units"`
	}
	if err := json.Unmarshal([]byte(stdout), &doc); err != nil {
		t.Fatalf("%v: %s", err, stdout)
	}
	if strings.Join(doc.Roles, ",") != "server,node" {
		t.Errorf("roles = %v, want both: a --with-node box is one host with two roles", doc.Roles)
	}

	var names []string
	for _, u := range doc.Units {
		names = append(names, u.Unit)
	}
	for _, want := range []string{"nodary-server.service", "nodary-gateway.service",
		"nodary-litellm.service", "nodary-agent.service", "nodary-prune.timer", "containerd.service"} {
		if !strings.Contains(strings.Join(names, " "), want) {
			t.Errorf("units = %v, missing %s", names, want)
		}
	}
	// Both roles start containerd; a host that is both must not be told it has
	// two of them.
	containerd := 0
	for _, n := range names {
		if n == "containerd.service" {
			containerd++
		}
	}
	if containerd != 1 {
		t.Errorf("containerd.service listed %d times, want once", containerd)
	}
}

// Nothing installed is a refusal that names what it looked for, not an empty
// table that reads as "installed and idle".
func TestStatusOnAHostWithNothingInstalledSaysSo(t *testing.T) {
	code, _, stderr := run(t, "status", "--root", t.TempDir())
	if code != ExitFailure {
		t.Errorf("code = %d, want 1", code)
	}
	for _, want := range []string{"server.toml", "agent.toml", "nodary install"} {
		if !strings.Contains(stderr, want) {
			t.Errorf("stderr does not name %s: %s", want, stderr)
		}
	}
}

// `systemctl is-active`'s contract, because it is the one an operator scripting
// this already knows: zero when what is installed is running, nonzero when it
// is not. The two exceptions are what makes it usable — a unit that was never
// installed is not a stopped service, and a Type=oneshot triggered by a timer
// is inactive between runs by design.
func TestAStoppedApplianceIsNotASuccessfulStatus(t *testing.T) {
	for _, c := range []struct {
		name  string
		units []install.UnitStatus
		want  int
	}{
		{"everything up", []install.UnitStatus{
			{Unit: "nodary-server.service", Active: "active", Enabled: "enabled"}}, ExitOK},
		{"one stopped", []install.UnitStatus{
			{Unit: "nodary-server.service", Active: "active", Enabled: "enabled"},
			{Unit: "nodary-gateway.service", Active: "inactive", Enabled: "enabled"}}, ExitFailure},
		{"one failed", []install.UnitStatus{
			{Unit: "nodary-server.service", Active: "failed", Enabled: "enabled"}}, ExitFailure},
		// A control plane has no nodary-agent.service, and systemd answers
		// "inactive" with no unit file for it. That is not a failure of
		// anything.
		{"never installed", []install.UnitStatus{
			{Unit: "nodary-server.service", Active: "active", Enabled: "enabled"},
			{Unit: "nodary-agent.service", Active: "inactive", Enabled: ""}}, ExitOK},
		{"the oneshots between runs", []install.UnitStatus{
			{Unit: "nodary-prune.timer", Active: "active", Enabled: "enabled"},
			{Unit: "nodary-prune.service", Active: "inactive", Enabled: "static"},
			{Unit: "nodary-gateway-sync.timer", Active: "active", Enabled: "enabled"},
			{Unit: "nodary-gateway-sync.service", Active: "inactive", Enabled: "static"}}, ExitOK},
		// A stopped timer is not: a data-plane sync that has quietly stopped
		// happening is a fleet whose routes freeze at whatever they were.
		{"a stopped timer", []install.UnitStatus{
			{Unit: "nodary-gateway-sync.timer", Active: "inactive", Enabled: "enabled"}}, ExitFailure},
	} {
		if got := statusExit(c.units); got != c.want {
			t.Errorf("%s: exit %d, want %d", c.name, got, c.want)
		}
	}
}

// `nodary restart` is not a synonym for one systemctl call — what it knows is
// the set and the order. containerd is deliberately not in it: restarting a
// shared runtime stops every container on the machine, including every
// deployment, to fix something that is almost never containerd.
func TestRestartBouncesWhatNodaryOwnsAndLeavesContainerdAlone(t *testing.T) {
	root := installedTree(t, "server", "node")

	code, stdout, stderr := run(t, "restart", "--root", root)
	if code != ExitOK {
		t.Fatalf("code = %d: %s %s", code, stdout, stderr)
	}
	if strings.Contains(stdout, "containerd") {
		t.Errorf("restart touched containerd:\n%s", stdout)
	}
	// Data plane before the API that proxies to it, agent last.
	want := []string{"nodary-litellm.service", "nodary-server.service",
		"nodary-gateway.service", "nodary-agent.service"}
	at := -1
	for _, u := range want {
		i := strings.Index(stdout, u)
		if i < 0 {
			t.Fatalf("restart did not name %s:\n%s", u, stdout)
		}
		if i < at {
			t.Errorf("%s came out of dependency order:\n%s", u, stdout)
		}
		at = i
	}
}

// A control plane has no agent to bounce, and asking systemd to restart a unit
// that was never installed reports a failure for something that is not wrong.
func TestRestartOnAControlPlaneLeavesTheAgentOut(t *testing.T) {
	root := installedTree(t, "server")

	code, stdout, _ := run(t, "restart", "--root", root)
	if code != ExitOK {
		t.Fatalf("code = %d: %s", code, stdout)
	}
	if strings.Contains(stdout, "nodary-agent.service") {
		t.Errorf("restart named an agent this host does not run:\n%s", stdout)
	}
}

func TestRestartOnAHostWithNothingInstalledSaysSo(t *testing.T) {
	code, _, stderr := run(t, "restart", "--root", t.TempDir())
	if code != ExitFailure {
		t.Errorf("code = %d, want 1", code)
	}
	if !strings.Contains(stderr, "nothing installed here") {
		t.Errorf("stderr = %q", stderr)
	}
}

// A half-finished uninstall leaves the binaries and no configuration, and both
// verbs have to work on it — that is when somebody is most likely to run them.
func TestStatusStillReportsAfterTheConfigurationIsGone(t *testing.T) {
	root := installedTree(t, "server")
	if err := os.Remove(filepath.Join(root, "etc", "nodary", "server.toml")); err != nil {
		t.Fatal(err)
	}

	code, stdout, stderr := run(t, "status", "--root", root, "--format", "json")
	if code != ExitOK {
		t.Fatalf("code = %d: %s %s", code, stdout, stderr)
	}
	if !strings.Contains(stdout, "nodary-server.service") {
		t.Errorf("status found nothing on a host that still has /opt/nodary:\n%s", stdout)
	}
}

// R4-25, dev/specs/11-failure-modes.md §2: "GPU falls off the bus — agent
// reports; affected deployments marked `failed`; **node flagged**."
//
// Flagged by derivation rather than by a stored column: the offer is what the
// node declared and `gpus` is what it measured on its last heartbeat, so the
// two disagreeing *is* the fact. A flag column would be one more thing to
// clear, and the clearing is what gets forgotten.
func TestNodeShowFlagsACardTheDriverStoppedReporting(t *testing.T) {
	a := newAppliance(t)
	a.enrolled("fractal")
	setNodeGPUs(t, a.db, "fractal", `[{"index":0,"name":"A","memory_mib":1}]`,
		`{"gpus":[{"index":0},{"index":1}],"max_deployments":2}`)

	code, stdout, stderr := a.run("node", "show", "fractal")
	if code != ExitOK {
		t.Fatalf("code = %d: %s", code, stderr)
	}
	if !strings.Contains(stdout, "gpu missing") {
		t.Errorf("node show does not flag the missing card:\n%s", stdout)
	}
	for _, want := range []string{"nvidia-smi", "nothing is rebooted"} {
		if !strings.Contains(stderr, want) {
			t.Errorf("stderr does not say %q: %s", want, stderr)
		}
	}
}

// A node that has never checked in has not lost a card — it has not reported
// one. Flagging that would put a hardware alarm on every node between
// enrollment and its first heartbeat.
func TestANodeThatHasReportedNoInventoryIsNotFlagged(t *testing.T) {
	a := newAppliance(t)
	a.enrolled("fractal") // gpus_json is '[]', offer names GPU 0

	_, stdout, stderr := a.run("node", "show", "fractal")
	if strings.Contains(stdout, "gpu missing") || strings.Contains(stderr, "no longer reports") {
		t.Errorf("a node that has never reported an inventory was flagged:\n%s\n%s", stdout, stderr)
	}
}

func setNodeGPUs(t *testing.T, dbPath, node, gpus, offer string) {
	t.Helper()
	db, err := store.Open(context.Background(), dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.WriteTx(context.Background(), func(tx *sql.Tx) error {
		_, err := tx.ExecContext(context.Background(),
			`UPDATE node SET gpus_json = ?, offer_json = ? WHERE name = ?`, gpus, offer, node)
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

// R4-11: an incompatible node keeps heartbeating, so it is *not* stale — and
// from a listing that only reports staleness it looks perfectly healthy while
// nothing it is told to do is happening. `node list` has to say so, and say
// what to run.
func TestNodeListFlagsAnAgentOutsideTheProtocolRange(t *testing.T) {
	a := newAppliance(t)
	a.enrolled("fractal")
	setNodeProtocol(t, a.db, "fractal", fleet.ProtocolMax+1)

	code, _, stderr := a.run("node", "list")
	if code != ExitOK {
		t.Fatalf("code = %d: %s", code, stderr)
	}
	for _, want := range []string{"fractal", "protocol", "nodary upgrade"} {
		if !strings.Contains(stderr, want) {
			t.Errorf("node list does not say %q:\n%s", want, stderr)
		}
	}

	_, stdout, _ := a.run("node", "show", "fractal")
	if !strings.Contains(stdout, "INCOMPATIBLE") {
		t.Errorf("node show does not flag it:\n%s", stdout)
	}
}

// A node speaking a protocol this build accepts is not flagged, and neither is
// one that has never said which it speaks — that is an agent old enough that an
// operator most needs to keep seeing it in order to upgrade it.
func TestASupportedAgentIsNotFlagged(t *testing.T) {
	a := newAppliance(t)
	a.enrolled("fractal")
	for _, p := range []int{0, fleet.Protocol} {
		setNodeProtocol(t, a.db, "fractal", p)
		_, stdout, stderr := a.run("node", "list")
		if strings.Contains(stderr, "accepts") || strings.Contains(stdout, "INCOMPATIBLE") {
			t.Errorf("protocol %d was flagged:\n%s\n%s", p, stdout, stderr)
		}
	}
}

func setNodeProtocol(t *testing.T, dbPath, node string, protocol int) {
	t.Helper()
	db, err := store.Open(context.Background(), dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.WriteTx(context.Background(), func(tx *sql.Tx) error {
		_, err := tx.ExecContext(context.Background(),
			// Approved and just-seen, because that is the node this is about:
			// one the fleet expects to be working. A pending node is reported
			// as pending first, which is the more actionable line.
			`UPDATE node SET protocol = ?, agent_version = '0.0.1', state = 'approved',
			                 last_seen = strftime('%Y-%m-%dT%H:%M:%f000Z','now')
			 WHERE name = ?`, protocol, node)
		return err
	}); err != nil {
		t.Fatal(err)
	}
}
