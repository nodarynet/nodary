package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nodarynet/nodary/internal/agent"
	"github.com/nodarynet/nodary/internal/config"
)

// TestOnlyDeploymentsThisHostCanReachAreServed is the honest half of a design
// question the specifications have not answered.
//
// docs/specs/03-agent.md publishes a deployment on `127.0.0.1` "so the
// container is reachable by the gateway" — true when the gateway is on the same
// machine, false when it is not — and docs/specs/00-overview.md §2 makes traffic
// to nodes agent-initiated only, so the control plane has no way to dial a
// node's loopback either.
//
// Until that is resolved, a route pointing at another node's deployment must be
// **skipped and named**. Rendering it anyway would produce a configuration whose
// api_base answers nothing, and the symptom would be a model that returns
// connection-refused from inside LiteLLM rather than anything naming the
// topology.
func TestOnlyDeploymentsThisHostCanReachAreServed(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "agent.toml"),
		agent.RenderConfig(agent.Config{Server: "https://127.0.0.1:8443", Name: "here"}), 0o644); err != nil {
		t.Fatal(err)
	}

	snap := &config.Snapshot{
		Deployments: []config.Deployment{
			{ID: "d-here", NodeName: "here", Port: 8001},
			{ID: "d-elsewhere", NodeName: "another-box", Port: 8002},
			{ID: "d-unplaced", NodeName: "here"}, // no port yet
		},
		Routes: []config.Route{
			{Name: "llama", Members: []config.RouteMember{{DeploymentID: "d-here"}}},
			{Name: "remote", Members: []config.RouteMember{{DeploymentID: "d-elsewhere"}}},
			{Name: "pending", Members: []config.RouteMember{{DeploymentID: "d-unplaced"}}},
		},
	}

	var out bytes.Buffer
	models, skipped := routeModels(env{stdout: &out, stderr: &out}, snap, dir)

	if len(models) != 1 || models[0].Name != "llama" {
		t.Fatalf("served %+v, want only the local route", models)
	}
	if models[0].APIBase != "http://127.0.0.1:8001/v1" {
		t.Errorf("api_base = %q", models[0].APIBase)
	}
	if skipped != 2 {
		t.Errorf("skipped %d, want 2", skipped)
	}
	// Named, not merely dropped: an operator has to be able to tell a route
	// that is not served from one that is.
	if !strings.Contains(out.String(), "another-box") {
		t.Errorf("the skipped node is not named: %s", out.String())
	}
	if !strings.Contains(out.String(), "no port yet") {
		t.Errorf("the unplaced deployment is not explained: %s", out.String())
	}
}

// TestAControlPlaneThatIsNotANodeServesEveryRoute keeps the filter from being a
// refusal in disguise.
//
// With no agent.toml this host cannot tell which deployments it could reach.
// Skipping all of them would leave an empty configuration and no explanation;
// rendering them lets the operator see the result and decide.
func TestAControlPlaneThatIsNotANodeServesEveryRoute(t *testing.T) {
	dir := t.TempDir() // no agent.toml
	snap := &config.Snapshot{
		Deployments: []config.Deployment{{ID: "d1", NodeName: "somewhere", Port: 9001}},
		Routes:      []config.Route{{Name: "m", Members: []config.RouteMember{{DeploymentID: "d1"}}}},
	}
	var out bytes.Buffer
	models, skipped := routeModels(env{stdout: &out, stderr: &out}, snap, dir)
	if len(models) != 1 || skipped != 0 {
		t.Errorf("served %d and skipped %d; want every route served", len(models), skipped)
	}
}

// TestGatewaySyncNeverMintsAMasterKey. Generating one here would write a
// configuration the gateway cannot authenticate against, and the failure —
// every request rejected upstream — would follow a sync that reported success.
func TestGatewaySyncNeverMintsAMasterKey(t *testing.T) {
	dir := t.TempDir()
	var out bytes.Buffer
	if _, code := readMasterKey(env{stdout: &out, stderr: &out}, dir); code == ExitOK {
		t.Error("a missing gateway.env was accepted")
	}
	if _, err := os.Stat(filepath.Join(dir, "gateway.env")); err == nil {
		t.Error("gateway sync created a master key")
	}

	if err := os.WriteFile(filepath.Join(dir, "gateway.env"),
		[]byte("# a comment\nNODARY_MASTER_KEY=sk-nodary-abc\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	key, code := readMasterKey(env{stdout: &out, stderr: &out}, dir)
	if code != ExitOK || key != "sk-nodary-abc" {
		t.Errorf("read %q (%d), want the key past the comment line", key, code)
	}
}

// TestSyncRestartsWhenTheRunningConfigurationIsStale is the failure that made
// `gateway sync` report success and change nothing that mattered.
//
// LiteLLM reads its configuration at startup, so what matters is whether the
// *running process* has the current one — and that comes apart from "the file
// changed" exactly when it counts. The file was written while LiteLLM was
// already up; a later sync found it correct, restarted nothing, and left the
// data plane serving an empty model list with a perfectly good file beside it.
//
// The digest of what the running process was started with is recorded in /run,
// which a boot clears — and a boot starts LiteLLM from the current file anyway,
// so a missing marker means "unknown" and restarts.
func TestSyncRestartsWhenTheRunningConfigurationIsStale(t *testing.T) {
	a := newAppliance(t)
	if code, stderr := stagedInstall(t, a); code != ExitOK {
		t.Fatalf("server install: exit %d, %s", code, stderr)
	}
	dir := a.dir
	marker := filepath.Join(dir, "run", "nodary", "litellm.applied")

	// A first sync knows nothing about the running process, so it acts and
	// records what it applied.
	if code, _, stderr := runWithStdin(t, "", "gateway", "sync",
		"--root", dir, "--config-dir", dir, "--db", a.db); code != ExitOK {
		t.Fatalf("gateway sync: exit %d, %s", code, stderr)
	}
	first, err := os.ReadFile(marker)
	if err != nil {
		t.Fatalf("no marker was recorded, so every later sync would restart: %v", err)
	}

	// A second sync, with nothing changed and the marker matching, does not
	// restart — an operator must be able to run this to check without dropping
	// live requests.
	if code, out, _ := runWithStdin(t, "", "gateway", "sync",
		"--root", dir, "--config-dir", dir, "--db", a.db); code != ExitOK {
		t.Fatalf("exit %d", code)
	} else if strings.Contains(out, "start:") {
		t.Errorf("an unchanged sync restarted the data plane:\n%s", out)
	}

	// The marker gone — a reboot, or a process nobody can vouch for — restarts
	// even though the file is unchanged. This is the case the bug lived in.
	if err := os.Remove(marker); err != nil {
		t.Fatal(err)
	}
	code, out, _ := runWithStdin(t, "", "gateway", "sync",
		"--root", dir, "--config-dir", dir, "--db", a.db)
	if code != ExitOK {
		t.Fatalf("exit %d", code)
	}
	if !strings.Contains(out, "start:") {
		t.Errorf("a sync with no record of the running configuration did not restart:\n%s", out)
	}
	if again, err := os.ReadFile(marker); err != nil || string(again) != string(first) {
		t.Errorf("the marker was not restored: %q, %v", again, err)
	}
}
