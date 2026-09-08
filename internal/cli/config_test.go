package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// R2-11: every configuration change writes a revision. The active policy
// profile is part of the snapshot, so applying one is a configuration change.
func TestApplyingAProfileRecordsARevision(t *testing.T) {
	a := newAppliance(t)
	a.addUser("alice", "admin")

	if code, _, stderr := a.run("config", "list"); code != ExitOK {
		t.Fatalf("config list on a fresh install: %d %s", code, stderr)
	}

	if code, _, stderr := a.run("policy", "apply", "regulated"); code != ExitOK {
		t.Fatalf("policy apply: %d %s", code, stderr)
	}
	_, stdout, _ := a.run("config", "list")
	if !strings.Contains(stdout, "\t") {
		t.Fatalf("no revision was recorded:\n%s", stdout)
	}

	// And the snapshot at that revision carries the profile that was applied.
	_, shown, _ := a.run("config", "show", "--rev", "1", "--format", "json")
	var snap struct {
		Policy *struct{ Name string } `json:"policy"`
	}
	if err := json.Unmarshal([]byte(shown), &snap); err != nil {
		t.Fatalf("config show is not JSON: %v\n%s", err, shown)
	}
	if snap.Policy == nil || snap.Policy.Name != "regulated" {
		t.Errorf("revision 1 does not record the applied profile: %s", shown)
	}
}

// R2-11: the chain verifies the same way the audit chain does, and altering a
// revision is caught.
func TestTheRevisionChainVerifiesAndCatchesTampering(t *testing.T) {
	a := newAppliance(t)
	a.addUser("alice", "admin")
	if code, _, stderr := a.run("policy", "apply", "regulated"); code != ExitOK {
		t.Fatalf("policy apply: %d %s", code, stderr)
	}
	if code, _, stderr := a.run("policy", "apply", "default",
		"--justify", "reverting the pilot posture"); code != ExitOK {
		t.Fatalf("policy apply: %d %s", code, stderr)
	}

	code, stdout, stderr := a.run("config", "verify")
	if code != ExitOK {
		t.Fatalf("verify: %d %s", code, stderr)
	}
	if !strings.Contains(stdout, "2 revisions verified") {
		t.Errorf("verify did not count both revisions:\n%s", stdout)
	}

	// Rewrite a snapshot in place, the way somebody with the database file
	// could, and the chain must name the revision.
	a.execSQL(`UPDATE revision SET snapshot_json = replace(snapshot_json, '"regulated"', '"tampered"') WHERE seq = 1`)
	code, stdout, _ = a.run("config", "verify")
	if code == ExitOK {
		t.Errorf("a tampered revision verified:\n%s", stdout)
	}
	if !strings.Contains(stdout, "revision 1") {
		t.Errorf("the break does not name the revision:\n%s", stdout)
	}
}

// R2-12: export emits what apply reads back, and the round trip is a no-op.
func TestExportApplyRoundTripsToNoChange(t *testing.T) {
	a := newAppliance(t)
	a.addUser("alice", "admin")

	out := filepath.Join(a.dir, "nodary.toml")
	if code, _, stderr := a.run("config", "export", "--out", out); code != ExitOK {
		t.Fatalf("export: %d %s", code, stderr)
	}
	body, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "# nodary configuration") {
		t.Errorf("the export has no header explaining what it is:\n%s", body)
	}

	// Applying what was exported must change nothing. An applier that reported
	// changes here would make every DR restore look like a configuration edit.
	code, stdout, stderr := a.run("config", "apply", "-f", out)
	if code != ExitOK {
		t.Fatalf("apply: %d %s", code, stderr)
	}
	if !strings.Contains(stdout, "no change") {
		t.Errorf("re-applying an export reported changes:\n%s", stdout)
	}
}

// R2-12 and R2-13: a configuration creates objects, a rollback puts them back,
// and the rollback is itself a revision rather than a rewrite of history.
func TestRollbackRestoresAndIsItselfARevision(t *testing.T) {
	a := newAppliance(t)
	a.addUser("alice", "admin")

	one := filepath.Join(a.dir, "one.toml")
	write(t, one, `
[[model]]
id = "llama-3"
backend = "vllm"
source = "local"
artifact = "/srv/weights/llama-3"

[[route]]
name = "chat"
`)
	if code, stdout, stderr := a.run("config", "apply", "-f", one); code != ExitOK {
		t.Fatalf("apply: %d %s\n%s", code, stderr, stdout)
	}

	two := filepath.Join(a.dir, "two.toml")
	write(t, two, `
[[model]]
id = "llama-3"
backend = "vllm"
source = "local"
artifact = "/srv/weights/llama-3"

[[model]]
id = "mistral"
backend = "vllm"
source = "local"
artifact = "/srv/weights/mistral"

[[route]]
name = "chat"
`)
	if code, _, stderr := a.run("config", "apply", "-f", two); code != ExitOK {
		t.Fatalf("apply: %d %s", code, stderr)
	}

	// Two models now. Roll back to the revision that had one, pruning so the
	// second is actually removed.
	_, shown, _ := a.run("config", "show", "--format", "json")
	if !strings.Contains(shown, "mistral") {
		t.Fatalf("the second model was not applied:\n%s", shown)
	}

	if code, _, stderr := a.run("config", "rollback", "1", "--prune",
		"--justify", "backing out the mistral rollout"); code != ExitOK {
		t.Fatalf("rollback: %d %s", code, stderr)
	}
	_, shown, _ = a.run("config", "show", "--format", "json")
	if strings.Contains(shown, "mistral") {
		t.Errorf("the rollback did not remove the model:\n%s", shown)
	}
	if !strings.Contains(shown, "llama-3") {
		t.Errorf("the rollback removed too much:\n%s", shown)
	}

	// History is append-only: the rollback is a new revision, not an erasure of
	// the one it undid.
	_, list, _ := a.run("config", "list")
	lines := strings.Count(strings.TrimSpace(list), "\n") + 1
	if lines != 3 {
		t.Errorf("expected three revisions after two applies and a rollback, got %d:\n%s", lines, list)
	}
	if code, out, _ := a.run("config", "verify"); code != ExitOK {
		t.Errorf("the chain broke across a rollback:\n%s", out)
	}
}

// Objects absent from a configuration are left alone unless --prune. The
// alternative makes `config apply -f partial.toml` a fleet-wide delete.
func TestApplyLeavesOrphansAloneWithoutPrune(t *testing.T) {
	a := newAppliance(t)
	a.addUser("alice", "admin")

	full := filepath.Join(a.dir, "full.toml")
	write(t, full, `
[[model]]
id = "llama-3"
backend = "vllm"
source = "local"
artifact = "/srv/w/a"

[[model]]
id = "mistral"
backend = "vllm"
source = "local"
artifact = "/srv/w/b"
`)
	if code, _, stderr := a.run("config", "apply", "-f", full); code != ExitOK {
		t.Fatalf("apply: %d %s", code, stderr)
	}

	partial := filepath.Join(a.dir, "partial.toml")
	write(t, partial, `
[[model]]
id = "llama-3"
backend = "vllm"
source = "local"
artifact = "/srv/w/a"
`)
	code, _, stderr := a.run("config", "apply", "-f", partial)
	if code != ExitOK {
		t.Fatalf("apply: %d %s", code, stderr)
	}
	if !strings.Contains(stderr, "left in place") || !strings.Contains(stderr, "mistral") {
		t.Errorf("the orphan was not reported:\n%s", stderr)
	}
	if !strings.Contains(stderr, "--prune") {
		t.Errorf("the report does not say how to delete it:\n%s", stderr)
	}
	if _, shown, _ := a.run("config", "show", "--format", "json"); !strings.Contains(shown, "mistral") {
		t.Error("a partial configuration deleted a model nobody asked to delete")
	}
}

// A node joins by enrolling. A configuration file that could conjure one would
// let a paste into the wrong terminal add a machine to the fleet.
func TestApplyRefusesToInventANode(t *testing.T) {
	a := newAppliance(t)
	a.addUser("alice", "admin")

	f := filepath.Join(a.dir, "node.toml")
	write(t, f, `
[[node]]
name = "gpu-99"
state = "approved"
reboot_policy = "manual-console"
`)
	code, _, stderr := a.run("config", "apply", "-f", f)
	if code == ExitOK {
		t.Fatal("a configuration file created a node")
	}
	if !strings.Contains(stderr, "enrolling") {
		t.Errorf("the refusal does not say how a node joins:\n%s", stderr)
	}
}

// A configuration is reviewed by reading it, so a key nobody applies is refused
// rather than ignored — the same rule a policy profile follows.
func TestApplyRefusesAnUnknownKey(t *testing.T) {
	a := newAppliance(t)
	a.addUser("alice", "admin")

	f := filepath.Join(a.dir, "typo.toml")
	write(t, f, `
[[model]]
id = "llama-3"
backend = "vllm"
source = "local"
artifact = "/srv/w"
licence = "apache-2.0"
`)
	code, _, stderr := a.run("config", "apply", "-f", f)
	if code == ExitOK {
		t.Fatal("a configuration with an unknown key was applied")
	}
	if !strings.Contains(stderr, "licence") {
		t.Errorf("the refusal does not name the key:\n%s", stderr)
	}
}

// A snapshot carries desired state only. A revision that moved because a node
// checked in would make `config diff` unreadable.
func TestASnapshotCarriesNoObservedState(t *testing.T) {
	a := newAppliance(t)
	a.addUser("alice", "admin")
	a.execSQL(`INSERT INTO node (name, state, created_at) VALUES ('gpu-1', 'ready', '2026-01-01T00:00:00.000Z')`)

	_, before, _ := a.run("config", "show", "--format", "json")

	// Everything an agent would report.
	a.execSQL(`UPDATE node SET last_seen = '2026-09-07T00:00:00.000Z', agent_version = '0.2.0',
		gpus_json = '[{"index":0}]', driver_version = '610.88', protocol = 3 WHERE name = 'gpu-1'`)

	_, after, _ := a.run("config", "show", "--format", "json")
	if before != after {
		t.Errorf("observed state reached the snapshot:\nbefore %s\nafter  %s", before, after)
	}
	for _, forbidden := range []string{"last_seen", "agent_version", "driver_version", "protocol", "610.88"} {
		if strings.Contains(after, forbidden) {
			t.Errorf("the snapshot carries %q", forbidden)
		}
	}
}

func write(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

// docs/specs/08-data-model.md §2 calls the export "canonical, for provisioning
// and DR". That is a claim about a *different machine*: exporting and applying
// to the same database proves much less, because everything is already there.
//
// So this restores onto a fresh database and exports again, and the two files
// have to be identical.
func TestAnExportRestoresOntoAFreshDatabase(t *testing.T) {
	origin := newAppliance(t)
	origin.addUser("alice", "admin")

	site := filepath.Join(origin.dir, "site.toml")
	write(t, site, `
[[model]]
id = "llama-3-70b"
backend = "vllm"
source = "local"
artifact = "/srv/weights/llama-3-70b"
origin_country = "US"

[[model]]
id = "mistral"
backend = "vllm"
source = "local"
artifact = "/srv/weights/mistral"

[[route]]
name = "chat"

[[limits]]
subject_kind = "role"
subject_id = "user"
rpm = 60
daily_tokens = 500000
`)
	if code, _, stderr := origin.run("config", "apply", "-f", site); code != ExitOK {
		t.Fatalf("apply: %d %s", code, stderr)
	}

	exported := filepath.Join(origin.dir, "dr.toml")
	if code, _, stderr := origin.run("config", "export", "--out", exported); code != ExitOK {
		t.Fatalf("export: %d %s", code, stderr)
	}

	// A different machine: its own database, its own key, nothing carried over
	// but the file.
	rebuilt := newAppliance(t)
	rebuilt.addUser("alice", "admin")
	if code, _, stderr := rebuilt.run("config", "apply", "-f", exported); code != ExitOK {
		t.Fatalf("restoring: %d %s", code, stderr)
	}

	restored := filepath.Join(rebuilt.dir, "after.toml")
	if code, _, stderr := rebuilt.run("config", "export", "--out", restored); code != ExitOK {
		t.Fatalf("re-export: %d %s", code, stderr)
	}

	before, err := os.ReadFile(exported)
	if err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(restored)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Errorf("a restored configuration does not re-export identically\n--- exported ---\n%s\n--- restored ---\n%s",
			before, after)
	}
	// And it must not be empty, or this passes on two blank files.
	if !strings.Contains(string(after), "llama-3-70b") {
		t.Errorf("the restored configuration is missing its models:\n%s", after)
	}
}

// A configuration naming a deployment nothing defines is an operator's typo,
// and it deserves an answer better than the constraint's own text.
func TestADanglingReferenceIsNamedNotReportedAsAConstraint(t *testing.T) {
	a := newAppliance(t)
	a.addUser("alice", "admin")

	f := filepath.Join(a.dir, "dangling.toml")
	write(t, f, `
[[route]]
name = "chat"
  [[route.member]]
  deployment_id = "dep-1"
`)
	code, _, stderr := a.run("config", "apply", "-f", f)
	if code == ExitOK {
		t.Fatal("a route pointing at nothing was applied")
	}
	// "this control plane does not have", not "does not exist in this
	// configuration": a partial document is the ordinary case and is meant to
	// reference objects it does not restate, so the message has to point at the
	// fleet rather than send the operator back to their file.
	if !strings.Contains(stderr, "dep-1") || !strings.Contains(stderr, "does not have") {
		t.Errorf("the refusal does not name what is missing:\n%s", stderr)
	}
	if strings.Contains(stderr, "FOREIGN KEY") {
		t.Errorf("the operator was handed the constraint's own text:\n%s", stderr)
	}
}
