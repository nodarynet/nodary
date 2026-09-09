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
artifact = "hf-cache"

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
artifact = "hf-cache"

[[model]]
id = "mistral"
backend = "vllm"
source = "local"
artifact = "hf-cache"

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
artifact = "hf-cache"

[[model]]
id = "mistral"
backend = "vllm"
source = "local"
artifact = "hf-cache"
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
artifact = "hf-cache"
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
artifact = "hf-cache"
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
artifact = "hf-cache"
origin_country = "US"

[[model]]
id = "mistral"
backend = "vllm"
source = "local"
artifact = "hf-cache"

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

// TestAPartialApplyDoesNotReportDeletionsItDidNotMake is the most alarming
// thing this verb could say untruthfully.
//
// `--prune` is off by default so that `config apply -f fragment.toml` adds
// rather than replaces — but the change list was the *whole* diff, so every
// partial apply printed `- node <the machine you are standing on>` beside the
// things it really did. Found on a first real deployment, where the line read
// as though applying a model had removed the only GPU host.
//
// Objects the document does not mention are Orphans and are reported as left
// in place. The change list is what was done.
func TestAPartialApplyDoesNotReportDeletionsItDidNotMake(t *testing.T) {
	a := newAppliance(t)
	a.addUser("alice", "admin")

	first := filepath.Join(a.dir, "first.toml")
	write(t, first, `
[[model]]
id       = "kept/model"
backend  = "vllm"
source   = "local"
artifact = "hf-cache"
`)
	if code, _, stderr := a.run("config", "apply", "-f", first); code != ExitOK {
		t.Fatalf("apply: exit %d, %s", code, stderr)
	}

	// A second, unrelated fragment. It says nothing about the first model, and
	// with prune off nothing about it changes.
	second := filepath.Join(a.dir, "second.toml")
	write(t, second, `
[[model]]
id       = "added/model"
backend  = "vllm"
source   = "local"
artifact = "hf-cache"
`)
	code, stdout, stderr := a.run("config", "apply", "-f", second)
	if code != ExitOK {
		t.Fatalf("apply: exit %d, %s", code, stderr)
	}
	if strings.Contains(stdout, "- model kept/model") {
		t.Errorf("the apply reported deleting a model it left in place:\n%s", stdout)
	}
	if !strings.Contains(stdout, "+ model added/model") {
		t.Errorf("the apply did not report what it did:\n%s", stdout)
	}
	// Said, not silent: left in place is a fact the operator wants, and it goes
	// to stderr as an orphan rather than into the change list as a deletion.
	if !strings.Contains(stderr, "kept/model") {
		t.Errorf("the untouched model is not reported as left in place:\n%s", stderr)
	}

	// And it really is still there.
	if code, out, _ := a.run("config", "show"); code != ExitOK || !strings.Contains(out, "kept/model") {
		t.Errorf("the model the apply did not mention is gone:\n%s", out)
	}
}

// TestThePreviewDoesNotShowDeletionsItWillNotMake is the same bug one layer
// earlier: the fix above filtered the post-apply *report*, but the
// confirmation an operator actually reads and approves — what "apply? [y/N]"
// shows, and what intent_hash is computed over — called config.Changes
// directly and was never touched. Every partial `config apply` or `model
// register` said, in the thing being approved, that it would delete every
// existing object the document didn't happen to mention. --dry-run renders
// the identical preview non-interactively, which is what makes this
// checkable without a TTY.
func TestThePreviewDoesNotShowDeletionsItWillNotMake(t *testing.T) {
	a := newAppliance(t)
	a.addUser("alice", "admin")
	a.enrolled("fractal")

	first := filepath.Join(a.dir, "first.toml")
	write(t, first, `
[[model]]
id       = "kept/model"
backend  = "vllm"
source   = "local"
artifact = "hf-cache"
`)
	if code, _, stderr := a.run("config", "apply", "-f", first); code != ExitOK {
		t.Fatalf("apply: exit %d, %s", code, stderr)
	}

	second := filepath.Join(a.dir, "second.toml")
	write(t, second, `
[[model]]
id       = "added/model"
backend  = "vllm"
source   = "local"
artifact = "hf-cache"
`)
	code, stdout, stderr := a.run("config", "apply", "-f", second, "--dry-run")
	if code != ExitOK {
		t.Fatalf("dry-run apply: exit %d, %s", code, stderr)
	}
	if strings.Contains(stdout, "- model kept/model") || strings.Contains(stdout, "- node fractal") {
		t.Errorf("the preview says it will delete objects a partial apply leaves in place:\n%s", stdout)
	}
	if !strings.Contains(stdout, "+ model added/model") {
		t.Errorf("the preview does not show what it will actually do:\n%s", stdout)
	}
}

// TestAModelWhoseArtifactItsBackendCannotReadIsRefused is docs/specs/05-catalog.md
// §1's "must match the backend's weights_layout", enforced where it can still
// be corrected.
//
// Without it the apply succeeds and the failure lands on a node, as a model
// reported `corrupt` with "unknown weights layout" — a message naming neither
// the field nor the document that set it, on a machine that is not the one the
// operator is typing on. A catalog entry that can never stage is not a catalog
// entry.
func TestAModelWhoseArtifactItsBackendCannotReadIsRefused(t *testing.T) {
	a := newAppliance(t)
	a.addUser("alice", "admin")

	f := filepath.Join(a.dir, "bad.toml")
	write(t, f, `
[[model]]
id       = "some/model"
backend  = "vllm"
source   = "local"
artifact = "weights"
`)
	code, _, stderr := a.run("config", "apply", "-f", f)
	if code == ExitOK {
		t.Fatal("a model its backend cannot read was applied")
	}
	for _, want := range []string{"some/model", "weights", "hf-cache", "vllm"} {
		if !strings.Contains(stderr, want) {
			t.Errorf("the refusal does not name %q:\n%s", want, stderr)
		}
	}

	// The right one applies, so this is a check and not a wall.
	write(t, f, `
[[model]]
id       = "some/model"
backend  = "vllm"
source   = "local"
artifact = "hf-cache"
`)
	if code, _, stderr := a.run("config", "apply", "-f", f); code != ExitOK {
		t.Errorf("a matching artifact was refused: %s", stderr)
	}
}

// A route change has to reach the data plane, and against a database the
// operator named it must not: that is not the installed control plane.
func TestARouteChangeAgainstANamedDatabaseOnlyPrintsTheSync(t *testing.T) {
	if !movesTheDataPlane([]string{"+ route tiny"}) {
		t.Error("a new route does not move the data plane")
	}
	// A deployment moving port or node re-renders every api_base without any
	// route line appearing at all.
	if !movesTheDataPlane([]string{"~ deployment tiny-fractal"}) {
		t.Error("a changed deployment does not move the data plane")
	}
	if movesTheDataPlane([]string{"+ grant alice/tiny", "~ policy a -> b"}) {
		t.Error("a grant restarted the data plane for nothing")
	}
}

// TestAPartialApplyDoesNotRevokeEveryGrant.
//
// `applyGrants` began `DELETE FROM user_route` unconditionally, so applying any
// fragment — a new model, a changed port — revoked every user's access to every
// route. The deletion was also invisible: with prune off, Apply strips `- `
// lines from the change list, so the verb reported adding a model and said
// nothing about the access it had destroyed.
//
// docs/specs/06-gateway.md §2 is deny-by-default, which is what makes this
// undetectable from the outside: the symptom is 403 on a fleet where nothing
// else moved, and 403 is also what correct behavior looks like.
func TestAPartialApplyDoesNotRevokeEveryGrant(t *testing.T) {
	a := newAppliance(t)
	a.enrolled("fractal")
	a.addUser("alice", "operator")

	models := t.TempDir()
	dir := filepath.Join(models, "hub", "models--acme--tiny")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "config.json"), []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	if code, _, stderr := a.run("model", "register", "acme/tiny", "--node", "fractal",
		"--models-dir", models, "--yes", "--justify", "a model"); code != ExitOK {
		t.Fatalf("register: %s", stderr)
	}

	grant := filepath.Join(t.TempDir(), "grant.toml")
	if err := os.WriteFile(grant, []byte("[[grant]]\nuser = \"alice\"\nroute = \"tiny\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if code, _, stderr := a.run("config", "apply", "-f", grant, "--yes", "--justify", "grant"); code != ExitOK {
		t.Fatalf("grant: %s", stderr)
	}

	// Anything at all, as long as it mentions no grant.
	other := filepath.Join(t.TempDir(), "other.toml")
	if err := os.WriteFile(other, []byte(
		"[[model]]\nid = \"acme/other\"\nbackend = \"vllm\"\nsource = \"local\"\nartifact = \"hf-cache\"\n"),
		0o644); err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr := a.run("config", "apply", "-f", other, "--yes", "--justify", "another")
	if code != ExitOK {
		t.Fatalf("second apply: %s", stderr)
	}
	if _, show, _ := a.run("config", "show", "--format", "json"); !strings.Contains(show, `"alice"`) {
		t.Fatalf("an unrelated partial apply revoked the grant:\n%s\n%s", stdout, show)
	}
	// Reported as left in place, like every other object the document omits, so
	// nobody has to infer it from silence.
	if !strings.Contains(stderr, "grant alice → tiny") {
		t.Errorf("the untouched grant is not reported as left in place:\n%s", stderr)
	}

	// And --prune still removes it, because that is how everything else here is
	// removed. The document is the export with the grant block cut out, so the
	// prune has nothing else to delete.
	_, exported, _ := a.run("config", "export")
	full := filepath.Join(t.TempDir(), "full.toml")
	if err := os.WriteFile(full, []byte(withoutGrants(exported)), 0o644); err != nil {
		t.Fatal(err)
	}
	if code, out, stderr := a.run("config", "apply", "-f", full, "--prune",
		"--yes", "--justify", "revoke"); code != ExitOK {
		t.Fatalf("prune: %s | %s", out, stderr)
	}
	if _, show, _ := a.run("config", "show", "--format", "json"); strings.Contains(show, `"alice"`) {
		t.Errorf("--prune left the grant in place:\n%s", show)
	}
}

// withoutGrants drops every [[grant]] table from an exported document.
func withoutGrants(doc string) string {
	var out []string
	skipping := false
	for _, line := range strings.Split(doc, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "[[") {
			skipping = strings.HasPrefix(strings.TrimSpace(line), "[[grant]]")
		}
		if !skipping {
			out = append(out, line)
		}
	}
	return strings.Join(out, "\n")
}
