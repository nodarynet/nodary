package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// docs/specs/07-identity-audit.md §4: `default` is what a fresh install runs.
// There is no row until somebody applies one, so this also covers the absence.
func TestPolicyShowOnAFreshInstallIsDefault(t *testing.T) {
	a := newAppliance(t)
	a.addUser("alice", "admin") // creates the database

	code, stdout, stderr := a.run("policy", "show")
	if code != ExitOK {
		t.Fatalf("exit = %d, want 0: %s", code, stderr)
	}
	if !strings.HasPrefix(stdout, "default\n") {
		t.Errorf("stdout does not begin with the profile name:\n%s", stdout)
	}
	if !strings.Contains(stdout, "require_totp             false") {
		t.Errorf("default demands ceremony:\n%s", stdout)
	}
}

func TestPolicyApplyRoundTripsAndLandsInTheChain(t *testing.T) {
	a := newAppliance(t)
	a.addUser("alice", "admin")

	code, _, stderr := a.run("policy", "apply", "regulated")
	if code != ExitOK {
		t.Fatalf("apply: exit = %d, want 0: %s", code, stderr)
	}

	_, stdout, _ := a.run("policy", "show")
	if !strings.HasPrefix(stdout, "regulated\n") {
		t.Errorf("show does not report the applied profile:\n%s", stdout)
	}

	// Every mutating verb passes through the audit layer; this is that check
	// for the one R1d adds.
	_, audit, _ := a.run("audit", "list")
	if !strings.Contains(audit, "policy.apply") {
		t.Errorf("the apply is not in the chain:\n%s", audit)
	}
}

// R1-28: loosening is permitted; doing it silently is not.
func TestPolicyApplyReportsWhatItLoosens(t *testing.T) {
	a := newAppliance(t)
	a.addUser("alice", "admin")

	if code, _, stderr := a.run("policy", "apply", "regulated"); code != ExitOK {
		t.Fatalf("apply regulated: %d %s", code, stderr)
	}
	code, _, stderr := a.run("policy", "apply", "default")
	if code != ExitOK {
		t.Fatalf("apply default: exit = %d, want 0: %s", code, stderr)
	}
	for _, want := range []string{"require_totp", "audit_retention_days", "allow_unattended_tokens"} {
		if !strings.Contains(stderr, "loosens: "+want) {
			t.Errorf("loosening %s was not reported:\n%s", want, stderr)
		}
	}
}

func TestPolicyDiffJSONNamesTheLoosening(t *testing.T) {
	a := newAppliance(t)
	a.addUser("alice", "admin")
	if code, _, stderr := a.run("policy", "apply", "regulated"); code != ExitOK {
		t.Fatalf("apply: %d %s", code, stderr)
	}

	code, stdout, stderr := a.run("policy", "diff", "--format", "json", "default")
	if code != ExitOK {
		t.Fatalf("exit = %d, want 0: %s", code, stderr)
	}
	var got struct {
		Active, Candidate string
		Loosens           bool
		Changes           []struct {
			Setting, From, To string
			Loosens           bool
		}
	}
	if err := json.Unmarshal([]byte(stdout), &got); err != nil {
		t.Fatalf("stdout is not the documented JSON: %v\n%s", err, stdout)
	}
	if got.Active != "regulated" || got.Candidate != "default" || !got.Loosens {
		t.Errorf("diff = %+v", got)
	}
}

// A profile from a file is the normal way an operator applies one.
func TestPolicyApplyFromAFileAndRefusesAnUnknownKey(t *testing.T) {
	a := newAppliance(t)
	a.addUser("alice", "admin")

	good := filepath.Join(a.dir, "site.toml")
	if err := os.WriteFile(good, []byte(`[policy]
name = "site"
require_totp             = true
require_justification    = true
min_justification_length = 20
require_signed_artifacts = true
allow_unattended_tokens  = false
allow_custom_backends    = false
allow_derived_images     = false
require_pinned_derives   = true
egress_default           = "deny"
require_model_manifest   = true
audit_retention_days     = 2555
usage_retention_days     = 90
session_ttl_minutes      = 15
token_max_ttl_days       = 90
`), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, _, stderr := a.run("policy", "apply", good); code != ExitOK {
		t.Fatalf("apply from file: exit = %d, want 0: %s", code, stderr)
	}
	if _, stdout, _ := a.run("policy", "show"); !strings.HasPrefix(stdout, "site\n") {
		t.Errorf("the file profile did not take effect:\n%s", stdout)
	}

	bad := filepath.Join(a.dir, "typo.toml")
	if err := os.WriteFile(bad, []byte("[policy]\nname = \"typo\"\nrequire_signed_artifacts = true\negress_default = \"deny\"\naudit_retention_days = 1\nusage_retention_days = 1\nsession_ttl_minutes = 1\ntoken_max_ttl_days = 1\nrequire_totpp = true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, _, stderr := a.run("policy", "apply", bad)
	if code == ExitOK {
		t.Error("a profile with an unknown key was applied")
	}
	if !strings.Contains(stderr, "require_totpp") {
		t.Errorf("the refusal does not name the key:\n%s", stderr)
	}
	// The refused apply must not have displaced the profile in force.
	if _, stdout, _ := a.run("policy", "show"); !strings.HasPrefix(stdout, "site\n") {
		t.Errorf("a refused profile changed the active one:\n%s", stdout)
	}
}

// A built-in name beats a file of the same name in the working directory: a
// posture object silently coming from somewhere else is exactly the surprise
// this must not have.
func TestBuiltinNameBeatsAFileOfThatName(t *testing.T) {
	a := newAppliance(t)
	a.addUser("alice", "admin")

	decoy := filepath.Join(a.dir, "regulated")
	if err := os.WriteFile(decoy, []byte("[policy]\nname = \"decoy\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Chdir(a.dir)

	if code, _, stderr := a.run("policy", "apply", "regulated"); code != ExitOK {
		t.Fatalf("exit = %d, want 0: %s", code, stderr)
	}
	if _, stdout, _ := a.run("policy", "show"); !strings.HasPrefix(stdout, "regulated\n") {
		t.Errorf("a file displaced the built-in profile:\n%s", stdout)
	}
}
