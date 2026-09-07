package policy

import (
	"errors"
	"os"
	"reflect"
	"regexp"
	"strings"
	"testing"
)

// The shipped profiles must match docs/specs/07-identity-audit.md §4 exactly.
// R1-26 says "exactly", and the cheapest way to mean it is to compare against
// the specification rather than against a transcription of it — a transcription
// is the thing that drifts.
func TestBuiltinProfilesMatchTheSpecification(t *testing.T) {
	spec, err := os.ReadFile("../../docs/specs/07-identity-audit.md")
	if err != nil {
		t.Fatalf("reading the specification: %v", err)
	}
	blocks := regexp.MustCompile("(?s)```toml\n(.*?)```").FindAllStringSubmatch(string(spec), -1)
	if len(blocks) != 2 {
		t.Fatalf("07 §4 has %d toml blocks, want 2 (default and regulated)", len(blocks))
	}
	for i, name := range BuiltinNames() {
		src, err := profiles.ReadFile("profiles/" + name + ".toml")
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if got, want := strings.TrimSpace(string(src)), strings.TrimSpace(blocks[i][1]); got != want {
			t.Errorf("%s.toml does not match the specification\n--- embedded ---\n%s\n--- 07 §4 ---\n%s", name, got, want)
		}
	}
}

func TestBothBuiltinProfilesParse(t *testing.T) {
	for _, name := range BuiltinNames() {
		p, _, err := Builtin(name)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if p.Name != name {
			t.Errorf("%s: parsed name is %q", name, p.Name)
		}
	}
}

// docs/specs/07-identity-audit.md §4: `default` is the profile a fresh install
// runs, because demanding a TOTP code before a user exists converts nobody.
func TestDefaultAsksForNoCeremony(t *testing.T) {
	p, _, err := Builtin(Default)
	if err != nil {
		t.Fatal(err)
	}
	if p.RequireTOTP || p.RequireJustification {
		t.Errorf("default requires ceremony: totp=%v justification=%v", p.RequireTOTP, p.RequireJustification)
	}
	if !p.AllowUnattendedTokens {
		t.Error("default forbids unattended tokens; scripts and cron are the normal case there")
	}
}

func TestRegulatedDemandsCeremonyAndHoldsEvidenceLonger(t *testing.T) {
	d, _, _ := Builtin("default")
	r, _, err := Builtin("regulated")
	if err != nil {
		t.Fatal(err)
	}
	if !r.RequireTOTP || !r.RequireJustification || r.MinJustificationLength < 12 {
		t.Errorf("regulated does not demand ceremony: %+v", r)
	}
	if r.AllowUnattendedTokens {
		t.Error("regulated allows unattended tokens")
	}
	if r.AuditRetentionDays <= d.AuditRetentionDays {
		t.Errorf("regulated holds audit evidence for %d days, default for %d", r.AuditRetentionDays, d.AuditRetentionDays)
	}
}

// R1-25: unknown keys are rejected rather than ignored. A profile is reviewed by
// reading it, so a key nobody applies is a constraint an operator wrongly
// believes is in force.
func TestUnknownKeyIsRefusedAndNamed(t *testing.T) {
	_, err := Parse([]byte("[policy]\nname = \"x\"\nrequire_signed_artifacts = true\negress_default = \"deny\"\naudit_retention_days = 1\nusage_retention_days = 1\nsession_ttl_minutes = 1\ntoken_max_ttl_days = 1\nrequire_totpp = true\n"))
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("err = %v, want ErrInvalid", err)
	}
	if !strings.Contains(err.Error(), "require_totpp") {
		t.Errorf("the message does not name the key: %v", err)
	}
}

// R1-27's three inexpressible invariants. "unknown key audit_chain" reads as a
// typo; somebody who just tried to disable the audit chain deserves to be told
// that it is not a setting.
func TestDisablingAnInvariantSaysWhyRatherThanUnknownKey(t *testing.T) {
	for _, key := range []string{"audit_chain", "intent_hash", "digest_pinning", "egress_isolation"} {
		_, err := Parse([]byte("[policy]\nname = \"x\"\n" + key + " = false\n"))
		if !errors.Is(err, ErrInvalid) {
			t.Fatalf("%s: err = %v, want ErrInvalid", key, err)
		}
		if strings.Contains(err.Error(), "unknown key") {
			t.Errorf("%s: refused as an unknown key rather than as an invariant: %v", key, err)
		}
		if !strings.Contains(err.Error(), "not a setting") {
			t.Errorf("%s: message does not say it is not a setting: %v", key, err)
		}
	}
}

// R1-27's two expressible invariants — the ones a plausible profile could
// contain by accident.
func TestExpressibleInvariantsAreRefused(t *testing.T) {
	base := "[policy]\nname = \"x\"\naudit_retention_days = 1\nusage_retention_days = 1\nsession_ttl_minutes = 1\ntoken_max_ttl_days = 1\n"
	for _, tc := range []struct{ name, src, want string }{
		{"unsigned artifacts", base + "require_signed_artifacts = false\negress_default = \"deny\"\n", "require_signed_artifacts"},
		{"egress allowed", base + "require_signed_artifacts = true\negress_default = \"allow\"\n", "egress_default"},
	} {
		_, err := Parse([]byte(tc.src))
		if !errors.Is(err, ErrInvalid) {
			t.Fatalf("%s: err = %v, want ErrInvalid", tc.name, err)
		}
		if !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: message does not name %s: %v", tc.name, tc.want, err)
		}
	}
}

// Every field must appear in the diff table. A setting missing from it would
// never show up in `policy diff`, which is the one failure that verb exists to
// prevent.
func TestEverySettingIsDiffable(t *testing.T) {
	n := reflect.TypeOf(Profile{}).NumField() - 1 // Name is the profile's identity, not a setting
	if len(fields) != n {
		t.Errorf("Profile has %d settings and the diff table has %d — a setting missing here is invisible to `policy diff`", n, len(fields))
	}
}

func TestDiffNamesWhatLoosens(t *testing.T) {
	strict, _, _ := Builtin("regulated")
	loose, _, _ := Builtin("default")

	changes := Diff(strict, loose)
	if !Loosens(changes) {
		t.Fatal("regulated -> default does not report loosening")
	}
	got := map[string]bool{}
	for _, c := range changes {
		if c.Loosens {
			got[c.Setting] = true
		}
	}
	for _, want := range []string{
		"require_totp", "require_justification", "min_justification_length",
		"allow_unattended_tokens", "allow_custom_backends", "require_pinned_derives",
		"require_model_manifest", "audit_retention_days", "session_ttl_minutes",
		"token_max_ttl_days", "model_origin_allowlist", "model_origin_denylist",
	} {
		if !got[want] {
			t.Errorf("%s does not report as loosening when regulated becomes default", want)
		}
	}

	// The other direction tightens, and nothing in it may claim to loosen.
	for _, c := range Diff(loose, strict) {
		if c.Loosens {
			t.Errorf("default -> regulated reports %s as loosening", c.Setting)
		}
	}
}

func TestDiffOfAProfileWithItselfIsEmpty(t *testing.T) {
	for _, name := range BuiltinNames() {
		p, _, _ := Builtin(name)
		if changes := Diff(p, p); len(changes) != 0 {
			t.Errorf("%s differs from itself: %v", name, changes)
		}
	}
}

// An empty allowlist means any origin, so emptying one is the loosest move
// available -- and filling one in is a tightening, not a change to wave through.
func TestEmptyAllowlistIsTheLoosestAllowlist(t *testing.T) {
	restricted, _, _ := Builtin("regulated")
	open := restricted
	open.ModelOriginAllowlist = nil

	if !Diff(restricted, open)[0].Loosens {
		t.Error("emptying the allowlist does not report as loosening")
	}
	for _, c := range Diff(open, restricted) {
		if c.Setting == "model_origin_allowlist" && c.Loosens {
			t.Error("filling in an empty allowlist reports as loosening")
		}
	}
}
