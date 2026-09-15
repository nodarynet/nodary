package evidence

import (
	"strings"
	"testing"
	"time"

	"github.com/nodarynet/nodary/internal/policy"
)

func regulated() policy.Profile {
	return policy.Profile{
		Name: "regulated", RequireTOTP: true, RequireJustification: true,
		MinJustificationLength: 12, AuditRetentionDays: 1095, UsageRetentionDays: 90,
		SessionTTLMinutes: 30, TokenMaxTTLDays: 90, AdvisoryDecisionDays: 14,
		EgressDefault: "deny",
	}
}

func opts() Options {
	return Options{Install: "inst_test",
		From: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		To:   time.Date(2026, 3, 31, 0, 0, 0, 0, time.UTC)}
}

// R9-11: the paragraphs carry this install's own values.
//
// **And the reason they can be trusted to is that the alternative fails.** A
// narrative naming a value nodary does not hold has to stop the export, not
// emit `<no value>` into a document somebody signs — which is
// indistinguishable, on the page, from a number they forgot to fill in.
func TestANarrativeCarriesThisInstallsValuesOrDoesNotRender(t *testing.T) {
	files, err := narrativeFiles(regulated(), opts(), 3)
	if err != nil {
		t.Fatalf("rendering: %v", err)
	}
	if len(files) != len(narratives) {
		t.Fatalf("rendered %d files for %d narratives", len(files), len(narratives))
	}

	body := string(files["narratives/3.3.1.md"])
	for _, want := range []string{"1095 days", "90 days", "regulated", "2026-01-01", "2026-03-31"} {
		if !strings.Contains(body, want) {
			t.Errorf("3.3.1 does not carry %q:\n%s", want, body)
		}
	}
	if !strings.Contains(string(files["narratives/3.1.1.md"]), "3 approved node") {
		t.Errorf("3.1.1 does not carry the fleet size: %s", files["narratives/3.1.1.md"])
	}
	// Every file quotes the requirement it is answering, so a paragraph pasted
	// into a plan carries what it is a paragraph about.
	for name, f := range files {
		if !strings.HasPrefix(string(f), "# 3.") {
			t.Errorf("%s does not name its requirement: %.60s", name, f)
		}
		if strings.Contains(string(f), "<no value>") {
			t.Errorf("%s shipped a placeholder", name)
		}
	}

	// The two settings that change what the paragraph says, rather than only
	// which number is in it. A profile that does not require a second factor
	// must not produce a plan claiming one.
	loose := regulated()
	loose.Name, loose.RequireTOTP, loose.EgressDefault = "default", false, "allow"
	files, err = narrativeFiles(loose, opts(), 1)
	if err != nil {
		t.Fatalf("rendering the default profile: %v", err)
	}
	if got := string(files["narratives/3.5.3.md"]); !strings.Contains(got, "is not required") {
		t.Errorf("under a profile that does not require a second factor, 3.5.3 reads:\n%s", got)
	}
	if got := string(files["narratives/3.13.6.md"]); strings.Contains(got, "denied\nby default") ||
		strings.Contains(got, "denied by default") {
		t.Errorf("under an allow default, 3.13.6 claims deny-by-default:\n%s", got)
	}
	if got := string(files["narratives/3.4.3.md"]); strings.Contains(got, "second authentication factor") {
		t.Errorf("3.4.3 claims a second factor under a profile that does not require one:\n%s", got)
	}
}

// Every narrative is about a requirement the crosswalk holds, and every mapped
// requirement has one. A paragraph for a practice nobody mapped would be a
// claim with no evidence behind it; a mapped practice with no paragraph is a
// gap in the plan this bundle exists to support.
func TestNarrativesAndTheCrosswalkCoverTheSameRequirements(t *testing.T) {
	mapped := map[string]bool{}
	for _, p := range crosswalk {
		mapped[p.ID] = true
	}
	written := map[string]bool{}
	for _, n := range narratives {
		if !mapped[n.Practice] {
			t.Errorf("there is a narrative for %s and the crosswalk does not map it", n.Practice)
		}
		written[n.Practice] = true
	}
	for id := range mapped {
		if !written[id] {
			t.Errorf("%s is mapped and has no narrative", id)
		}
	}
}
