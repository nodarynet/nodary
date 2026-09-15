package evidence

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The published page and the bundle carry one crosswalk, not two.
//
// **Two copies of a control mapping is the failure mode this whole area is
// careful about.** docs/compliance.md is what a buyer and an assessor read
// before they ever run the software; controls.json is what ships inside the
// bundle. If they disagree, one of them is telling somebody the wrong thing
// about their own System Security Plan, and nothing else would notice.
func TestThePublishedPageAndTheBundleCarryTheSameCrosswalk(t *testing.T) {
	page, err := os.ReadFile(filepath.Join("..", "..", "docs", "compliance.md"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(page)

	for _, p := range crosswalk {
		if !strings.Contains(text, "**"+p.ID+"**") {
			t.Errorf("the published page does not carry practice %s", p.ID)
		}
		// The requirement text too, not just the number: a row whose
		// identifier is right and whose quoted requirement has drifted is
		// worse than a missing row, because it reads as transcribed.
		if !strings.Contains(text, p.Requirement) {
			t.Errorf("practice %s is quoted differently on the page than in the bundle", p.ID)
		}
	}
	for _, f := range notCovered {
		if !strings.Contains(text, f) {
			t.Errorf("the page does not say it is not evidence for %q", f)
		}
	}

	// And nothing on the page claims a practice the crosswalk does not hold.
	known := map[string]bool{}
	for _, p := range crosswalk {
		known[p.ID] = true
	}
	for _, line := range strings.Split(text, "\n") {
		if !strings.HasPrefix(line, "| **3.") {
			continue
		}
		id := strings.TrimSpace(strings.Trim(strings.SplitN(line, "|", 3)[1], " *"))
		if !known[id] {
			t.Errorf("the page claims practice %q and the crosswalk does not hold it", id)
		}
	}
}

// Every identifier is a real Rev 2 requirement, in the right family.
//
// A transcription is only worth the thing it was transcribed from, so the
// shape is checked here and the text itself is pinned by the page test above:
// an identifier invented in a plausible family is exactly the error that would
// otherwise survive review.
func TestEveryPracticeIsWellFormedAndSaysWhatItIsEvidenceFor(t *testing.T) {
	families := map[string]string{
		"3.1": "Access Control", "3.3": "Audit and Accountability",
		"3.4": "Configuration Management", "3.5": "Identification and Authentication",
		"3.12": "Security Assessment", "3.13": "System and Communications Protection",
	}
	seen := map[string]bool{}
	for _, p := range crosswalk {
		if seen[p.ID] {
			t.Errorf("practice %s appears twice", p.ID)
		}
		seen[p.ID] = true

		prefix := p.ID[:strings.LastIndex(p.ID, ".")]
		want, ok := families[prefix]
		if !ok {
			t.Errorf("practice %s is in family prefix %q, which this crosswalk does not claim",
				p.ID, prefix)
			continue
		}
		if p.Family != want {
			t.Errorf("practice %s is filed under %q, and NIST calls %s %q", p.ID, p.Family, prefix, want)
		}
		if p.Requirement == "" || p.Mechanism == "" {
			t.Errorf("practice %s carries no requirement or no mechanism", p.ID)
		}
		for _, m := range p.Members {
			if !strings.Contains(m, ".") {
				t.Errorf("practice %s names %q, which is not a bundle member", p.ID, m)
			}
		}
	}
}

// renderTable writes the published table, so docs/compliance.md is generated
// from this data rather than retyped. Kept beside the test that checks the two
// agree, because it is the thing that makes agreeing cheap.
func renderTable() string {
	var b strings.Builder
	for _, p := range crosswalk {
		fmt.Fprintf(&b, "| **%s** | %s | %s | %s |\n", p.ID, p.Requirement, p.Mechanism, members(p.Members))
	}
	return b.String()
}

func TestRenderCrosswalk(t *testing.T) {
	out := os.Getenv("CROSSWALK_OUT")
	if out == "" {
		t.Skip("set CROSSWALK_OUT to re-render the published table")
	}
	if err := os.WriteFile(out, []byte(renderTable()), 0o644); err != nil {
		t.Fatal(err)
	}
}
