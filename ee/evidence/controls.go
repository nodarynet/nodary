package evidence

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/nodarynet/nodary/internal/policy"
)

// controlIndex renders the crosswalk in both machine and human form.
//
// **It carries practice identifiers now.** It shipped as a structure with every
// entry marked `unmapped`, because dev/plans/pivot-cmmc.md §5 makes this the one
// artifact where being approximately right is worse than being absent — a
// customer pastes it into a System Security Plan an assessor reads. The
// identifiers and the quoted requirements are transcribed from NIST's own
// published CSV of the Rev 2 requirements; see crosswalk.go.
//
// A row still says where evidence lives and not that a requirement is
// discharged, and the rendering says so where a reader cannot miss it.
func controlIndex(active policy.Profile) ([]byte, []byte) {
	type entry struct {
		Practice
		// Status is `evidence` and never `satisfied`. The word is chosen so
		// that a row pasted into a plan cannot be read as a claim nodary is
		// not in a position to make.
		Status string `json:"status"`
	}
	doc := struct {
		Schema     int      `json:"schema"`
		Source     string   `json:"source"`
		Revision   string   `json:"revision"`
		Status     string   `json:"status"`
		Detail     string   `json:"detail"`
		Profile    string   `json:"active_profile"`
		NotCovered []string `json:"families_not_covered"`
		Entries    []entry  `json:"entries"`
	}{
		Schema:     2,
		Source:     "NIST SP 800-171 Rev. 2 (February 2020, updated 28 January 2021)",
		Revision:   "rev2",
		Status:     "evidence",
		Detail:     mappedDetail,
		Profile:    active.Name,
		NotCovered: notCovered,
	}
	for _, p := range crosswalk {
		doc.Entries = append(doc.Entries, entry{Practice: p, Status: "evidence"})
	}
	out, _ := json.MarshalIndent(doc, "", "  ")

	var md bytes.Buffer
	md.WriteString("# Control index\n\n")
	md.WriteString(mappedDetail + "\n\n")
	fmt.Fprintf(&md, "Source: %s\n\n", doc.Source)
	fmt.Fprintf(&md, "Active policy profile: **%s**\n\n", active.Name)
	md.WriteString("| Practice | Family | Requirement | What nodary does | Evidence |\n")
	md.WriteString("| :--- | :--- | :--- | :--- | :--- |\n")
	for _, p := range crosswalk {
		fmt.Fprintf(&md, "| **%s** | %s | %s | %s | %s |\n",
			p.ID, p.Family, p.Requirement, p.Mechanism, members(p.Members))
	}
	md.WriteString("\n## Requirement families this bundle is not evidence for\n\n")
	md.WriteString("Listed because an index that shows only what it covers reads as though it " +
		"covers everything. Each of these is satisfied by the operating organization, and " +
		"nothing in nodary contributes to it:\n\n")
	for _, f := range notCovered {
		fmt.Fprintf(&md, "- %s\n", f)
	}
	return append(out, '\n'), md.Bytes()
}

func members(names []string) string {
	if len(names) == 0 {
		return "_no artifact in this bundle_"
	}
	out := make([]string, 0, len(names))
	for _, n := range names {
		out = append(out, "`"+n+"`")
	}
	return strings.Join(out, ", ")
}

// notCovered is the families nodary contributes nothing to.
//
// **Published deliberately.** dev/status.md's own rule is that a half-built
// control is the one that gets written into a plan by mistake; an index listing
// only what it covers invites exactly that reading of everything it omits.
var notCovered = []string{
	"3.2 Awareness and Training — entirely organizational.",
	"3.6 Incident Response — nodary produces evidence an investigation uses; it runs no incident response process.",
	"3.7 Maintenance — host and hardware maintenance is outside what nodary manages, by design.",
	"3.8 Media Protection — nodary holds no removable media and does not mark, transport or sanitize any.",
	"3.9 Personnel Security — screening and termination are the organization's, though revoking what a leaver held is an act nodary records.",
	"3.10 Physical Protection — nothing in software.",
	"3.11 Risk Assessment — nodary reports advisories against what it runs; assessing organizational risk is not in it.",
	"3.14 System and Information Integrity — the advisory feed contributes to flaw remediation and is reported under 3.12.2 rather than claimed twice here.",
}

const mappedDetail = "This index maps what this installation produces to the NIST SP 800-171 " +
	"Rev. 2 requirements it is EVIDENCE FOR. It does not assert that any requirement is " +
	"satisfied: every requirement has an owner inside your organization, the accuracy of your " +
	"System Security Plan is yours, and a row here means only that when the `regulated` " +
	"profile is active, the mechanism named is what an assessor would be shown and the member " +
	"named is where it is. Identifiers are transcribed from NIST's published requirements " +
	"list. Rev. 2 was withdrawn by NIST on 14 May 2024 and remains what CMMC Level 2 is " +
	"assessed against; the identifiers renumber when that changes."

// readme is the first thing an assessor opens.
func readme(opt Options, profile string) []byte {
	var b bytes.Buffer
	fmt.Fprintf(&b, `nodary evidence bundle
======================

Install                %s
Reporting period       %s to %s
Active policy profile  %s

WHAT THIS IS

  A record of what happened on one nodary installation during the period above,
  exported from a hash-chained audit log. Start with verify.txt, which says what
  the chain verification concluded and how to repeat it yourself.

WHAT THIS IS NOT

  It is not an assessment. Nothing here asserts that this installation satisfies
  any requirement. controls.md maps what this install produces to the NIST SP
  800-171 Rev. 2 requirements it is EVIDENCE FOR, and narratives/ holds a
  paragraph per requirement written to be pasted into a System Security Plan and
  then edited. Both say where evidence lives; the plan, and its accuracy, are
  yours.

  controls.md also lists the requirement families this bundle is NOT evidence
  for. That list is there because an index showing only what it covers reads as
  though it covers everything.

  An empty member is not a broken one. manifest.json gives a record count for
  every .jsonl member, so a file with no rows can be told apart from a file that
  failed to write.

  It does not cover what nodary does not manage. Host operating system patch
  level and GPU driver versions are outside nodary's control by design, and are
  reported by the fleet inventory rather than governed here.

  It contains no request or response content. nodary records that a request
  happened -- who, when, which model, how many tokens -- and never what it said.

CHECKING IT

  sha256sum -c manifest.sha256
  minisign -Vm manifest.json -p nodary-evidence.pub

  Neither needs nodary. See verify.txt for the chain procedure.
`, opt.Install,
		opt.From.UTC().Format(time.DateOnly), opt.To.UTC().Format(time.DateOnly), profile)
	return b.Bytes()
}
