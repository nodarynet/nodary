package evidence

import (
	"bytes"
	"encoding/json"
	"fmt"
	"time"

	"github.com/nodarynet/nodary/internal/policy"
)

// practices are the categories a nodary install produces evidence for.
//
// **No practice identifiers.** docs/specs/13-evidence.md §4 and
// docs/plans/pivot-cmmc.md §5 both say the same thing: a mapping table is the
// one artifact in this product where being approximately right is worse than
// being absent, because a customer pastes it into an SSP. The identifiers must
// be transcribed from the publication, which is R9-19 and needs the publication
// open.
//
// So the structure ships and the claims do not. What is here is true and
// checkable — these are the things nodary records — and each entry says plainly
// that it is not yet mapped.
var practices = []struct{ area, evidence, member string }{
	{"Audit and accountability", "Every administrative action, hash-chained, with actor, target, outcome and justification", MemberChain},
	{"Audit record integrity", "Verification of that chain across the reporting period", MemberVerify},
	{"Identification and authentication", "User accounts, roles, TOTP enrollment and credential lifecycle", MemberIdentity},
	{"Configuration management", "Configuration revisions, each authored and justified", MemberRevisions},
	{"System inventory", "Node approvals with the inventory offered at the time", MemberNodes},
	{"Flaw remediation", "What was known, decided, by whom, and applied when", MemberRemediation},
}

// controlIndex renders the practice → evidence index, in both machine and human
// form, with every entry marked unmapped.
func controlIndex(active policy.Profile) ([]byte, []byte) {
	type entry struct {
		Practice string `json:"practice"`
		Status   string `json:"status"`
		Area     string `json:"area"`
		Evidence string `json:"evidence"`
		Member   string `json:"member"`
	}
	doc := struct {
		Schema  int     `json:"schema"`
		Status  string  `json:"status"`
		Detail  string  `json:"detail"`
		Profile string  `json:"active_profile"`
		Entries []entry `json:"entries"`
	}{
		Schema:  1,
		Status:  "unmapped",
		Detail:  unmappedDetail,
		Profile: active.Name,
	}
	for _, p := range practices {
		doc.Entries = append(doc.Entries, entry{
			Practice: "", Status: "unmapped", Area: p.area, Evidence: p.evidence, Member: p.member,
		})
	}
	out, _ := json.MarshalIndent(doc, "", "  ")

	var md bytes.Buffer
	md.WriteString("# Control index\n\n")
	md.WriteString(unmappedDetail + "\n\n")
	fmt.Fprintf(&md, "Active policy profile: **%s**\n\n", active.Name)
	md.WriteString("| Practice | Area | Evidence | Member |\n| :--- | :--- | :--- | :--- |\n")
	for _, p := range practices {
		fmt.Fprintf(&md, "| _unmapped_ | %s | %s | `%s` |\n", p.area, p.evidence, p.member)
	}
	return append(out, '\n'), md.Bytes()
}

const unmappedDetail = "This index lists the evidence this install produces and the bundle member " +
	"holding it. It does NOT yet carry 800-171 practice identifiers: those must be transcribed " +
	"from the publication, and a mapping that is approximately right is worse than one that is " +
	"absent, because it will be pasted into an SSP. Treat the rows below as a guide to what is " +
	"in the bundle, not as a claim that any practice is satisfied."

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
  any practice or control; controls.md lists what evidence exists, and explicitly
  does not carry practice identifiers yet.

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
