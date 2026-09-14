package agent

import (
	"strings"
	"testing"
)

// R4-28: the unit's IPAddressDeny= is defense in depth and is documented in
// place as not being the egress control.
//
// Two opposite things can go wrong with this line, and a test is the only thing
// that catches either.
//
// Delete it, because it demonstrably filters nothing here, and the host loses a
// filter that does apply in the configurations where the container is *not*
// reparented — which is the whole meaning of defense in depth. Delete the
// comment instead, and a later reader finds a directive that looks like the
// egress control, reviews clean, and stops looking for the mechanism that
// actually enforces docs/specs/03-agent.md §5. The second is worse: §5 opens by
// saying this exact approach "looks correct, reviews clean, and enforces
// nothing".
//
// So the assertion is the pairing, not either half — and "in place" means what
// it says: the disclaimer has to be in the comment block attached to the
// directive, where somebody editing that line will read it, not somewhere else
// in the file.
func TestTheUnitFilterIsKeptAndDisclaimedWhereItIsWritten(t *testing.T) {
	lines := strings.Split(RenderUnitTemplate("/etc/nodary"), "\n")

	at := -1
	for i, l := range lines {
		if strings.TrimSpace(l) == "IPAddressDeny=any" {
			at = i
			break
		}
	}
	if at < 0 {
		t.Fatal("IPAddressDeny=any is gone from the unit template. It is defense in depth " +
			"(R4-28) and filters nothing on a host that reparents the container — but it does " +
			"apply where nothing reparents it, which is why it is kept.")
	}

	// The contiguous comment block immediately above it, which is what an
	// operator or a reviewer reads when they touch that line.
	var block []string
	for i := at - 1; i >= 0; i-- {
		l := strings.TrimSpace(lines[i])
		if l != "" && !strings.HasPrefix(l, "#") {
			break
		}
		if l == "" && len(block) > 0 && i > 0 && !strings.HasPrefix(strings.TrimSpace(lines[i-1]), "#") {
			break
		}
		block = append(block, l)
	}
	attached := strings.ToLower(strings.Join(block, "\n"))

	for _, want := range []string{
		// That it is not the control, in the words §5 uses.
		"not the egress control",
		// And where the control actually is, so a reader has somewhere to go.
		"verify-egress",
	} {
		if !strings.Contains(attached, want) {
			t.Errorf("the comment attached to IPAddressDeny= does not say %q.\n"+
				"Without it the directive reads as the egress control, which is the "+
				"mistake docs/specs/03-agent.md §5 exists to prevent.\nAttached comment:\n%s",
				want, strings.Join(block, "\n"))
		}
	}
}
