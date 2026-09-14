package agent

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// docs/specs/11-failure-modes.md §2 and docs/specs/03-agent.md's reboot safety
// both state the same "never" twice over: a GPU falling off the bus is
// **never auto-rebooted**, and on a host with an encrypted root and no network
// unlock — or on WSL2, where `reboot` inside the distribution does not restart
// the Windows host anyway — the agent never initiates one at all.
//
// A "never" is not testable by exercising it: no input makes a reboot happen,
// which is exactly the claim. So this asserts the only thing that can be
// asserted — that nothing in this package can reach the command. That is worth
// having because the tempting fix for a wedged GPU is a reboot, and the cost of
// one here is a machine that comes back to a passphrase prompt at a console in
// a locked rack.
func TestTheAgentCannotRebootAnything(t *testing.T) {
	// A command name in argument position. Struct tags (`json:"reboot"`) are
	// not matched, because `json:` precedes the quote rather than `(` or `,`.
	dangerous := regexp.MustCompile(`[(,]\s*"(reboot|shutdown|poweroff|halt)"`)

	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	seen := 0
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		body, err := os.ReadFile(filepath.Join(".", name))
		if err != nil {
			t.Fatal(err)
		}
		seen++
		if m := dangerous.FindString(string(body)); m != "" {
			t.Errorf("%s can run %s. The agent reports a hardware fault and leaves the "+
				"decision to a person: 11 §2 says a GPU off the bus is never auto-rebooted, "+
				"and 03's reboot safety says a host that needs a human at the console must "+
				"not be restarted by software that cannot be there.", name, strings.TrimLeft(m, "(, "))
		}
	}
	if seen == 0 {
		t.Fatal("read no source for this package, so this asserted nothing")
	}
}
