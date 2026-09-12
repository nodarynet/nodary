package cli

import (
	"path/filepath"
	"strings"
	"testing"
)

// A read-only command that cannot open the database has to say which command
// it was.
//
// openForReading began as `audit`'s own helper with "audit" printed in front of
// it, and fifteen other commands then reused it — so `nodary node list` against
// a missing database announced itself as `nodary audit node list`. Harmless to
// the machine and actively misleading to the person reading it, who goes and
// looks at a verb they never ran.
func TestAReadOnlyVerbNamesItselfWhenTheDatabaseIsMissing(t *testing.T) {
	absent := filepath.Join(t.TempDir(), "absent.db")

	// The verb is the command, not its arguments — `node show somewhere` is
	// still `node show`.
	for _, tc := range []struct {
		args []string
		verb string
	}{
		{[]string{"node", "list"}, "node list"},
		{[]string{"node", "show", "somewhere"}, "node show"},
		{[]string{"user", "list"}, "user list"},
		{[]string{"user", "show", "alice"}, "user show"},
		{[]string{"token", "list"}, "token list"},
		{[]string{"route", "list"}, "route list"},
		{[]string{"route", "show", "a-route"}, "route show"},
		{[]string{"limits", "show"}, "limits show"},
		{[]string{"usage", "show"}, "usage show"},
		{[]string{"config", "list"}, "config list"},
		{[]string{"config", "show"}, "config show"},
		{[]string{"license", "show"}, "license show"},
		{[]string{"audit", "list"}, "audit list"},
		{[]string{"audit", "verify"}, "audit verify"},
		{[]string{"audit", "export"}, "audit export"},
	} {
		_, _, stderr := run(t, append(tc.args, "--db", absent)...)
		if !strings.HasPrefix(stderr, "nodary "+tc.verb+":") {
			t.Errorf("`nodary %s` reports itself as %q",
				strings.Join(tc.args, " "), strings.SplitN(stderr, ":", 2)[0])
		}
	}
}
