package install

import (
	"regexp"
	"strings"
	"testing"
)

// publishable is every environment variable a unit may interpolate into
// ExecStart=, and why each one is safe there.
//
// systemd expands ${VAR} before it execs, so the value lands in the process's
// argv and /proc/<pid>/cmdline hands it to every local account. That is fine for
// an image reference and wrong for a credential — and a unit template is not
// where anybody notices the difference. The gateway shipped the one key LiteLLM
// accepts, which grants its whole administrative API, that way.
//
// An allowlist rather than a pattern, because "does this name look like a
// secret" is a judgment the next person should have to make deliberately. A
// value that does not belong here is read inside the process instead;
// EnvironmentFile= is already loaded for exactly that, and /proc/<pid>/environ
// is readable only by the same user and root.
var publishable = map[string]string{
	"NODARY_LITELLM_IMAGE": "a digest-pinned image reference, which is public by construction",
}

var interpolation = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)\}`)

func TestNoUnitPutsASecretOnACommandLine(t *testing.T) {
	for _, role := range []string{"server", "node"} {
		for name, body := range Units(role) {
			for _, line := range strings.Split(body, "\n") {
				if !strings.HasPrefix(line, "ExecStart") {
					continue
				}
				for _, m := range interpolation.FindAllStringSubmatch(line, -1) {
					if _, ok := publishable[m[1]]; !ok {
						t.Errorf("%s (%s role) interpolates %s into argv, where /proc/<pid>/cmdline "+
							"publishes it to every local account. Read it inside the process, or say "+
							"here why it is safe to publish:\n  %s", name, role, m[0], line)
					}
				}
			}
		}
	}
}
