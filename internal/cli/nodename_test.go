package cli

import (
	"strings"
	"testing"
)

// R2-45. A node that is not there is `not found`, and a name that differs only
// in case says which node does exist.
//
// **Both halves came out of running the product**, not from reading it:
// scripts/verify-privileged.sh asked to approve `Fractal` on a host whose
// `hostname -s` answers `Fractal` and which had enrolled as `fractal`. The
// refusal called the name "unusable", which sends an operator looking at their
// spelling, and said nothing about the node sitting right there.
func TestApprovingANodeThatIsNotThere(t *testing.T) {
	a := newAppliance(t)
	a.enrolledAs("fractal", "linux", "amd64", offerOf("nvidia"))

	t.Run("a case-only miss names the node that exists", func(t *testing.T) {
		code, _, stderr := a.run("node", "approve", "Fractal",
			"--yes", "--justify", "the host's own spelling")
		if code == ExitOK {
			t.Fatal("approving \"Fractal\" succeeded; the node is \"fractal\"")
		}
		// The name it should have typed, and why the two differ. Enrollment
		// lowercases on purpose (internal/agent/agent.go): the name becomes a
		// certificate common name, a systemd instance after %i, a container
		// name and a directory, and none of those agree about case.
		for _, want := range []string{`"fractal"`, "did you mean", "lowercased"} {
			if !strings.Contains(stderr, want) {
				t.Errorf("the refusal does not say %q: %s", want, stderr)
			}
		}
		// Not "unusable name". The name is perfectly usable and the flags were
		// right; 10 §5 reserves exit 2 for "bad flags, missing arguments".
		if strings.Contains(stderr, "unusable name") {
			t.Errorf("a node that is merely absent is reported as a bad name: %s", stderr)
		}
		if code == ExitUsage {
			t.Errorf("exit = %d (usage); a well-formed name for an absent node is not a usage error", code)
		}
	})

	t.Run("a name nothing resembles is just not found", func(t *testing.T) {
		code, _, stderr := a.run("node", "approve", "gpu-99",
			"--yes", "--justify", "a node that never enrolled")
		if code == ExitOK {
			t.Fatal("approving a node that never enrolled succeeded")
		}
		if strings.Contains(stderr, "did you mean") {
			t.Errorf("a hint was offered for a name nothing resembles: %s", stderr)
		}
		if !strings.Contains(stderr, "a node joins by enrolling") {
			t.Errorf("the refusal does not say how a node arrives: %s", stderr)
		}
	})
}
