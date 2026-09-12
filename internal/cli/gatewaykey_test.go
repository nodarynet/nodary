package cli

import (
	"strings"
	"testing"
)

// The credential reaches the gateway through the environment and no longer
// through an argument, so the old invocation is refused with the reason rather
// than quietly accepted or reported as an unknown flag.
func TestTheGatewayRefusesAMasterKeyPassedAsAnArgument(t *testing.T) {
	t.Setenv("NODARY_MASTER_KEY", "sk-nodary-from-the-environment")

	code, _, stderr := run(t, "gateway", "start", "--master-key", "sk-nodary-on-the-command-line")
	if code != ExitUsage {
		t.Fatalf("exit = %d, want %d (usage)\n%s", code, ExitUsage, stderr)
	}
	for _, want := range []string{"cmdline", "NODARY_MASTER_KEY"} {
		if !strings.Contains(stderr, want) {
			t.Errorf("the refusal does not mention %q:\n%s", want, stderr)
		}
	}
	// And it does not echo the credential it just refused.
	if strings.Contains(stderr, "sk-nodary-on-the-command-line") {
		t.Errorf("the refusal repeats the credential:\n%s", stderr)
	}
}

func TestTheGatewayRefusesToStartWithNoMasterKeyAtAll(t *testing.T) {
	t.Setenv("NODARY_MASTER_KEY", "")

	code, _, stderr := run(t, "gateway", "start")
	if code != ExitUsage {
		t.Fatalf("exit = %d, want %d (usage)\n%s", code, ExitUsage, stderr)
	}
	// Refused rather than defaulted: a built-in default would be the same key
	// on every install, which is no key at all.
	if !strings.Contains(stderr, "must not be a default") {
		t.Errorf("the refusal does not say why there is no fallback:\n%s", stderr)
	}
}
