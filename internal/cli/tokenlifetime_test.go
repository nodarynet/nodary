package cli

import (
	"strings"
	"testing"
)

// token_max_ttl_days was a displayed number with nothing behind it: `policy
// show` reported a ceiling and the mint path never read it, so an install could
// hand out credentials its own profile forbade. An assessor reading the policy
// object and an operator reading the token table were looking at two different
// systems.
func TestAMintedCredentialCannotOutliveTheProfilesCeiling(t *testing.T) {
	a := newAppliance(t)
	a.addUser("alice", "operator")

	// default sets token_max_ttl_days = 3650, so the ceiling is loose and a
	// credential that never expires still exceeds it — no finite ceiling admits
	// an infinite lifetime.
	code, _, stderr := a.run("token", "create", "--user", "alice", "--expires", "never")
	if code != ExitPolicy {
		t.Fatalf("`never` exited %d, want %d (policy refused)\n%s", code, ExitPolicy, stderr)
	}
	for _, want := range []string{"token_max_ttl_days", "never expire"} {
		if !strings.Contains(stderr, want) {
			t.Errorf("the refusal does not mention %q:\n%s", want, stderr)
		}
	}

	// Exactly at the ceiling still mints. A bound that refuses its own limit
	// would make the displayed number wrong in the other direction.
	if code, _, stderr := a.run("token", "create", "--user", "alice", "--expires", "3650d"); code != ExitOK {
		t.Errorf("a credential at the ceiling exited %d: %s", code, stderr)
	}
	if code, _, stderr := a.run("token", "create", "--user", "alice", "--expires", "3651d"); code != ExitPolicy {
		t.Errorf("a credential one day over exited %d, want %d\n%s", code, ExitPolicy, stderr)
	}
}

func TestATighterProfileLowersTheCeilingForBothKindsOfCredential(t *testing.T) {
	a := newAppliance(t)
	a.addUser("alice", "operator")

	if code, _, stderr := a.run("policy", "apply", "regulated",
		"--justify", "moving the pilot to regulated"); code != ExitOK {
		t.Fatalf("apply regulated: %d %s", code, stderr)
	}

	// regulated sets 365. The review minted a ten-year service key against it.
	code, _, stderr := a.run("token", "create", "--user", "alice", "--kind", "sk",
		"--expires", "3650d", "--justify", "a batch job that runs forever")
	if code != ExitPolicy {
		t.Fatalf("a ten-year service key exited %d, want %d\n%s", code, ExitPolicy, stderr)
	}
	if !strings.Contains(stderr, "365") || !strings.Contains(stderr, "regulated") {
		t.Errorf("the refusal names neither the ceiling nor the profile:\n%s", stderr)
	}

	// A join token takes --expires in days too, so it reads the same ceiling.
	code, _, stderr = a.run("token", "join", "--expires", "3650d",
		"--justify", "enrolling the second GPU host")
	if code != ExitPolicy {
		t.Errorf("a ten-year join token exited %d, want %d\n%s", code, ExitPolicy, stderr)
	}

	if code, _, stderr := a.run("token", "create", "--user", "alice",
		"--expires", "30d", "--justify", "alice's laptop"); code != ExitOK {
		t.Errorf("an ordinary credential exited %d: %s", code, stderr)
	}
}
