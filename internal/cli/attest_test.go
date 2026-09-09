package cli

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/nodarynet/nodary/internal/identity"
)

// R1-13: --dry-run prints the rendered change and its hash and applies nothing.
func TestDryRunAppliesNothingAndPrintsTheIntent(t *testing.T) {
	a := newAppliance(t)
	a.addUser("alice", "admin")

	code, stdout, stderr := a.run("user", "add", "bob", "--role", "operator", "--dry-run")
	if code != ExitOK {
		t.Fatalf("exit = %d, want 0: %s", code, stderr)
	}
	if !strings.Contains(stdout, "intent ") {
		t.Errorf("no intent hash in the preview:\n%s", stdout)
	}
	if !strings.Contains(stderr, "nothing was applied") {
		t.Errorf("stderr does not say it applied nothing:\n%s", stderr)
	}

	// The whole point: bob must not exist.
	if _, list, _ := a.run("user", "list"); strings.Contains(list, "bob") {
		t.Errorf("--dry-run created the user:\n%s", list)
	}
}

// docs/specs/10-cli.md §4: --format json emits a stable schema to stdout and
// nothing else, and a dry run is the case where the preview *is* the output.
func TestDryRunJSONIsTheOnlyThingOnStdout(t *testing.T) {
	a := newAppliance(t)
	a.addUser("alice", "admin")

	code, stdout, _ := a.run("user", "add", "bob", "--role", "user", "--dry-run", "--format", "json")
	if code != ExitOK {
		t.Fatalf("exit = %d", code)
	}
	var got struct {
		DryRun     bool   `json:"dry_run"`
		Action     string `json:"action"`
		IntentHash string `json:"intent_hash"`
		Change     map[string]any
	}
	if err := json.Unmarshal([]byte(stdout), &got); err != nil {
		t.Fatalf("stdout is not the documented JSON: %v\n%s", err, stdout)
	}
	if !got.DryRun || got.Action != "user.add" || len(got.IntentHash) != 64 {
		t.Errorf("document = %+v", got)
	}
	if got.Change["name"] != "bob" {
		t.Errorf("the change does not describe the user: %v", got.Change)
	}
}

// R1-15: under regulated a five-character justification is refused, and the
// refusal is a policy refusal — exit 5, not a generic failure.
func TestRegulatedRefusesAShortJustificationWithExitFive(t *testing.T) {
	a := newAppliance(t)
	a.addUser("alice", "admin")
	if code, _, stderr := a.run("policy", "apply", "regulated"); code != ExitOK {
		t.Fatalf("apply regulated: %d %s", code, stderr)
	}

	code, _, stderr := a.run("user", "add", "bob", "--role", "user", "--justify", "fixed")
	if code != ExitPolicy {
		t.Errorf("exit = %d, want %d (policy refused)", code, ExitPolicy)
	}
	if !strings.Contains(stderr, "too short") {
		t.Errorf("the refusal does not say why:\n%s", stderr)
	}

	// Absent entirely is a different message and the same code.
	code, _, stderr = a.run("user", "add", "bob", "--role", "user")
	if code != ExitPolicy {
		t.Errorf("exit = %d, want %d", code, ExitPolicy)
	}
	if !strings.Contains(stderr, "--justify") {
		t.Errorf("the refusal does not name the flag:\n%s", stderr)
	}

	// And a real one goes through.
	if code, _, stderr := a.run("user", "add", "bob", "--role", "user",
		"--justify", "onboarding the new operator"); code != ExitOK {
		t.Errorf("a good justification was refused: %d %s", code, stderr)
	}
}

// R1-31: --yes skips the confirmation and skips neither justification nor TOTP.
// It is the flag somebody reaches for to make a refusal go away, so the test is
// that the refusal still happens.
func TestYesDoesNotSkipJustification(t *testing.T) {
	a := newAppliance(t)
	a.addUser("alice", "admin")
	if code, _, stderr := a.run("policy", "apply", "regulated"); code != ExitOK {
		t.Fatalf("apply regulated: %d %s", code, stderr)
	}

	code, _, stderr := a.run("user", "add", "bob", "--role", "user", "--yes")
	if code != ExitPolicy {
		t.Errorf("--yes skipped the justification: exit = %d, want %d\n%s", code, ExitPolicy, stderr)
	}
}

// R1-17: the grant is refused at the mint under a profile that forbids it, and
// the refusal is the policy's, not a usage error.
func TestUnattendedGrantIsRefusedUnderRegulated(t *testing.T) {
	a := newAppliance(t)
	a.addUser("alice", "admin")

	// Allowed under default.
	code, _, stderr := a.run("token", "create", "--user", "alice", "--allow-unattended")
	if code != ExitOK {
		t.Fatalf("default refused the grant: %d %s", code, stderr)
	}
	if !strings.Contains(stderr, "unattended") {
		t.Errorf("the grant is not reported to the operator:\n%s", stderr)
	}
	// The grant is in the chain, which is what an assessor reads instead of a
	// person's presence for every act this credential later authorizes.
	if _, chain, _ := a.run("audit", "list", "--format", "json"); !strings.Contains(chain, "allow_unattended") {
		t.Errorf("the grant is not in the chain:\n%s", chain)
	}

	if code, _, stderr := a.run("policy", "apply", "regulated"); code != ExitOK {
		t.Fatalf("apply regulated: %d %s", code, stderr)
	}
	code, _, stderr = a.run("token", "create", "--user", "alice", "--allow-unattended",
		"--justify", "the nightly rotation job")
	if code != ExitPolicy {
		t.Errorf("exit = %d, want %d (policy refused)", code, ExitPolicy)
	}
	if !strings.Contains(stderr, "allow_unattended_tokens") {
		t.Errorf("the refusal does not name the setting:\n%s", stderr)
	}
}

// Local root has no user row and therefore no TOTP seed. R1c's argument applies
// unchanged — anyone who can open the database can already do anything to it —
// so the act proceeds and the record says why it carried no code.
func TestLocalRootIsExemptFromTOTPAndTheRecordSaysSo(t *testing.T) {
	a := newAppliance(t)
	a.addUser("alice", "admin")
	if code, _, stderr := a.run("policy", "apply", "regulated"); code != ExitOK {
		t.Fatalf("apply regulated: %d %s", code, stderr)
	}

	code, _, stderr := a.run("user", "add", "bob", "--role", "user",
		"--justify", "onboarding the new operator")
	if code != ExitOK {
		t.Fatalf("local root was refused under regulated: %d %s", code, stderr)
	}
	_, chain, _ := a.run("audit", "list", "--format", "json")
	if !strings.Contains(chain, "totp_exempt") {
		t.Errorf("the record does not say the act carried no code:\n%s", chain)
	}
}

// docs/specs/10-cli.md §4: diagnostics go to stderr. A preview on stdout would
// corrupt every scripted caller.
func TestThePreviewNeverReachesStdout(t *testing.T) {
	a := newAppliance(t)
	a.addUser("alice", "admin")

	_, stdout, _ := a.run("user", "add", "bob", "--role", "user", "--format", "json")
	var doc map[string]any
	if err := json.Unmarshal([]byte(stdout), &doc); err != nil {
		t.Fatalf("stdout is not a single JSON document: %v\n%s", err, stdout)
	}
	if _, ok := doc["intent_hash"]; ok {
		t.Error("the preview leaked into the result document")
	}
}

// The confirmation exists only when somebody is there to answer it, and
// answering "no" must apply nothing.
func TestDecliningTheConfirmationAppliesNothing(t *testing.T) {
	a := newAppliance(t)
	a.addUser("alice", "admin")

	args := append([]string{"user", "add"}, a.where()...)
	args = append(args, "bob", "--role", "user")

	code, _, stderr := runInteractive(t, "n\n", args...)
	if code == ExitOK {
		t.Errorf("declining reported success: %s", stderr)
	}
	if !strings.Contains(stderr, "nothing was applied") {
		t.Errorf("stderr does not say it applied nothing:\n%s", stderr)
	}
	if _, list, _ := a.run("user", "list"); strings.Contains(list, "bob") {
		t.Errorf("a declined change was applied:\n%s", list)
	}

	// And "y" goes through, so the test above is not passing for the wrong
	// reason.
	if code, _, stderr := runInteractive(t, "y\n", args...); code != ExitOK {
		t.Fatalf("confirming failed: %d %s", code, stderr)
	}
	if _, list, _ := a.run("user", "list"); !strings.Contains(list, "bob") {
		t.Errorf("a confirmed change was not applied:\n%s", list)
	}
}

// R1-16: re-authentication is per act, not per session. A token-authenticated
// operator under `regulated` is prompted, and a wrong code fails the act as an
// authentication failure rather than a policy refusal.
func TestTOTPReEntryIsPromptedAndAWrongCodeFailsTheAct(t *testing.T) {
	a := newAppliance(t)
	a.addUser("alice", "admin")
	a.enrollAndAuthenticate("alice")

	if code, _, stderr := a.run("policy", "apply", "regulated",
		"--justify", "moving the pilot to regulated"); code != ExitOK {
		t.Fatalf("apply regulated: %d %s", code, stderr)
	}

	args := append([]string{"user", "add"}, a.where()...)
	args = append(args, "bob", "--role", "user", "--justify", "onboarding the new operator")

	// Two prompts, in this order: confirm the change, then re-authenticate for
	// it. The code proves a person was present *for this act*, so asking after
	// the operator has seen and approved it is the order that means something —
	// asking first would be proving presence for something not yet shown.
	code, _, stderr := runInteractive(t, "y\n000000\n", args...)
	if code != ExitAuth {
		t.Errorf("a wrong code exited %d, want %d (authentication failure)\n%s", code, ExitAuth, stderr)
	}
	if !strings.Contains(stderr, "TOTP code") {
		t.Errorf("the operator was never prompted:\n%s", stderr)
	}
	if _, list, _ := a.run("user", "list"); strings.Contains(list, "bob") {
		t.Errorf("a failed re-authentication still applied the change:\n%s", list)
	}
}

// Non-interactive, ordinary credential, under a profile that requires a code:
// refused for having nobody to ask, and told what would fix it.
func TestNonInteractiveUnderRegulatedIsRefusedWithTheWayOut(t *testing.T) {
	a := newAppliance(t)
	a.addUser("alice", "admin")
	a.enrollAndAuthenticate("alice")
	if code, _, stderr := a.run("policy", "apply", "regulated",
		"--justify", "moving the pilot to regulated"); code != ExitOK {
		t.Fatalf("apply regulated: %d %s", code, stderr)
	}

	code, _, stderr := a.run("user", "add", "bob", "--role", "user",
		"--justify", "onboarding the new operator")
	if code != ExitPolicy {
		t.Errorf("exit = %d, want %d (policy refused)\n%s", code, ExitPolicy, stderr)
	}
	if !strings.Contains(stderr, "allow-unattended") {
		t.Errorf("the refusal does not name the way out:\n%s", stderr)
	}
}

// enrollAndAuthenticate gives the user a TOTP seed and leaves a personal token
// in the credentials file, so later commands act as that person rather than as
// local root — which is the only way to reach the re-authentication path, since
// local root has no seed to check.
func (a *appliance) enrollAndAuthenticate(name string) {
	a.t.Helper()

	a.seeds[name] = a.enrollTOTP(name)

	if code, _, stderr := a.run("token", "create", "--user", name, "--save"); code != ExitOK {
		a.t.Fatalf("minting a credential for %s: %d %s", name, code, stderr)
	}
}

// enrollTOTP completes an enrollment, which cannot be driven with a fixed
// stdin: each run mints a fresh seed, prints it, and then asks for the code
// that seed is showing. So the seed is read off stdout and the answer written
// back while the command is still running -- which is what an operator with an
// authenticator does.
func (a *appliance) enrollTOTP(name string) []byte {
	a.t.Helper()

	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	var stderr bytes.Buffer
	done := make(chan int, 1)

	go func() {
		args := append([]string{"user", "totp"}, a.where()...)
		args = append(args, name)
		done <- dispatch(env{stdin: inR, stdout: outW, stderr: &stderr, tty: true}, args)
		outW.Close()
	}()

	// The seed is the only thing on stdout, and it is written before the
	// prompt, so one line is the whole of it.
	line, err := bufio.NewReader(outR).ReadString('\n')
	if err != nil {
		a.t.Fatalf("reading the seed for %s: %v", name, err)
	}
	seed, err := identity.DecodeSeed(strings.TrimSpace(line))
	if err != nil {
		a.t.Fatalf("decoding the seed for %s: %v", name, err)
	}
	if _, err := io.WriteString(inW, identity.Code(seed, time.Now())+"\n"); err != nil {
		a.t.Fatalf("answering the prompt: %v", err)
	}
	inW.Close()
	go io.Copy(io.Discard, outR)

	if code := <-done; code != ExitOK {
		a.t.Fatalf("enrolling %s: exit %d\n%s", name, code, stderr.String())
	}
	return seed
}

// code is the next code that user's authenticator will show.
//
// The next one rather than the current one because enrollment just spent the
// current step, and a step at or below the floor is refused however well it
// verifies -- which is the replay protection working, not a quirk to route
// around. An operator in this position waits thirty seconds; a test does not
// have to.
func (a *appliance) code(name string) string {
	a.t.Helper()
	seed, ok := a.seeds[name]
	if !ok {
		a.t.Fatalf("%s is not enrolled", name)
	}
	return identity.Code(seed, time.Now().Add(30*time.Second))
}

// The correct code is accepted, and it is spent: docs/specs/07-identity-audit.md
// §2's re-entry is per act, so the same code cannot authorize a second one.
func TestACorrectCodeIsAcceptedAndThenSpent(t *testing.T) {
	a := newAppliance(t)
	a.addUser("alice", "admin")
	a.enrollAndAuthenticate("alice")
	if code, _, stderr := a.run("policy", "apply", "regulated",
		"--justify", "moving the pilot to regulated"); code != ExitOK {
		t.Fatalf("apply regulated: %d %s", code, stderr)
	}

	shown := a.code("alice")
	if code, _, stderr := a.run("user", "add", "bob", "--role", "user",
		"--justify", "onboarding the new operator", "--totp", shown); code != ExitOK {
		t.Fatalf("a correct code was refused: %d %s", code, stderr)
	}

	// The same code again, for a different act, must not work.
	code, _, stderr := a.run("user", "add", "carol", "--role", "user",
		"--justify", "onboarding another operator", "--totp", shown)
	if code != ExitAuth {
		t.Errorf("a spent code authorized a second act: exit = %d, want %d\n%s", code, ExitAuth, stderr)
	}
}

// R1-29: the codes are a contract a script depends on, so they are asserted as
// a table rather than one at a time. Every code docs/specs/10-cli.md §5 defines
// and R1 can produce appears here; 6 does not, because R1 has no control plane
// to be unable to reach.
func TestExitCodesAreDistinguishableWithoutParsingStderr(t *testing.T) {
	a := newAppliance(t)
	a.addUser("alice", "admin")

	for _, tc := range []struct {
		name string
		args []string
		want int
	}{
		{"success", []string{"user", "add", "bob", "--role", "user"}, ExitOK},
		{"unknown flag", []string{"user", "add", "bob", "--nonesuch"}, ExitUsage},
		{"no such user", []string{"user", "suspend", "nobody"}, ExitFailure},
		{"name already taken", []string{"user", "add", "bob", "--role", "user"}, ExitPrecondition},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if code, _, stderr := a.run(tc.args...); code != tc.want {
				t.Errorf("exit = %d, want %d: %s", code, tc.want, stderr)
			}
		})
	}

	// 5 needs a profile that refuses, and 3 needs a credential that fails.
	if code, _, stderr := a.run("policy", "apply", "regulated"); code != ExitOK {
		t.Fatalf("apply regulated: %d %s", code, stderr)
	}
	if code, _, stderr := a.run("user", "add", "carol", "--role", "user"); code != ExitPolicy {
		t.Errorf("policy refusal exited %d, want %d: %s", code, ExitPolicy, stderr)
	}
}

// docs/specs/10-cli.md §4: --format json emits a stable schema to stdout and
// nothing else, so it can be piped without filtering. Asserted across every R1
// verb that offers it, because one verb getting this wrong breaks scripts that
// only ever touch that verb.
func TestJSONOutputIsAlwaysASingleDocumentOnStdout(t *testing.T) {
	a := newAppliance(t)
	a.addUser("alice", "admin")
	a.run("token", "create", "--user", "alice")

	for _, args := range [][]string{
		{"user", "list"}, {"user", "show", "alice"},
		{"token", "list"}, {"audit", "list"},
		{"policy", "show"}, {"policy", "diff", "regulated"},
		{"user", "add", "bob", "--role", "user"},
	} {
		name := strings.Join(args[:2], " ")
		t.Run(name, func(t *testing.T) {
			code, stdout, _ := a.run(append(args, "--format", "json")...)
			if code != ExitOK {
				t.Fatalf("exit = %d", code)
			}
			var doc any
			if err := json.Unmarshal([]byte(stdout), &doc); err != nil {
				t.Errorf("stdout is not one JSON document: %v\n%s", err, stdout)
			}
		})
	}
}

// docs/specs/10-cli.md §4: secrets are printed once at creation and never
// appear in a listing, in any format.
func TestNoListingEverCarriesASecret(t *testing.T) {
	a := newAppliance(t)
	a.addUser("alice", "admin")

	_, plaintext, _ := a.run("token", "create", "--user", "alice")
	secret := strings.TrimSpace(plaintext)
	if len(secret) < 20 {
		t.Fatalf("no credential was printed: %q", plaintext)
	}

	for _, args := range [][]string{
		{"token", "list"}, {"token", "list", "--format", "json"},
		{"audit", "list"}, {"audit", "list", "--format", "json"},
		{"user", "list", "--format", "json"},
	} {
		_, stdout, stderr := a.run(args...)
		if strings.Contains(stdout+stderr, secret) {
			t.Errorf("%v leaked the credential", args)
		}
	}
}
