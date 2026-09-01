package cli

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nodarynet/nodary/internal/audit"
	"github.com/nodarynet/nodary/internal/identity"
)

// appliance is the state a command operates on: a database, an at-rest key and
// a credentials file, all under a temporary directory.
type appliance struct {
	t     *testing.T
	dir   string
	db    string
	key   string
	creds string
}

func newAppliance(t *testing.T) *appliance {
	t.Helper()
	// Otherwise every session tries to deliver to /var/log/nodary and warns on
	// the stream these tests read.
	t.Setenv(audit.SinksEnv, "none")
	dir := t.TempDir()
	return &appliance{
		t:     t,
		dir:   dir,
		db:    filepath.Join(dir, "nodary.db"),
		key:   filepath.Join(dir, "secret.key"),
		creds: filepath.Join(dir, "credentials"),
	}
}

// where returns the flags that point a command at this appliance.
func (a *appliance) where() []string {
	return []string{"--db", a.db, "--secret-key", a.key, "--credentials", a.creds}
}

// readOnly names the subcommands that never write, and so take only --db.
var readOnly = map[string]bool{"list": true, "show": true}

func (a *appliance) whereFor(sub string) []string {
	if readOnly[sub] {
		return []string{"--db", a.db}
	}
	return a.where()
}

// run invokes a command against this appliance, inserting the state flags
// after the verb and its subcommand.
func (a *appliance) run(args ...string) (int, string, string) {
	a.t.Helper()
	return a.runWithStdin("", args...)
}

func (a *appliance) runWithStdin(stdin string, args ...string) (int, string, string) {
	a.t.Helper()
	full := append(append([]string{}, args[:2]...), a.whereFor(args[1])...)
	full = append(full, args[2:]...)
	return runWithStdin(a.t, stdin, full...)
}

// addUser creates a user and fails the test if it does not work.
func (a *appliance) addUser(name, role string) {
	a.t.Helper()
	code, _, stderr := a.run("user", "add", "--role", role, name)
	if code != ExitOK {
		a.t.Fatalf("user add %s: exit %d, %s", name, code, stderr)
	}
}

func TestUserAddListShow(t *testing.T) {
	a := newAppliance(t)

	// The role flag comes after the name, which is how an operator types it and
	// which Go's flag package would otherwise ignore.
	code, stdout, stderr := a.run("user", "add", "alice", "--role", "operator",
		"--email", "alice@example.test", "--justify", "onboarding")
	if code != ExitOK {
		t.Fatalf("exit = %d, want 0: %s", code, stderr)
	}
	if !strings.Contains(stdout, "alice") || !strings.Contains(stdout, "operator") {
		t.Errorf("stdout = %q", stdout)
	}
	// The record's sequence number is progress information, so it belongs on
	// stderr and must not pollute a captured stdout.
	if !strings.Contains(stderr, "audit record") {
		t.Errorf("stderr should name the audit record: %q", stderr)
	}

	a.addUser("bob", "viewer")

	code, stdout, stderr = a.run("user", "list")
	if code != ExitOK {
		t.Fatalf("list: exit = %d: %s", code, stderr)
	}
	for _, want := range []string{"NAME", "alice", "bob", "operator", "viewer"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("list output missing %q: %q", want, stdout)
		}
	}

	code, stdout, _ = a.run("user", "show", "alice", "--format", "json")
	if code != ExitOK {
		t.Fatalf("show: exit = %d", code)
	}
	var doc struct {
		User   userReport    `json:"user"`
		Tokens []tokenReport `json:"tokens"`
	}
	if err := json.Unmarshal([]byte(stdout), &doc); err != nil {
		t.Fatalf("show json: %v in %q", err, stdout)
	}
	if doc.User.Name != "alice" || doc.User.Role != "operator" || doc.User.State != "active" {
		t.Errorf("user = %+v", doc.User)
	}
	if doc.User.Email != "alice@example.test" || doc.User.TOTPEnrolled {
		t.Errorf("user = %+v", doc.User)
	}
}

func TestUserAddRejectsAnUnknownRoleWithExitTwo(t *testing.T) {
	a := newAppliance(t)
	code, stdout, stderr := a.run("user", "add", "alice", "--role", "root")
	if code != ExitUsage {
		t.Fatalf("exit = %d, want %d", code, ExitUsage)
	}
	if stdout != "" {
		t.Errorf("a usage error wrote to stdout: %q", stdout)
	}
	if !strings.Contains(stderr, "root") {
		t.Errorf("stderr should name the bad role: %q", stderr)
	}
}

func TestUserStateTransitions(t *testing.T) {
	a := newAppliance(t)
	a.addUser("alice", "user")

	if code, _, stderr := a.run("user", "suspend", "alice"); code != ExitOK {
		t.Fatalf("suspend: exit = %d: %s", code, stderr)
	}
	// A forbidden transition is a precondition failure, not a general one:
	// docs/specs/10-cli.md §5 makes that distinguishable without reading text.
	code, _, stderr := a.run("user", "suspend", "alice")
	if code != ExitPrecondition {
		t.Fatalf("second suspend: exit = %d, want %d: %s", code, ExitPrecondition, stderr)
	}
	if code, _, stderr := a.run("user", "delete", "alice"); code != ExitOK {
		t.Fatalf("delete: exit = %d: %s", code, stderr)
	}

	code, stdout, _ := a.run("user", "list")
	if code != ExitOK || strings.Contains(stdout, "alice") {
		t.Errorf("a deleted user is still listed: %q", stdout)
	}
	code, stdout, _ = a.run("user", "list", "--all")
	if code != ExitOK || !strings.Contains(stdout, "alice") {
		t.Errorf("--all does not show a deleted user: %q", stdout)
	}
}

func TestUserPasswdSaysItIsNotInThisRelease(t *testing.T) {
	a := newAppliance(t)
	code, stdout, stderr := a.run("user", "passwd", "alice")
	if code != ExitFailure {
		t.Errorf("exit = %d, want %d", code, ExitFailure)
	}
	if stdout != "" {
		t.Errorf("stdout = %q, want nothing", stdout)
	}
	// Saying what to use instead is the difference between a user waiting and
	// a user filing a bug.
	if !strings.Contains(stderr, "token create") {
		t.Errorf("stderr should point at the alternative: %q", stderr)
	}
}

// TestTOTPEnrollmentPrintsTheSeedAloneOnStdout is R1-19 plus
// docs/specs/10-cli.md §4: the secret has to be capturable with no decoration
// to strip.
func TestTOTPEnrollmentPrintsTheSeedAloneOnStdout(t *testing.T) {
	a := newAppliance(t)
	a.addUser("alice", "operator")

	// The seed is printed before the code is asked for, so the confirming code
	// has to be piped in ahead of seeing it. A wrong one first: nothing may be
	// enrolled by a failed confirmation.
	code, stdout, stderr := a.runWithStdin("000000\n", "user", "totp", "alice")
	if code != ExitAuth {
		t.Fatalf("wrong code: exit = %d, want %d: %s", code, ExitAuth, stderr)
	}
	seed := strings.TrimSpace(stdout)
	if len(seed) != 32 {
		t.Fatalf("stdout should be the seed alone, got %q", stdout)
	}
	if strings.Contains(stdout, "otpauth") || strings.Contains(stdout, "authenticator") {
		t.Errorf("stdout carries decoration around the secret: %q", stdout)
	}
	// The provisioning URI is the human-facing form and belongs with the
	// prompt, on the human-facing stream.
	if !strings.Contains(stderr, "otpauth://totp/") {
		t.Errorf("stderr should carry the provisioning URI: %q", stderr)
	}

	code, stdout, _ = a.run("user", "show", "alice", "--format", "json")
	if code != ExitOK {
		t.Fatal(code)
	}
	if strings.Contains(stdout, seed) {
		t.Error("a refused enrollment left the seed readable")
	}
	var doc struct {
		User userReport `json:"user"`
	}
	if err := json.Unmarshal([]byte(stdout), &doc); err != nil {
		t.Fatal(err)
	}
	if doc.User.TOTPEnrolled {
		t.Error("a refused enrollment was recorded")
	}
}

func TestASealedSeedNeverAppearsInOutput(t *testing.T) {
	a := newAppliance(t)
	a.addUser("alice", "operator")

	// Enroll for real, by generating the code from the seed the command prints.
	// Two passes: the first to learn the seed, the second to confirm it.
	seed := enrollTOTP(t, a, "alice")

	code, stdout, _ := a.run("user", "show", "alice", "--format", "json")
	if code != ExitOK {
		t.Fatal(code)
	}
	if strings.Contains(stdout, seed) {
		t.Error("show carries the TOTP seed")
	}
	var doc struct {
		User userReport `json:"user"`
	}
	if err := json.Unmarshal([]byte(stdout), &doc); err != nil {
		t.Fatal(err)
	}
	if !doc.User.TOTPEnrolled {
		t.Error("enrollment was not recorded")
	}

	_, stdout, _ = a.run("user", "list", "--format", "json")
	if strings.Contains(stdout, seed) {
		t.Error("list carries the TOTP seed")
	}
}

// TestTheKeyBindingRefusesAMissingKey is R1-36 through the CLI: deleting
// secret.key must stop the appliance rather than quietly minting a new one.
func TestTheKeyBindingRefusesAMissingKey(t *testing.T) {
	a := newAppliance(t)
	a.addUser("alice", "operator")
	enrollTOTP(t, a, "alice")

	if err := os.Remove(a.key); err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr := a.run("user", "add", "bob", "--role", "viewer")
	if code != ExitFailure {
		t.Fatalf("exit = %d, want %d", code, ExitFailure)
	}
	if stdout != "" {
		t.Errorf("stdout = %q, want nothing", stdout)
	}
	for _, want := range []string{"sealed", "backup", "unreadable"} {
		if !strings.Contains(stderr, want) {
			t.Errorf("stderr should mention %q: %q", want, stderr)
		}
	}

	// A different key is refused too, and names both ids rather than
	// replacing anything.
	if err := os.WriteFile(a.key, []byte(strings.Repeat("0", 64)+"\n"), 0o400); err != nil {
		t.Fatal(err)
	}
	code, _, stderr = a.run("user", "add", "bob", "--role", "viewer")
	if code == ExitOK {
		t.Fatalf("a stranger key was accepted: %s", stderr)
	}
	if !strings.Contains(stderr, "sealed under a different key") {
		t.Errorf("stderr should name the mismatch: %q", stderr)
	}

	// Reading still works, and deliberately: a read-only command is how an
	// operator diagnoses this, so blocking one would remove the tool they need
	// exactly when they need it. Refusing the mutation is the load-bearing
	// half — it stops a new secret being sealed under a key that cannot read
	// the old ones.
	if code, stdout, _ := a.run("user", "list"); code != ExitOK ||
		!strings.Contains(stdout, "alice") {
		t.Errorf("reading was blocked by the key mismatch: exit %d, %q", code, stdout)
	}
}

// enrollTOTP drives the interactive enrollment: it reads the seed the command
// prints, computes the code an authenticator would show, and answers with it.
//
// Through real pipes, because that is the contract. The seed is displayed
// before the code is asked for — deliberately, so a mis-scanned QR cannot
// silently lock an account out — which means no canned stdin can ever confirm
// an enrollment. A test that could would be testing a different command.
func enrollTOTP(t *testing.T, a *appliance, name string) string {
	t.Helper()

	stdinR, stdinW := io.Pipe()
	stdoutR, stdoutW := io.Pipe()
	var stderr bytes.Buffer

	args := append(append([]string{"user", "totp"}, a.where()...), name)
	done := make(chan int, 1)
	go func() {
		code := Main(args, stdinR, stdoutW, &stderr)
		stdoutW.Close()
		done <- code
	}()

	// Bounded, because the failure this helper is most likely to meet is the
	// command not printing a seed at all — at which point it is blocked
	// reading stdin and this is blocked reading stdout. A deadlocked test
	// costs the whole CI timeout and reports nothing useful.
	type read struct {
		line string
		err  error
	}
	lines := make(chan read, 1)
	go func() {
		l, err := bufio.NewReader(stdoutR).ReadString('\n')
		lines <- read{l, err}
	}()

	var line string
	select {
	case got := <-lines:
		if got.err != nil {
			stdinW.Close()
			t.Fatalf("reading the seed: %v (stderr: %s)", got.err, stderr.String())
		}
		line = got.line
	case <-time.After(10 * time.Second):
		stdinW.Close()
		stdoutR.Close()
		t.Fatalf("no seed reached stdout before the code was asked for (stderr: %s)",
			stderr.String())
	}
	seed, err := identity.DecodeSeed(line)
	if err != nil {
		t.Fatalf("the command printed %q, which is not a seed: %v", line, err)
	}

	if _, err := io.WriteString(stdinW, identity.Code(seed, time.Now())+"\n"); err != nil {
		t.Fatalf("answering with the code: %v", err)
	}
	stdinW.Close()
	io.Copy(io.Discard, stdoutR)

	if code := <-done; code != ExitOK {
		t.Fatalf("enrolling %s: exit %d: %s", name, code, stderr.String())
	}
	return strings.TrimSpace(line)
}

// TestANamedCredentialsFileThatYieldsNothingSaysSo: a typo in --credentials
// would otherwise be silent. It changes attribution rather than authority —
// the record says "local" either way — but silence is the wrong answer when an
// operator asked to act as somebody.
func TestANamedCredentialsFileThatYieldsNothingSaysSo(t *testing.T) {
	a := newAppliance(t)
	code, _, stderr := a.run("user", "add", "alice", "--role", "admin")
	if code != ExitOK {
		t.Fatalf("exit = %d: %s", code, stderr)
	}
	if !strings.Contains(stderr, "acting locally") {
		t.Errorf("stderr should say the named file yielded nothing: %q", stderr)
	}

	// Once a credential is there, the notice stops.
	if code, _, stderr := a.run("token", "create", "--user", "alice", "--save"); code != ExitOK {
		t.Fatalf("exit = %d: %s", code, stderr)
	}
	_, _, stderr = a.run("user", "add", "bob", "--role", "viewer")
	if strings.Contains(stderr, "acting locally") {
		t.Errorf("the notice survived a working credential: %q", stderr)
	}
}

// TestTheDefaultCredentialsPathIsQuiet: an appliance with no credentials file
// is the ordinary case, and saying so on every command would train operators
// to ignore the line that matters when they did name a file.
func TestTheDefaultCredentialsPathIsQuiet(t *testing.T) {
	a := newAppliance(t)
	// os.UserHomeDir reads HOME, so the default path lands inside the test's
	// own directory rather than the developer's.
	t.Setenv("HOME", a.dir)

	code, _, stderr := run(t, "user", "add", "--db", a.db, "--secret-key", a.key,
		"alice", "--role", "admin")
	if code != ExitOK {
		t.Fatalf("exit = %d: %s", code, stderr)
	}
	if strings.Contains(stderr, "acting locally") {
		t.Errorf("the default path reported itself: %q", stderr)
	}
}
