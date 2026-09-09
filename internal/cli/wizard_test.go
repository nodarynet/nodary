package cli

import (
	"bufio"
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// wizardEnv builds the env dispatch() would, minus the dispatch — the wizard
// methods are exercised directly here, one level below cmdInstall, so the
// database and models directory can be pointed into a temp tree without also
// working around --with-node's refusal to combine with --root (it needs a
// running control plane to enroll into, and a staged install starts nothing).
func wizardEnv(script string) (env, *bytes.Buffer, *bytes.Buffer) {
	var out, errb bytes.Buffer
	r := strings.NewReader(script)
	return env{stdin: r, in: bufio.NewReader(r), stdout: &out, stderr: &errb, tty: true}, &out, &errb
}

func TestWizardStringReadsAnAnswerOrFallsBackToTheDefault(t *testing.T) {
	e, out, _ := wizardEnv("custom\n\n")
	w := &wizard{e: e}
	if got := w.string("Q", "def"); got != "custom" {
		t.Errorf("got %q, want the typed answer", got)
	}
	if got := w.string("Q", "def"); got != "def" {
		t.Errorf("got %q, want the default on a blank line", got)
	}
	if !strings.Contains(out.String(), "Q [def]: ") {
		t.Errorf("the default is not shown in the prompt: %s", out.String())
	}
}

func TestWizardYesNoRespectsItsDefault(t *testing.T) {
	e, _, _ := wizardEnv("\nn\ny\nnonsense\n")
	w := &wizard{e: e}
	if !w.yesNo("Q", true) {
		t.Error("a blank line did not take the [Y/n] default")
	}
	if w.yesNo("Q", true) {
		t.Error("\"n\" was not read as no")
	}
	if !w.yesNo("Q", false) {
		t.Error("\"y\" was not read as yes")
	}
	if w.yesNo("Q", true) {
		t.Error("an unrecognized answer was read as yes")
	}
}

func TestWizardChoiceParsesANumberAndDefaultsToTheFirstOption(t *testing.T) {
	opts := []string{"a", "b", "c"}
	e, out, _ := wizardEnv("2\n\nbogus\n1\n")
	w := &wizard{e: e}
	if got := w.choice("Q", opts); got != 1 {
		t.Errorf("choice(\"2\") = %d, want 1", got)
	}
	if got := w.choice("Q", opts); got != 0 {
		t.Errorf("a blank line = %d, want the first option (0)", got)
	}
	// "bogus" re-prompts rather than silently defaulting — the next real
	// answer, "1", is what choice() should return.
	if got := w.choice("Q", opts); got != 0 {
		t.Errorf("choice() after a bad answer = %d, want 0", got)
	}
	if !strings.Contains(out.String(), "please enter a number") {
		t.Errorf("a bad answer was not told so: %s", out.String())
	}
}

// TestWizardWalksApproveStageRegisterGrantAndKey is the wizard's whole reason
// to exist, checked end to end: a pending node, answered through in plain
// yes/no/value prompts, ends up approved, its model registered with a real
// manifest, the route granted, a user created, and a service key printed —
// each step the same verb an operator would otherwise have had to remember
// the flags for.
func TestWizardWalksApproveStageRegisterGrantAndKey(t *testing.T) {
	a := newAppliance(t)
	a.enrolled("fractal")

	models := t.TempDir()
	dir := filepath.Join(models, "hub", "models--acme--tiny")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "config.json"), []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}

	script := strings.Join([]string{
		"y",         // approve fractal now?
		"y",         // stage and register a model now?
		"acme/tiny", // model
		"0",         // gpu
		"8001",      // port
		"y",         // create a user?
		"alice",     // name
		"operator",  // role
		"y",         // mint a service key?
	}, "\n") + "\n"

	e, out, errOut := wizardEnv(script)
	w := &wizard{e: e, db: a.db, key: a.key, modelsDir: models}
	if code := w.afterEnroll(); code != ExitOK {
		t.Fatalf("afterEnroll: exit %d\nstdout: %s\nstderr: %s", code, out, errOut)
	}

	if !strings.Contains(out.String(), "nodary_sk_") {
		t.Errorf("no service key was printed:\n%s", out.String())
	}

	if code, show, _ := a.run("node", "show", "fractal"); code != ExitOK || !strings.Contains(show, "approved") {
		t.Errorf("the node was not approved: %d\n%s", code, show)
	}
	code, cfg, _ := a.run("config", "show", "--format", "json")
	if code != ExitOK {
		t.Fatalf("config show: %d", code)
	}
	for _, want := range []string{`"acme/tiny"`, `"alice"`} {
		if !strings.Contains(cfg, want) {
			t.Errorf("config show does not mention %s:\n%s", want, cfg)
		}
	}
}

// A "no" at the first question leaves the node exactly as it was, and says
// what to run instead of trying to guess.
func TestWizardDeclinedApprovalLeavesTheNodePendingAndSaysWhatToRunInstead(t *testing.T) {
	a := newAppliance(t)
	a.enrolled("fractal")

	e, _, errOut := wizardEnv("n\n")
	w := &wizard{e: e, db: a.db, key: a.key}
	if code := w.afterEnroll(); code != ExitOK {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	if !strings.Contains(errOut.String(), "nodary node approve fractal") {
		t.Errorf("did not say how to approve it later:\n%s", errOut.String())
	}
	if code, show, _ := a.run("node", "show", "fractal"); code != ExitOK || strings.Contains(show, "state        approved") {
		t.Errorf("the node was approved despite a \"no\":\n%s", show)
	}
}

func TestWizardMoreThanOnePendingNodeRefusesToGuess(t *testing.T) {
	a := newAppliance(t)
	a.enrolled("fractal")
	a.enrolled("brook")

	e, _, errOut := wizardEnv("")
	w := &wizard{e: e, db: a.db, key: a.key}
	if code := w.afterEnroll(); code != ExitOK {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	if !strings.Contains(errOut.String(), "More than one node is pending") {
		t.Errorf("did not say why it stopped:\n%s", errOut.String())
	}
}

func TestInstallRefusesWhenNobodyCanAnswer(t *testing.T) {
	code, stdout, stderr := run(t, "install")
	if code != ExitUsage {
		t.Fatalf("exit = %d, want %d", code, ExitUsage)
	}
	if stdout != "" {
		t.Errorf("wrote to stdout with nobody to prompt: %q", stdout)
	}
	if !strings.Contains(stderr, "server install") || !strings.Contains(stderr, "node install") {
		t.Errorf("did not name the scriptable verbs instead: %s", stderr)
	}
}

// TestInstallControlPlaneOnlyDoesNotTryToEnroll is cmdInstall itself, not just
// afterEnroll below it: choosing "control plane only" has to route to
// server(false) and stop there rather than trying to approve a node that was
// never enrolled.
func TestInstallControlPlaneOnlyDoesNotTryToEnroll(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("NODARY_AUDIT_SINKS", "none")
	script := strings.Join([]string{
		"2",         // control plane only
		"127.0.0.1", // host
	}, "\n") + "\n"

	code, _, stderr := runInteractive(t, script, "install",
		"--root", dir, "--skip-preflight",
		"--db", filepath.Join(dir, "nodary.db"), "--secret-key", filepath.Join(dir, "secret.key"))
	if code != ExitOK {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	if !strings.Contains(stderr, "On each GPU host") {
		t.Errorf("did not say what comes next for a control-plane-only install:\n%s", stderr)
	}
	if strings.Contains(stderr, "Approve") {
		t.Errorf("tried to approve a node that was never enrolled:\n%s", stderr)
	}
}
