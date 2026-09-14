package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// R5-19: macOS builds are the operator CLI. `server install` there gets one
// sentence naming the requirement — not preflight's wall of consequences, where
// systemd and cgroup v2 are also reported and none of them is a thing the
// operator can do anything about.
func TestTheServerAndAgentInstallsRefuseANonLinuxHost(t *testing.T) {
	previous := goos
	goos = "darwin"
	t.Cleanup(func() { goos = previous })

	for _, verb := range [][]string{
		{"server", "install"},
		{"node", "install", "--server", "https://cp:8443", "--token", "t",
			"--ca-fingerprint", "sha256:aa"},
	} {
		code, _, stderr := run(t, append(verb, "--root", t.TempDir())...)
		if code == ExitOK {
			t.Fatalf("%v ran on darwin", verb)
		}
		if !strings.Contains(stderr, "requires Linux with systemd") {
			t.Errorf("%v does not name the requirement: %s", verb, stderr)
		}
		if !strings.Contains(stderr, "operator CLI only") {
			t.Errorf("%v does not say what the macOS build is for: %s", verb, stderr)
		}
		// One answer, not a list of the checks that fail because of it.
		if strings.Contains(stderr, "cgroup") {
			t.Errorf("%v reported the consequences instead of the cause: %s", verb, stderr)
		}
	}
}

// --skip-preflight skips the checks. It does not make this host Linux, and a
// flag that carried past here would reach a systemd call whose error names a
// missing binary rather than an unsupported platform.
func TestSkipPreflightDoesNotSkipThePlatform(t *testing.T) {
	previous := goos
	goos = "darwin"
	t.Cleanup(func() { goos = previous })

	code, _, stderr := run(t, "server", "install", "--root", t.TempDir(), "--skip-preflight")
	if code == ExitOK {
		t.Fatal("--skip-preflight installed a server on darwin")
	}
	if !strings.Contains(stderr, "requires Linux with systemd") {
		t.Errorf("the refusal was skipped with the checks: %s", stderr)
	}
}

// The script and the binary are two implementations of one sentence, and an
// operator who hits the refusal through `install.sh` and then by running the
// binary directly must not be told two different things.
func TestTheScriptAndTheBinaryRefuseInTheSameWords(t *testing.T) {
	body, err := os.ReadFile(filepath.Join("..", "..", "install.sh"))
	if err != nil {
		t.Fatal(err)
	}
	previous := goos
	goos = "darwin"
	t.Cleanup(func() { goos = previous })
	_, _, stderr := run(t, "server", "install", "--root", t.TempDir())

	for _, phrase := range []string{"requires Linux with systemd", "operator CLI only"} {
		if !strings.Contains(string(body), phrase) {
			t.Errorf("install.sh does not say %q", phrase)
		}
		if !strings.Contains(stderr, phrase) {
			t.Errorf("the binary does not say %q: %s", phrase, stderr)
		}
	}
}
