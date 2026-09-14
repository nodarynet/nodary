package scripts

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// install.sh's whole job is download-and-verify, so `--offline` is the one mode
// where it has nothing to do but hand over — and handing over to whatever
// binary happens to be lying on the box is exactly the failure the release
// signature exists to prevent. These pin both halves of that: it refuses when
// there is nothing placed, and it execs the placed binary when there is.
func TestInstallScriptOffline(t *testing.T) {
	if _, err := os.Stat("/run/systemd/system"); err != nil {
		// check_role_supported refuses `server` without systemd, long before
		// the offline branch, and that refusal has its own reason.
		t.Skip("no systemd on this host, so the script refuses the role first")
	}
	script, err := filepath.Abs(filepath.Join("..", "install.sh"))
	if err != nil {
		t.Fatal(err)
	}

	run := func(t *testing.T, prefix string, args ...string) (string, error) {
		t.Helper()
		cmd := exec.Command("sh", append([]string{script}, args...)...)
		cmd.Env = append(os.Environ(), "NODARY_PREFIX="+prefix, "NODARY_BIN_DIR="+prefix+"/bin")
		out, err := cmd.CombinedOutput()
		return string(out), err
	}

	t.Run("refuses when no binary is placed", func(t *testing.T) {
		out, err := run(t, t.TempDir(), "server", "--offline", "--bundle", "site.tar")
		if err == nil {
			t.Fatalf("an offline install ran with no binary on the host:\n%s", out)
		}
		// It has to say what to do, because the operator is standing at a
		// machine with no network and no way to look it up.
		for _, want := range []string{"--offline needs nodary already installed", "cp ./nodary"} {
			if !strings.Contains(out, want) {
				t.Errorf("the refusal does not say %q:\n%s", want, out)
			}
		}
	})

	t.Run("hands over to the placed binary", func(t *testing.T) {
		prefix := t.TempDir()
		dir := filepath.Join(prefix, "0.0.1")
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		// A stand-in that reports its argv, which is the contract under test.
		fake := filepath.Join(dir, "nodary")
		if err := os.WriteFile(fake, []byte("#!/bin/sh\necho \"ARGV: $*\"\n"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(dir, filepath.Join(prefix, "current")); err != nil {
			t.Fatal(err)
		}

		out, err := run(t, prefix, "server", "--offline", "--bundle", "site.tar")
		if err != nil {
			t.Fatalf("exit: %v\n%s", err, out)
		}
		// The role becomes a verb and every other flag is forwarded untouched,
		// including --offline: the binary needs to know too, or it would reach
		// for a network this host does not have.
		if !strings.Contains(out, "ARGV: server install --offline --bundle site.tar") {
			t.Errorf("wrong hand-off:\n%s", out)
		}
		// And nothing was downloaded, which is the point.
		if strings.Contains(out, "downloading") {
			t.Errorf("an offline install tried to download:\n%s", out)
		}
	})

	t.Run("still refuses an unsupported role", func(t *testing.T) {
		out, err := run(t, t.TempDir(), "nonesuch", "--offline")
		// `nonesuch` is not a role check_role_supported knows, so the script
		// hands it on; what must not happen is the offline branch inventing a
		// role of its own or accepting none at all.
		if err == nil && !strings.Contains(out, "ARGV:") {
			t.Errorf("unexpected success with no hand-off:\n%s", out)
		}
	})
}
