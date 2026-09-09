package install

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nodarynet/nodary/internal/paths"
)

// The units carry PrivateTmp=true and ProtectHome=true, so a binary under /tmp
// or /home is invisible to the service — systemd reports 203/EXEC, which says
// nothing about why.
//
// Measured directly on systemd 255: the same binary at /tmp/x with
// PrivateTmp=true exits 203, and with PrivateTmp=false exits 0. So the unit's
// ExecStart has to be a path that exists inside the service's namespace, which
// is what docs/specs/01-install.md §12 fixes at /opt/nodary/current/nodary.
func TestUnitsInvokeTheStablePathAndNotWhereverTheBinaryIs(t *testing.T) {
	for role, units := range map[string]map[string]string{
		"server": Units("server"), "node": Units("node"),
	} {
		for name, tmpl := range units {
			if !strings.Contains(tmpl, "%[1]s") {
				continue // containerd's unit, which is upstream's text
			}
			var o Options
			o.setDefaults()
			body := strings.ReplaceAll(tmpl, "%[1]s", o.Binary)
			if !strings.Contains(body, paths.Binary()) {
				t.Errorf("%s/%s invokes %q, want %s", role, name, o.Binary, paths.Binary())
			}
			for _, bad := range []string{"ExecStart=/tmp/", "ExecStart=/home/"} {
				if strings.Contains(body, bad) {
					t.Errorf("%s/%s invokes a path the service cannot see: %s", role, name, bad)
				}
			}
		}
	}
}

// The binary lands where 01 §12 says, and `current` points at it.
func TestEnsureBinaryPlacesAndLinks(t *testing.T) {
	root := t.TempDir()
	o := Options{Root: root}

	steps, stable, err := EnsureBinary("1.2.3", o)
	if err != nil {
		t.Fatal(err)
	}
	if len(steps) == 0 || !steps[0].Changed {
		t.Error("the first placement reported no change")
	}
	if stable != filepath.Join(root, paths.Binary()) {
		t.Errorf("stable path = %q", stable)
	}
	if _, err := os.Stat(filepath.Join(root, paths.VersionedBinary("1.2.3"))); err != nil {
		t.Errorf("the versioned binary is not there: %v", err)
	}
	target, err := os.Readlink(filepath.Join(root, paths.OptDir, "current"))
	if err != nil {
		t.Fatal(err)
	}
	if target != "1.2.3" {
		t.Errorf("current → %q, want 1.2.3", target)
	}

	// An upgrade flips one symlink and every unit follows without being
	// rewritten (01 §9).
	if _, _, err := EnsureBinary("1.2.4", o); err != nil {
		t.Fatal(err)
	}
	target, _ = os.Readlink(filepath.Join(root, paths.OptDir, "current"))
	if target != "1.2.4" {
		t.Errorf("after an upgrade current → %q, want 1.2.4", target)
	}
	// And the old version is still there, so a rollback is a symlink away.
	if _, err := os.Stat(filepath.Join(root, paths.VersionedBinary("1.2.3"))); err != nil {
		t.Errorf("the previous version was removed: %v", err)
	}
}

// TestTheSealingKeyIsNeverChownedAwayFromRoot pins the two halves of the
// arrangement together.
//
// 01 §12 keeps /etc/nodary/secret.key at 0400 root:root while the unit runs as
// an unprivileged account, which is only possible because the unit loads it as
// a systemd credential. Two ways to break that: drop the LoadCredential line,
// or add the key to what the install chowns. Either alone leaves a control
// plane that cannot read its own sealing key, or a sealing key readable by the
// network-facing process — and both look harmless in review.
func TestTheSealingKeyIsNeverChownedAwayFromRoot(t *testing.T) {
	for _, p := range serviceOwned {
		if p == paths.SecretKey() {
			t.Fatalf("the install chowns %s to the service account; 01 §12 says root:root", p)
		}
	}
	want := "LoadCredential=secret.key:" + paths.SecretKey()
	if !strings.Contains(serverUnit, want) {
		t.Errorf("nodary-server.service does not carry %q, so it cannot read the key it may not own", want)
	}
}

// TestTheInstalledBinaryIsOnPath is the gap every printed instruction depended
// on.
//
// 01 §12 puts the binary at /opt/nodary/current/nodary, which is on nobody's
// PATH. The install prints `nodary node approve …`, `nodary token join`,
// `nodary doctor` and a setup URL, and until this none of those were commands
// the operator could run. It went unnoticed because
// scripts/verify-privileged.sh invokes its own build out of /tmp.
func TestTheInstalledBinaryIsOnPath(t *testing.T) {
	root := t.TempDir()
	o := Options{Root: root}
	steps, _, err := EnsureBinary("1.0.0", o)
	if err != nil {
		t.Fatal(err)
	}
	// Reported as its own step, because the one case that matters most is the
	// one it declines to do: an existing file it must not replace.
	var named bool
	for _, s := range steps {
		if s.Name == "PATH" {
			named = true
		}
	}
	if !named {
		t.Error("the PATH link is not reported, so a refusal to replace one would be silent")
	}

	link := filepath.Join(root, "usr/local/bin/nodary")
	target, err := os.Readlink(link)
	if err != nil {
		t.Fatalf("nodary is not on PATH after an install: %v", err)
	}
	// At `current`, not at a version: an upgrade has to move both by moving one.
	if want := filepath.Join(root, paths.Binary()); target != want {
		t.Errorf("the link points at %q, want %q", target, want)
	}
	if _, err := os.Stat(link); err != nil {
		t.Errorf("the link does not resolve: %v", err)
	}

	// Idempotent, and it heals a run that placed the binary and not the link.
	if err := os.Remove(link); err != nil {
		t.Fatal(err)
	}
	if _, _, err := EnsureBinary("1.0.0", o); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Readlink(link); err != nil {
		t.Errorf("a re-run did not restore the link: %v", err)
	}
}

// TestAnExistingNodaryOnPathIsNotReplaced follows PlaceComponents' rule: what
// somebody else installed is theirs. A pip or npm wrapper puts a real file
// there, and removing it because the name matches would take down whatever they
// were using it for.
func TestAnExistingNodaryOnPathIsNotReplaced(t *testing.T) {
	root := t.TempDir()
	link := filepath.Join(root, "usr/local/bin/nodary")
	if err := os.MkdirAll(filepath.Dir(link), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(link, []byte("#!/bin/sh\necho somebody else's\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	step, err := linkOnPath(Options{Root: root, BinDir: "/usr/local/bin"})
	if err != nil {
		t.Fatal(err)
	}
	if step.Changed {
		t.Error("an existing binary was replaced")
	}
	if !strings.Contains(step.Detail, "not ours to replace") {
		t.Errorf("the report does not explain what was left alone: %q", step.Detail)
	}
	body, err := os.ReadFile(link)
	if err != nil || !strings.Contains(string(body), "somebody else") {
		t.Errorf("the existing file was modified: %v", err)
	}
}

// TestRestartActuallySaysRestart is Restart's whole reason to exist as a
// function separate from Start: `systemctl enable --now` on a unit that is
// already active is a no-op by systemd's own semantics, and `gateway sync`
// called exactly that after writing LiteLLM's first real route — reporting
// success, restarting nothing, and leaving the running process serving the
// empty model list it started with. The fix is the verb, so the verb is what
// this pins.
func TestRestartActuallySaysRestart(t *testing.T) {
	var got []string
	run := func(_ context.Context, name string, args ...string) ([]byte, error) {
		got = append(got, name+" "+strings.Join(args, " "))
		return nil, nil
	}
	step, err := Restart(context.Background(), "nodary-litellm.service", Options{Run: run})
	if err != nil {
		t.Fatal(err)
	}
	if !step.Changed {
		t.Error("Restart did not report a change")
	}
	want := "systemctl restart nodary-litellm.service"
	if len(got) != 1 || got[0] != want {
		t.Errorf("ran %v, want exactly [%q]", got, want)
	}
}

// A staged install has nothing running to restart, same as Start.
func TestRestartDoesNothingUnderRoot(t *testing.T) {
	called := false
	run := func(context.Context, string, ...string) ([]byte, error) {
		called = true
		return nil, nil
	}
	step, err := Restart(context.Background(), "nodary-litellm.service", Options{Run: run, Root: "/staged"})
	if err != nil {
		t.Fatal(err)
	}
	if called {
		t.Error("Restart ran systemctl against a staged install")
	}
	if step.Changed {
		t.Error("a staged install reported a change it did not make")
	}
}
