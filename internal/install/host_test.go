package install

import (
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

	step, stable, err := EnsureBinary("1.2.3", o)
	if err != nil {
		t.Fatal(err)
	}
	if !step.Changed {
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
