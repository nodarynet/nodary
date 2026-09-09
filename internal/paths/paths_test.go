package paths

import (
	"os"
	"testing"
)

// The literal paths are a contract with the specs, with install.sh, and with
// every operator who has backed one of them up. A typo here writes state
// somewhere nobody looks, so they are asserted rather than assumed.
func TestLocationsMatchTheSpecs(t *testing.T) {
	for _, tc := range []struct {
		name string
		got  string
		want string
	}{
		{"database", Database(), "/var/lib/nodary/nodary.db"},
		{"secret key", SecretKey(), "/etc/nodary/secret.key"},
		{"audit mirror", AuditLog(), "/var/log/nodary/audit.jsonl"},
	} {
		if tc.got != tc.want {
			t.Errorf("%s = %q, want %q", tc.name, tc.got, tc.want)
		}
	}
}

// Every mode below protects something whose disclosure is unrecoverable: the
// key that decrypts every TOTP seed, the audit mirror, the operator's token.
// Widening one is the kind of change that passes review by looking like a
// formatting fix, so the property is pinned instead of the digits.
//
// DataDir is deliberately absent from this list — see
// TestDataDirGrantsOnlyGroupTraverse — because it is the one directory here
// that is not itself the secret: the database and its -wal/-shm sidecars are
// independently chmod'd to ModeDatabase on every open regardless of what the
// directory allows (internal/store/store.go's restrictPermissions), so a bit
// here is defense in depth, not the guard.
func TestModesExcludeGroupAndOther(t *testing.T) {
	for _, tc := range []struct {
		name string
		mode os.FileMode
	}{
		{"LogDir", ModeLogDir},
		{"Database", ModeDatabase},
		{"SecretKey", ModeSecretKey},
		{"AuditLog", ModeAuditLog},
		{"Credentials", ModeCredentials},
	} {
		if tc.mode&0o077 != 0 {
			t.Errorf("%s = %#o, grants access beyond the owner", tc.name, tc.mode)
		}
	}
}

// TestDataDirGrantsOnlyGroupTraverse pins DataDir's one deliberate exception
// to the rule above: group *execute*, so a member of the service account's
// group can pass through to `models/` (0755 in Layout, and meant to be
// written by an operator per docs/specs/05-catalog.md §3) without being able
// to list the directory or reach anything else in it. Pinned to exactly that
// bit so a future change that also grants group *read* — which would make the
// directory listable, though still not the database, whose own mode holds
// regardless — has to edit this test to know it moved.
func TestDataDirGrantsOnlyGroupTraverse(t *testing.T) {
	if got := ModeDataDir & 0o077; got != 0o010 {
		t.Errorf("ModeDataDir grants %#o beyond the owner, want exactly group-execute (0010)", got)
	}
}

// The secret key is read, never written after creation. 08 §4 says 0400 root,
// and a writable key is one an attacker can replace rather than merely read.
func TestSecretKeyIsReadOnly(t *testing.T) {
	if ModeSecretKey != 0o400 {
		t.Errorf("ModeSecretKey = %#o, want 0400 (docs/specs/08-data-model.md §4)", ModeSecretKey)
	}
}

func TestCredentialsFollowsHome(t *testing.T) {
	t.Setenv("HOME", "/home/example")
	got, err := Credentials()
	if err != nil {
		t.Fatalf("Credentials() error: %v", err)
	}
	if want := "/home/example/.nodary/credentials"; got != want {
		t.Errorf("Credentials() = %q, want %q", got, want)
	}
}

// Reported rather than guessed at: a fabricated fallback path would write an
// operator's token somewhere they never chose.
func TestCredentialsWithoutHomeIsAnError(t *testing.T) {
	t.Setenv("HOME", "")
	if got, err := Credentials(); err == nil {
		t.Errorf("Credentials() = %q with no HOME, want an error", got)
	}
}
