package preflight

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeWSL builds a tree that reads as a WSL2 host, so these checks can be
// driven on a machine that is not one — and, more usefully, on one that is,
// without the answer depending on the developer's own Windows profile.
func fakeWSL(t *testing.T) hostFS {
	t.Helper()
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "proc/sys/kernel"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "proc/sys/kernel/osrelease"),
		[]byte("6.6.87.2-microsoft-standard-WSL2\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return hostFS{root: root}
}

// 01 §8: the models directory must never be under /mnt/c, where 9p makes
// staging pathologically slow. The symptom is a download that crawls on a
// machine whose network is fine, which reads as a problem with the mirror.
func TestWeightsOnTheWindowsFilesystemAreAWarning(t *testing.T) {
	h := fakeWSL(t)
	if got := checkWSLModelsDir(Options{ModelsDir: "/mnt/c/models"}, h); got.Level != LevelWarn {
		t.Errorf("/mnt/c/models is %q, want a warning: %s", got.Level, got.Detail)
	}
	if got := checkWSLModelsDir(Options{ModelsDir: "/var/lib/nodary/models"}, h); got.Level != LevelOK {
		t.Errorf("a path on the distribution's own disk is %q: %s", got.Level, got.Detail)
	}
	// `/mnt` is the trap and `/mnterrific` is not: the prefix has to be a path
	// boundary or every directory starting with those four letters is warned
	// about.
	if got := checkWSLModelsDir(Options{ModelsDir: "/mnterrific/models"}, h); got.Level != LevelOK {
		t.Errorf("/mnterrific was matched as /mnt: %q %s", got.Level, got.Detail)
	}
	// And none of it applies to a host that is not WSL2.
	if got := checkWSLModelsDir(Options{ModelsDir: "/mnt/c/models"}, hostFS{root: t.TempDir()}); got.Level != LevelSkip {
		t.Errorf("a non-WSL host was warned about /mnt: %q", got.Level)
	}
}

// WSL2 caps the VM near half the host's RAM unless .wslconfig says otherwise,
// which on a 64GB workstation is 32GB — enough to look fine, and not enough for
// the model somebody sized against the machine they bought.
func TestAVMWithNoExplicitMemoryCapIsAWarning(t *testing.T) {
	h := fakeWSL(t)
	if got := checkWSLMemory(h); got.Level != LevelWarn {
		t.Errorf("no .wslconfig reads %q, want a warning: %s", got.Level, got.Detail)
	}

	profile := filepath.Join(h.root, "mnt/c/Users/aweng")
	if err := os.MkdirAll(profile, 0o755); err != nil {
		t.Fatal(err)
	}
	// Both spellings WSL accepts, because a check that knew only one would warn
	// about a machine that is already configured.
	for _, body := range []string{"[wsl2]\nmemory=64GB\n", "[wsl2]\nmemory = 64GB\n"} {
		if err := os.WriteFile(filepath.Join(profile, ".wslconfig"), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		if got := checkWSLMemory(h); got.Level != LevelOK {
			t.Errorf("%q reads %q, want ok: %s", strings.TrimSpace(body), got.Level, got.Detail)
		}
	}

	// A file that exists and sets something else is not an answer.
	if err := os.WriteFile(filepath.Join(profile, ".wslconfig"), []byte("[wsl2]\nprocessors=8\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := checkWSLMemory(h); got.Level != LevelWarn {
		t.Errorf("a .wslconfig with no memory= reads %q, want a warning", got.Level)
	}
}
