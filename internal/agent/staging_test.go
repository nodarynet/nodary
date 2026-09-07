package agent

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// stage lays out a model the way an operator carrying removable media would,
// and returns models_dir and the manifest's own digest.
func stage(t *testing.T, files map[string]string) (string, string) {
	t.Helper()
	root := t.TempDir()
	dir, err := ModelDir(root, "hf-cache", "acme/tiny")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}

	var manifest strings.Builder
	for name, body := range files {
		path := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256([]byte(body))
		// Two spaces: this is `sha256sum` output, so that an operator can
		// produce it and check it without nodary installed.
		manifest.WriteString(hex.EncodeToString(sum[:]) + "  " + name + "\n")
	}
	body := []byte(manifest.String())
	if err := os.WriteFile(filepath.Join(dir, ManifestName), body, 0o644); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(body)
	return root, hex.EncodeToString(sum[:])
}

func TestLocallyStagedWeightsVerify(t *testing.T) {
	root, digest := stage(t, map[string]string{
		"config.json":          `{"model_type":"tiny"}`,
		"blobs/model.safetens": "weights, allegedly",
	})
	got := VerifyStaged(root, "hf-cache", "acme/tiny", digest)
	if got.State != StateStaged {
		t.Fatalf("state = %s (%s), want staged", got.State, got.Reason)
	}
	if got.Files != 2 {
		t.Errorf("files = %d, want 2", got.Files)
	}
	if got.Bytes == 0 {
		t.Error("bytes = 0; nothing was actually read")
	}
}

// The manifest is checked before it is trusted. Without that, a manifest and
// the files it describes could have been replaced together and every file would
// verify against a digest list for the wrong weights.
func TestASwappedManifestIsCorruptEvenThoughEveryFileMatchesIt(t *testing.T) {
	root, _ := stage(t, map[string]string{"config.json": `{"model_type":"tiny"}`})
	pinned := strings.Repeat("a", 64) // what the catalog says, and it is not this

	got := VerifyStaged(root, "hf-cache", "acme/tiny", pinned)
	if got.State != StateCorrupt {
		t.Fatalf("state = %s, want corrupt", got.State)
	}
	if !strings.Contains(got.Reason, "catalog pins") {
		t.Errorf("reason = %q, want it to name the mismatch", got.Reason)
	}
}

func TestAChangedByteIsCorruptAndSaysWhich(t *testing.T) {
	root, digest := stage(t, map[string]string{
		"config.json": `{"model_type":"tiny"}`,
		"weights.bin": "0123456789",
	})
	dir, _ := ModelDir(root, "hf-cache", "acme/tiny")
	if err := os.WriteFile(filepath.Join(dir, "weights.bin"), []byte("0123456788"), 0o644); err != nil {
		t.Fatal(err)
	}

	got := VerifyStaged(root, "hf-cache", "acme/tiny", digest)
	if got.State != StateCorrupt {
		t.Fatalf("state = %s, want corrupt", got.State)
	}
	if !strings.Contains(got.Reason, "weights.bin") {
		t.Errorf("reason = %q, want it to name the file", got.Reason)
	}
	// 0006_fleet.sql's CHECK requires it, and a terminal state that does not
	// say what went wrong is how a corrupt artifact becomes a mystery.
	if got.Reason == "" {
		t.Error("corrupt with no reason")
	}
}

// A missing file is `absent`, not `corrupt`. `corrupt` is terminal and needs a
// human; weights that have not finished being copied do not.
func TestMissingWeightsAreAbsentAndNotCorrupt(t *testing.T) {
	root, digest := stage(t, map[string]string{"config.json": "{}", "weights.bin": "x"})
	dir, _ := ModelDir(root, "hf-cache", "acme/tiny")
	if err := os.Remove(filepath.Join(dir, "weights.bin")); err != nil {
		t.Fatal(err)
	}
	if got := VerifyStaged(root, "hf-cache", "acme/tiny", digest); got.State != StateAbsent {
		t.Errorf("state = %s (%s), want absent", got.State, got.Reason)
	}

	// So is a model directory nobody has created, and so is one with weights
	// but no manifest yet.
	if got := VerifyStaged(t.TempDir(), "hf-cache", "acme/tiny", digest); got.State != StateAbsent {
		t.Errorf("an empty models_dir: state = %s, want absent", got.State)
	}
	root2, _ := stage(t, map[string]string{"config.json": "{}"})
	dir2, _ := ModelDir(root2, "hf-cache", "acme/tiny")
	if err := os.Remove(filepath.Join(dir2, ManifestName)); err != nil {
		t.Fatal(err)
	}
	if got := VerifyStaged(root2, "hf-cache", "acme/tiny", ""); got.State != StateAbsent {
		t.Errorf("no manifest: state = %s, want absent", got.State)
	}
}

// A manifest is carried on removable media, so it is untrusted input. An entry
// that escapes the model directory would let it name a file elsewhere on the
// host and have that reported as staged weights.
func TestAManifestCannotNameAFileOutsideItsModelDirectory(t *testing.T) {
	root, _ := stage(t, map[string]string{"config.json": "{}"})
	dir, _ := ModelDir(root, "hf-cache", "acme/tiny")

	outside := filepath.Join(root, "elsewhere")
	if err := os.WriteFile(outside, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte("x"))
	body := []byte(hex.EncodeToString(sum[:]) + "  ../../elsewhere\n")
	if err := os.WriteFile(filepath.Join(dir, ManifestName), body, 0o644); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(body)

	got := VerifyStaged(root, "hf-cache", "acme/tiny", hex.EncodeToString(digest[:]))
	if got.State != StateCorrupt || !strings.Contains(got.Reason, "outside") {
		t.Errorf("state = %s (%s), want corrupt naming the escape", got.State, got.Reason)
	}
}

func TestParseManifestRefusesWhatIsNotOne(t *testing.T) {
	good := strings.Repeat("a", 64) + "  config.json\n"
	if _, err := ParseManifest([]byte(good)); err != nil {
		t.Fatalf("sha256sum output was refused: %v", err)
	}
	// One space, and a binary-mode star: both are real sha256sum dialects.
	if got, err := ParseManifest([]byte(strings.Repeat("b", 64) + " *weights.bin\n")); err != nil {
		t.Errorf("binary-mode output was refused: %v", err)
	} else if got[0].Path != "weights.bin" {
		t.Errorf("path = %q, want the star stripped", got[0].Path)
	}

	for _, tc := range []struct{ what, body string }{
		{"no digest", "config.json\n"},
		{"a short digest", strings.Repeat("a", 63) + "  config.json\n"},
		{"a digest that is not hex", strings.Repeat("z", 64) + "  config.json\n"},
		{"no filename", strings.Repeat("a", 64) + "  \n"},
		{"one file listed twice", good + strings.Repeat("b", 64) + "  config.json\n"},
	} {
		if _, err := ParseManifest([]byte(tc.body)); err == nil {
			t.Errorf("%s: accepted", tc.what)
		}
	}
}

func TestModelDirFollowsTheHuggingFaceLayout(t *testing.T) {
	// docs/specs/05-catalog.md §3: an existing cache is adopted rather than
	// copied into a layout of our own, so this path is not ours to choose.
	got, err := ModelDir("/var/lib/nodary/models", "hf-cache", "google/gemma-4-31b-it")
	if err != nil {
		t.Fatal(err)
	}
	want := "/var/lib/nodary/models/hub/models--google--gemma-4-31b-it"
	if got != want {
		t.Errorf("ModelDir = %q, want %q", got, want)
	}
	if _, err := ModelDir("/m", "tarball", "a/b"); err == nil {
		t.Error("an unknown layout was accepted")
	}
}

// The format claim, measured rather than assumed: a manifest produced by stock
// `sha256sum` verifies here, and one this package accepts verifies under
// `sha256sum -c`. An operator staging by hand needs nodary installed for
// neither half, which is the same property the evidence bundle has.
func TestTheManifestIsInteroperableWithStockSha256sum(t *testing.T) {
	if _, err := exec.LookPath("sha256sum"); err != nil {
		t.Skip("sha256sum is not installed")
	}
	root, _ := stage(t, map[string]string{
		"config.json":          `{"model_type":"tiny"}`,
		"blobs/model.safetens": "weights, allegedly",
	})
	dir, _ := ModelDir(root, "hf-cache", "acme/tiny")

	// Ours is checkable by theirs.
	cmd := exec.Command("sha256sum", "-c", ManifestName)
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Errorf("sha256sum -c refused our manifest: %v\n%s", err, out)
	}

	// Theirs is checkable by ours.
	gen := exec.Command("sha256sum", "config.json", "blobs/model.safetens")
	gen.Dir = dir
	body, err := gen.Output()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ManifestName), body, 0o644); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(body)
	got := VerifyStaged(root, "hf-cache", "acme/tiny", hex.EncodeToString(sum[:]))
	if got.State != StateStaged {
		t.Errorf("a manifest sha256sum wrote: state = %s (%s), want staged", got.State, got.Reason)
	}
}
