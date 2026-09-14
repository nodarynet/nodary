package cli

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nodarynet/nodary/internal/minisign"
	"github.com/nodarynet/nodary/internal/release"
)

// releaseSigner installs a trusted release key for the duration of a test and
// signs with it, standing in for the signing pipeline.
func releaseSigner(t *testing.T) func([]byte) string {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var id [8]byte
	copy(id[:], []byte("release "))
	prev := release.TrustedKey
	release.TrustedKey = minisign.EncodePublicKey(minisign.PublicKey{ID: id, Key: pub})
	t.Cleanup(func() { release.TrustedKey = prev })
	return func(b []byte) string { return minisign.Sign(priv, id, b, "nodary release") }
}

func installedAt(t *testing.T, optDir, version string, body []byte, sig string) {
	t.Helper()
	dir := filepath.Join(optDir, version)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "nodary"), body, 0o755); err != nil {
		t.Fatal(err)
	}
	if sig != "" {
		if err := os.WriteFile(filepath.Join(dir, BinarySig), []byte(sig), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// R5-16's property: a node with no egress can be handed a binary, and what
// makes that safe is that it arrives with a signature the node checks itself.
func TestUpgradePublishesTheBinaryAndItsSignature(t *testing.T) {
	sign := releaseSigner(t)
	data, opt := t.TempDir(), t.TempDir()
	body := []byte("a nodary binary")
	installedAt(t, opt, "1.2.3", body, sign(body))

	step := publishBinary(data, opt, "1.2.3", "linux-amd64")
	if !step.Changed {
		t.Fatalf("nothing was published: %s", step.Detail)
	}
	name := filepath.Join(data, "dist", "nodary-1.2.3-linux-amd64")
	got, err := os.ReadFile(name)
	if err != nil {
		t.Fatalf("the mirror has no binary: %v", err)
	}
	if string(got) != string(body) {
		t.Error("the published binary is not the installed one")
	}
	// Without the signature the binary is unverifiable, which is the whole
	// reason it is published at all rather than simply served.
	if _, err := os.Stat(name + ".minisig"); err != nil {
		t.Errorf("the mirror has no signature beside the binary: %v", err)
	}
	if fi, err := os.Stat(name); err == nil && fi.Mode().Perm()&0o111 == 0 {
		t.Error("the published binary is not executable")
	}
}

// **Verified before published, not after.** A control plane serving a binary it
// cannot itself check would be asking every node to trust bytes on its word,
// and the failure would land on the fleet instead of on the one machine with an
// operator in front of it.
func TestABinaryThatDoesNotVerifyIsNotPublished(t *testing.T) {
	sign := releaseSigner(t)
	data, opt := t.TempDir(), t.TempDir()
	// A signature over something else: what a substituted binary looks like.
	installedAt(t, opt, "1.2.3", []byte("a nodary binary"), sign([]byte("something else")))

	step := publishBinary(data, opt, "1.2.3", "linux-amd64")
	if step.Changed {
		t.Fatal("a binary that does not verify was published to the fleet")
	}
	if !strings.Contains(step.Detail, "NOT published") {
		t.Errorf("the step does not say it refused: %q", step.Detail)
	}
	if _, err := os.Stat(filepath.Join(data, "dist", "nodary-1.2.3-linux-amd64")); err == nil {
		t.Error("the mirror holds a binary that failed verification")
	}
}

// A host installed before install.sh kept the signature has nothing to copy.
// Skipped and said, rather than failing the upgrade: the rest of it is correct
// and worth doing.
func TestAnUpgradeWithNoSignatureSaysSoAndCarriesOn(t *testing.T) {
	releaseSigner(t)
	data, opt := t.TempDir(), t.TempDir()
	installedAt(t, opt, "1.2.3", []byte("a nodary binary"), "")

	step := publishBinary(data, opt, "1.2.3", "linux-amd64")
	if step.Changed {
		t.Fatal("something was published with no signature to publish")
	}
	if !strings.Contains(step.Detail, "install.sh") {
		t.Errorf("the step does not say how to get one: %q", step.Detail)
	}
}

// A development build cannot verify anything, so it must not seed a mirror with
// something a node would then refuse — the same posture install.sh takes.
func TestADevelopmentBuildPublishesNothing(t *testing.T) {
	data, opt := t.TempDir(), t.TempDir()
	installedAt(t, opt, "1.2.3", []byte("a nodary binary"), "a signature")

	step := publishBinary(data, opt, "1.2.3", "linux-amd64")
	if step.Changed {
		t.Fatal("a build with a placeholder release key published a binary")
	}
	// "skipped", not "NOT published": the guard has to fire *before* the
	// verify, or a control plane reads a few tens of megabytes off disk to
	// reach a conclusion it already had — and reports a signature failure for
	// what is really a build with no key.
	if !strings.HasPrefix(step.Detail, "skipped:") {
		t.Errorf("the build with no key reached the verify instead of stopping early: %q",
			step.Detail)
	}
	if !strings.Contains(step.Detail, "placeholder release key") {
		t.Errorf("the step does not name the reason: %q", step.Detail)
	}
}
