package release

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"strings"
	"testing"

	"github.com/nodarynet/nodary/internal/minisign"
)

type signer struct {
	priv ed25519.PrivateKey
	id   [8]byte
}

func newSigner(t *testing.T) *signer {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var id [8]byte
	copy(id[:], []byte("release "))
	previous := TrustedKey
	TrustedKey = minisign.EncodePublicKey(minisign.PublicKey{ID: id, Key: pub})
	t.Cleanup(func() { TrustedKey = previous })
	return &signer{priv: priv, id: id}
}

func (s *signer) sign(b []byte) string {
	return minisign.Sign(s.priv, s.id, b, "nodary release")
}

// The property R5-16 exists for: a node checks what it was handed against
// something it already holds, rather than against the word of whoever handed
// it over.
func TestABinarySignedByTheReleaseKeyVerifies(t *testing.T) {
	s := newSigner(t)
	binary := []byte("a nodary binary, for these purposes")
	if err := Verify(binary, s.sign(binary)); err != nil {
		t.Fatalf("a correctly signed binary was refused: %v", err)
	}
	if !Trusted() {
		t.Error("a build with a real key reports itself untrusted")
	}
}

func TestABinaryThatWasChangedIsRefused(t *testing.T) {
	s := newSigner(t)
	binary := []byte("a nodary binary, for these purposes")
	sig := s.sign(binary)

	// One byte, which is the whole point: a control plane that substituted a
	// binary is what this catches, and a substitution is not subtle to the
	// signature even when it is subtle to a reader.
	tampered := append([]byte(nil), binary...)
	tampered[0] ^= 0x01
	if err := Verify(tampered, sig); !errors.Is(err, ErrUnverified) {
		t.Errorf("a modified binary verified: %v", err)
	}
}

// Somebody else's key is the case the whole mechanism is about: a control plane
// can sign whatever it likes, and what makes that useless is that the node
// checks against the release key rather than against any key.
func TestABinarySignedByAnotherKeyIsRefused(t *testing.T) {
	newSigner(t) // installs the trusted key
	other, otherPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_ = other
	var id [8]byte
	copy(id[:], []byte("notours "))

	binary := []byte("a nodary binary, for these purposes")
	sig := minisign.Sign(otherPriv, id, binary, "not ours")
	if err := Verify(binary, sig); !errors.Is(err, ErrUnverified) {
		t.Errorf("a binary signed by another key verified: %v", err)
	}
}

// The same posture install.sh takes when NODARY_PUBKEY is still
// REPLACE_AT_RELEASE_TIME: a development copy must not be able to install
// anything, and must say that rather than failing obscurely later.
func TestADevelopmentBuildRefusesRatherThanPretending(t *testing.T) {
	if Trusted() {
		t.Fatal("this build carries a real release key; the placeholder is the default")
	}
	err := Verify([]byte("anything"), "anything")
	if !errors.Is(err, ErrUnverified) {
		t.Fatalf("a build with no key accepted a binary: %v", err)
	}
	if !errors.Is(err, minisign.ErrPlaceholder) {
		t.Errorf("the refusal does not name the placeholder: %v", err)
	}
	if !strings.Contains(err.Error(), "placeholder release key") {
		t.Errorf("the refusal does not say what is wrong with this build: %v", err)
	}
}
