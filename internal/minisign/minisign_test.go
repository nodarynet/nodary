package minisign

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
)

func newKey(t *testing.T) (PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var id [keyIDLen]byte
	if _, err := rand.Read(id[:]); err != nil {
		t.Fatal(err)
	}
	return PublicKey{ID: id, Key: pub}, priv
}

func TestRoundTrip(t *testing.T) {
	pub, priv := newKey(t)
	msg := []byte("a manifest revision")
	sig := Sign(priv, pub.ID, msg, "nodary manifest revision 7")

	got, err := Verify(pub, msg, sig)
	if err != nil {
		t.Fatalf("a good signature was refused: %v", err)
	}
	if got.TrustedComment != "nodary manifest revision 7" {
		t.Errorf("trusted comment = %q", got.TrustedComment)
	}
}

// The public key must round-trip through the form minisign itself writes, or an
// assessor cannot check a bundle with the stock tool.
func TestPublicKeyEncodingIsParseable(t *testing.T) {
	pub, _ := newKey(t)
	back, err := ParsePublicKey(EncodePublicKey(pub))
	if err != nil {
		t.Fatalf("our own public key did not parse: %v", err)
	}
	if back.ID != pub.ID || !back.Key.Equal(pub.Key) {
		t.Error("the public key did not survive the round trip")
	}
	// The payload line alone is also accepted, since that is what a config file
	// or an embedded constant usually holds.
	if _, err := ParsePublicKey(strings.Split(EncodePublicKey(pub), "\n")[1]); err != nil {
		t.Errorf("the bare payload line was refused: %v", err)
	}
}

func TestEveryTamperIsCaught(t *testing.T) {
	pub, priv := newKey(t)
	msg := []byte("a manifest revision")
	good := Sign(priv, pub.ID, msg, "revision 7")

	t.Run("message changed", func(t *testing.T) {
		if _, err := Verify(pub, []byte("a different revision"), good); !errors.Is(err, ErrBadSig) {
			t.Errorf("err = %v, want ErrBadSig", err)
		}
	})

	t.Run("signed by another key", func(t *testing.T) {
		other, otherPriv := newKey(t)
		if _, err := Verify(pub, msg, Sign(otherPriv, other.ID, msg, "revision 7")); !errors.Is(err, ErrWrongKey) {
			t.Errorf("err = %v, want ErrWrongKey", err)
		}
	})

	// The trusted comment is where a version or a filename lives, so rewriting
	// it is how a signature gets lifted onto something it does not describe.
	t.Run("trusted comment rewritten", func(t *testing.T) {
		lifted := strings.Replace(good, "trusted comment: revision 7", "trusted comment: revision 9", 1)
		if _, err := Verify(pub, msg, lifted); !errors.Is(err, ErrBadSig) {
			t.Errorf("err = %v, want ErrBadSig", err)
		}
	})

	t.Run("key id swapped to ours", func(t *testing.T) {
		other, otherPriv := newKey(t)
		// Forge the id so the cheap check passes and only Ed25519 can refuse it.
		forged := Sign(otherPriv, pub.ID, msg, "revision 7")
		_ = other
		if _, err := Verify(pub, msg, forged); !errors.Is(err, ErrBadSig) {
			t.Errorf("err = %v, want ErrBadSig", err)
		}
	})
}

// docs/adr/0007: the prehashed variant needs BLAKE2b, which is neither in the
// standard library nor FIPS-approved. It is refused by name so the message says
// how to produce a signature this will accept.
func TestPrehashedIsRefusedByName(t *testing.T) {
	pub, priv := newKey(t)
	good := Sign(priv, pub.ID, []byte("x"), "c")

	lines := strings.Split(good, "\n")
	raw, _ := base64.StdEncoding.DecodeString(lines[1])
	copy(raw[:2], algPrehashed)
	lines[1] = base64.StdEncoding.EncodeToString(raw)

	_, err := Verify(pub, []byte("x"), strings.Join(lines, "\n"))
	if !errors.Is(err, ErrPrehashed) {
		t.Fatalf("err = %v, want ErrPrehashed", err)
	}
	if !strings.Contains(err.Error(), "-l") {
		t.Errorf("the refusal does not name the flag that fixes it: %v", err)
	}
}

func TestMalformedInputsAreRefusedNotPanicked(t *testing.T) {
	pub, _ := newKey(t)
	for _, tc := range []struct{ name, sig string }{
		{"empty", ""},
		{"one line", "untrusted comment: x"},
		{"not base64", "c\n!!!!\ntrusted comment: t\n!!!!"},
		{"short signature", "c\n" + base64.StdEncoding.EncodeToString([]byte("Edshort")) + "\ntrusted comment: t\nAAAA"},
		{"no trusted comment", "c\n" + base64.StdEncoding.EncodeToString(make([]byte, 74)) + "\nnope\nAAAA"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Verify(pub, []byte("x"), tc.sig); err == nil {
				t.Error("malformed input verified")
			}
		})
	}
}

func FuzzParseSignature(f *testing.F) {
	pub, priv := newKey(&testing.T{})
	f.Add(Sign(priv, pub.ID, []byte("x"), "c"))
	f.Add("")
	f.Fuzz(func(t *testing.T, s string) {
		_, _ = ParseSignature(s) // must not panic
		_, _ = ParsePublicKey(s)
	})
}
