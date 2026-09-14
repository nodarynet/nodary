package components

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nodarynet/nodary/internal/minisign"
)

// publisher is the release pipeline: a key this build trusts for the duration
// of one test, and the ability to sign a revision with it.
type publisher struct {
	priv ed25519.PrivateKey
	id   [8]byte
}

func newPublisher(t *testing.T) *publisher {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var id [8]byte
	copy(id[:], []byte("manifest"))
	previous := TrustedKey
	TrustedKey = minisign.EncodePublicKey(minisign.PublicKey{ID: id, Key: pub})
	t.Cleanup(func() { TrustedKey = previous })
	return &publisher{priv: priv, id: id}
}

func (p *publisher) sign(doc []byte) string {
	return minisign.Sign(p.priv, p.id, doc, "nodary component manifest")
}

// revisionDoc is the embedded manifest with a different revision number, so
// what is under test is the resolution rather than a hand-written fixture that
// might not describe a usable fleet.
func revisionDoc(t *testing.T, revision int) []byte {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(embedded, &m); err != nil {
		t.Fatal(err)
	}
	m["revision"] = revision
	doc, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return doc
}

// place writes a revision where Effective looks for it.
func place(t *testing.T, doc []byte, sig string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, RevisionName), doc, 0o644); err != nil {
		t.Fatal(err)
	}
	if sig != "" {
		if err := os.WriteFile(filepath.Join(dir, RevisionSig), []byte(sig), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func floorRevision(t *testing.T) int {
	t.Helper()
	m, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	return m.Revision
}

// The deliverable: a customer takes a component fix on their own timeline
// instead of waiting for us to tag a release.
func TestASignedRevisionSupersedesTheEmbeddedFloor(t *testing.T) {
	p := newPublisher(t)
	want := floorRevision(t) + 7
	doc := revisionDoc(t, want)

	m, src, err := Effective(place(t, doc, p.sign(doc)))
	if err != nil {
		t.Fatal(err)
	}
	if !src.Applied || src.Revision != want {
		t.Fatalf("the revision did not take effect: %+v", src)
	}
	if src.Why != "" {
		t.Errorf("a revision that took effect explained itself: %s", src.Why)
	}
	if m.Revision != want {
		t.Errorf("the returned manifest is revision %d", m.Revision)
	}
}

// The floor is the normal state, not a fallback. An install with no network, no
// bundle and no revision behaves exactly as it did before any of this existed.
func TestNoRevisionIsTheOrdinaryCaseAndSaysNothing(t *testing.T) {
	m, src, err := Effective(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if src.Applied || src.Why != "" {
		t.Fatalf("an install with no revision reported something: %+v", src)
	}
	if m.Revision != floorRevision(t) || len(m.Components) == 0 {
		t.Errorf("the floor was not returned: revision %d, %d components", m.Revision, len(m.Components))
	}
}

// Ignored, not rejected. An offline site replaying a bundle it already opened
// is not doing anything wrong, and failing closed there would make the safest
// delivery mechanism the most fragile.
func TestARevisionNoNewerThanTheFloorIsIgnoredAndNotAnError(t *testing.T) {
	p := newPublisher(t)
	for _, rev := range []int{floorRevision(t), floorRevision(t) - 1} {
		doc := revisionDoc(t, rev)
		m, src, err := Effective(place(t, doc, p.sign(doc)))
		if err != nil {
			t.Fatalf("revision %d was an error: %v", rev, err)
		}
		if src.Applied {
			t.Errorf("revision %d superseded the floor", rev)
		}
		if !strings.Contains(src.Why, "not newer") {
			t.Errorf("revision %d: %q", rev, src.Why)
		}
		if m.Revision != floorRevision(t) {
			t.Errorf("revision %d did not leave the floor running", rev)
		}
	}
}

// Every verification failure falls back to the floor *and is reported*. Falling
// back quietly would leave an operator who applied a revision running something
// else with nothing saying so.
func TestAnUnverifiableRevisionFallsBackToTheFloorAndSaysSo(t *testing.T) {
	p := newPublisher(t)
	newer := floorRevision(t) + 3

	cases := map[string]func() string{
		"body tampered": func() string {
			doc := revisionDoc(t, newer)
			sig := p.sign(doc)
			return place(t, append(doc, ' '), sig)
		},
		"wrong key": func() string {
			doc := revisionDoc(t, newer)
			other, otherPriv, _ := ed25519.GenerateKey(rand.Reader)
			_ = other
			var id [8]byte
			copy(id[:], []byte("intruder"))
			return place(t, doc, minisign.Sign(otherPriv, id, doc, "not ours"))
		},
		"no signature": func() string {
			return place(t, revisionDoc(t, newer), "")
		},
		"not a manifest": func() string {
			doc := []byte(`{"schema":1,"revision":99,"components":[]}`)
			return place(t, doc, p.sign(doc))
		},
	}
	for name, setup := range cases {
		t.Run(name, func(t *testing.T) {
			m, src, err := Effective(setup())
			if err != nil {
				t.Fatalf("resolution failed instead of falling back: %v", err)
			}
			if src.Applied {
				t.Fatal("an unverifiable revision took effect")
			}
			if src.Why == "" {
				t.Error("the fallback was silent")
			}
			if m.Revision != floorRevision(t) || len(m.Components) == 0 {
				t.Error("the floor is not what is running")
			}
		})
	}
}

// A build whose key was never stamped verifies nothing, and must say that
// rather than reporting a signature problem the operator cannot act on.
func TestADevelopmentBuildTrustsNoRevision(t *testing.T) {
	previous := TrustedKey
	TrustedKey = placeholderKey
	t.Cleanup(func() { TrustedKey = previous })

	_, err := VerifyRevision(revisionDoc(t, 99), "whatever")
	if !errors.Is(err, ErrUnverified) || !errors.Is(err, minisign.ErrPlaceholder) {
		t.Fatalf("a placeholder build reported %v", err)
	}
}
