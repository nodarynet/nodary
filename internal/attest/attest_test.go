package attest

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"testing"

	"github.com/nodarynet/nodary/internal/policy"
)

func profile(t *testing.T, name string) policy.Profile {
	t.Helper()
	p, _, err := policy.Builtin(name)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// docs/specs/07-identity-audit.md §4: default asks for no ceremony, so an
// operator restarting a model types the command and nothing else.
func TestDefaultDemandsNothing(t *testing.T) {
	if err := Require(profile(t, "default"), Ceremony{Interactive: true}); err != nil {
		t.Errorf("default refused a bare act: %v", err)
	}
}

func TestRegulatedRequiresAJustificationOfLength(t *testing.T) {
	p := profile(t, "regulated")

	if err := Require(p, Ceremony{Interactive: true, TOTPCode: "123456"}); !errors.Is(err, ErrJustification) {
		t.Errorf("no justification: err = %v, want ErrJustification", err)
	}
	// R1-15's own example: five characters under regulated is refused.
	if err := Require(p, Ceremony{Justification: "fixed", TOTPCode: "1", Interactive: true}); !errors.Is(err, ErrJustificationShort) {
		t.Errorf("short justification: err = %v, want ErrJustificationShort", err)
	}
	if err := Require(p, Ceremony{Justification: "rotating the pilot key", TOTPCode: "1", Interactive: true}); err != nil {
		t.Errorf("a good justification was refused: %v", err)
	}
}

// A floor with no requirement means "optional, but say something real". A
// length nobody enforces is the silently ineffective setting R1d refuses.
func TestAFloorAppliesToWhateverIsSupplied(t *testing.T) {
	p := profile(t, "default")
	p.MinJustificationLength = 10

	if err := Require(p, Ceremony{Interactive: true}); err != nil {
		t.Errorf("an absent optional justification was refused: %v", err)
	}
	if err := Require(p, Ceremony{Justification: "typo", Interactive: true}); !errors.Is(err, ErrJustificationShort) {
		t.Errorf("a short optional justification was accepted: %v", err)
	}
}

// Runes, not bytes: a length in bytes would fail an accented justification that
// an ASCII one of the same length passes, which is a rule nobody wrote down.
func TestLengthCountsCharactersNotBytes(t *testing.T) {
	p := profile(t, "default")
	p.MinJustificationLength = 12
	if err := Require(p, Ceremony{Justification: "réparation d", Interactive: true}); err != nil {
		t.Errorf("12 characters were refused as too short: %v", err)
	}
}

// The table in docs/plans/R1e-attestation.md, asserted directly.
func TestWhoMustReAuthenticate(t *testing.T) {
	def, reg := profile(t, "default"), profile(t, "regulated")
	for _, tc := range []struct {
		name string
		p    policy.Profile
		c    Ceremony
		want bool
	}{
		{"default asks nobody", def, Ceremony{Interactive: true}, false},
		{"regulated, ordinary credential", reg, Ceremony{Interactive: true}, true},
		{"regulated, unattended grant", reg, Ceremony{Unattended: true}, false},
		{"regulated, local root", reg, Ceremony{Local: true, Interactive: true}, false},
	} {
		if got := NeedsTOTP(tc.p, tc.c); got != tc.want {
			t.Errorf("%s: NeedsTOTP = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// A non-interactive caller with an ordinary credential is refused rather than
// asked for something it cannot produce, and the message says what would fix it.
func TestNonInteractiveWithoutTheGrantIsRefusedAndTold(t *testing.T) {
	err := Require(profile(t, "regulated"), Ceremony{Justification: "nightly rotation job"})
	if !errors.Is(err, ErrTOTPRequired) {
		t.Fatalf("err = %v, want ErrTOTPRequired", err)
	}
	if !strings.Contains(err.Error(), "allow-unattended") {
		t.Errorf("the refusal does not name the way out: %v", err)
	}
}

func TestUnattendedMintIsRefusedByProfile(t *testing.T) {
	if err := AllowUnattendedMint(profile(t, "default")); err != nil {
		t.Errorf("default refused an unattended mint: %v", err)
	}
	err := AllowUnattendedMint(profile(t, "regulated"))
	if !errors.Is(err, ErrUnattendedForbidden) {
		t.Errorf("regulated allowed an unattended mint: %v", err)
	}
}

// R1-14: the same render over moved state must not match the approved hash.
func TestHashBindsTheRenderedChangeNotItsArguments(t *testing.T) {
	before := map[string]any{"name": "alice", "from": "active", "to": "suspended"}
	after := map[string]any{"name": "alice", "from": "suspended", "to": "suspended"}

	h1, err := Hash(before)
	if err != nil {
		t.Fatal(err)
	}
	h2, _ := Hash(after)
	if h1 == h2 {
		t.Error("a change of the state being moved from did not change the hash")
	}
	// Reproducible, which is the property the whole gate rests on.
	again, _ := Hash(map[string]any{"to": "suspended", "from": "active", "name": "alice"})
	if again != h1 {
		t.Errorf("the same change hashed differently: %s vs %s", h1, again)
	}
}

// R1-14, at the mechanism: the render is run again and the result must still
// hash to what was approved. A render whose answer moved is exactly the window
// docs/specs/07-identity-audit.md §3 closes.
func TestBindRefusesWhenTheRenderedChangeMoved(t *testing.T) {
	state := "active"
	render := func(context.Context, *sql.Tx) (any, error) {
		return map[string]any{"name": "alice", "from": state}, nil
	}

	preview, _ := render(context.Background(), nil)
	approved, err := Hash(preview)
	if err != nil {
		t.Fatal(err)
	}

	// Nothing moved: the bind returns the change.
	if _, err := Bind(context.Background(), nil, render, approved); err != nil {
		t.Fatalf("an unmoved change was refused: %v", err)
	}

	// Somebody else suspended alice between the preview and the apply.
	state = "suspended"
	_, err = Bind(context.Background(), nil, render, approved)
	if !errors.Is(err, ErrIntentChanged) {
		t.Fatalf("err = %v, want ErrIntentChanged", err)
	}
	if !strings.Contains(err.Error(), approved[:12]) {
		t.Errorf("the refusal does not name the approved hash: %v", err)
	}
}
