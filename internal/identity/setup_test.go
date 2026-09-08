package identity

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/nodarynet/nodary/internal/audit"
)

// mintSetup issues a link and fails the test if it cannot.
func (f *fixture) mintSetup() string {
	f.t.Helper()
	var token string
	if _, err := f.act("installation.setup-link", func(m audit.Mutation) error {
		var err error
		token, _, err = MintSetup(context.Background(), m, f.now)
		return err
	}); err != nil {
		f.t.Fatalf("minting a setup link: %v", err)
	}
	return token
}

func (f *fixture) redeem(now time.Time, token, name, password string) (User, error) {
	f.t.Helper()
	var u User
	_, err := f.act("installation.setup", func(m audit.Mutation) error {
		var err error
		u, err = RedeemSetup(context.Background(), m, now, token, name, "a@example.com", password)
		return err
	})
	return u, err
}

const goodPassword = "correct-horse-battery"

// TestTheSetupLinkCreatesOneAdministratorAndDies is R5-08's whole requirement:
// **no default password ever exists**.
func TestTheSetupLinkCreatesOneAdministratorAndDies(t *testing.T) {
	f := newFixture(t)
	token := f.mintSetup()

	u, err := f.redeem(f.now, token, "admin", goodPassword)
	if err != nil {
		t.Fatalf("redeeming: %v", err)
	}
	if u.Role != RoleAdmin {
		t.Errorf("the first account is %q, want admin", u.Role)
	}

	// The password is the one that was chosen, and nothing else opens the
	// account. This is the assertion R5-08 is actually about — an account that
	// exists with no password, or with one this code picked, would pass every
	// check above and fail the requirement.
	if _, err := f.act("auth.login", func(m audit.Mutation) error {
		_, err := VerifyPassword(context.Background(), m, "admin", goodPassword)
		return err
	}); err != nil {
		t.Errorf("the administrator cannot log in with the password they set: %v", err)
	}

	// Replayed, the link is dead. The reason given is that the installation has
	// an administrator, which is the useful answer and not a secret.
	if _, err := f.redeem(f.now, token, "second", goodPassword); !errors.Is(err, ErrSetupDone) {
		t.Errorf("a replayed setup link returned %v, want ErrSetupDone", err)
	}
}

// TestASetupLinkIsRefusedWhenItShouldBe covers the three ways one stops working
// while an installation is still unconfigured — where the answers must be
// indistinguishable, because the caller is unauthenticated and the difference
// tells it whether a live link exists.
func TestASetupLinkIsRefusedWhenItShouldBe(t *testing.T) {
	for _, tc := range []struct {
		name  string
		at    func(base time.Time) time.Time
		token func(issued string) string
	}{
		{"expired", func(b time.Time) time.Time { return b.Add(SetupTTL + time.Second) },
			func(issued string) string { return issued }},
		{"wrong", func(b time.Time) time.Time { return b },
			func(string) string { return KindSetup.Prefix() + "notatoken" }},
		{"superseded", func(b time.Time) time.Time { return b },
			func(string) string { return "" }}, // filled in below
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			issued := f.mintSetup()
			token := tc.token(issued)
			if tc.name == "superseded" {
				// Minting again replaces the outstanding link, so the first one
				// stops working immediately. That is the point of re-minting on
				// a re-run, and it is worth asserting rather than assuming.
				f.mintSetup()
				token = issued
			}
			if _, err := f.redeem(tc.at(f.now), token, "admin", goodPassword); !errors.Is(err, ErrSetupUnavailable) {
				t.Errorf("redeeming a %s link returned %v, want ErrSetupUnavailable", tc.name, err)
			}
			// And nothing was created, so the real link still works.
			if _, err := Get(context.Background(), f.db.Read(), "admin"); !errors.Is(err, ErrNotFound) {
				t.Errorf("a refused redemption left an account behind: %v", err)
			}
		})
	}
}

// TestNobodyCanMintASetupCredentialAsAToken is the structural half.
//
// KindSetup carries a prefix so a leaked one is greppable, but it is not a kind
// an operator may mint: a setup credential creates an administrator, and
// `nodary token create --kind st` producing one would be a second, much larger
// meaning for the token verb. Leaving it out of Kinds is what enforces that,
// and this fails if somebody "completes" the list.
func TestNobodyCanMintASetupCredentialAsAToken(t *testing.T) {
	if _, err := ParseKind(string(KindSetup)); !errors.Is(err, ErrUnknownKind) {
		t.Errorf("ParseKind(%q) = %v; a setup credential must not be mintable as a token",
			KindSetup, err)
	}
	if KindSetup.Valid() {
		t.Error("KindSetup is in Kinds; `token create --kind st` would issue one")
	}
	// It still has a prefix, and it is distinct from every other one.
	for _, k := range Kinds {
		if k.Prefix() == KindSetup.Prefix() {
			t.Errorf("%s shares a prefix with the setup credential", k)
		}
	}
}

// TestSetupIsNotOfferedOnAConfiguredInstallation stops a second administrator
// being minted a link on a control plane that is already running.
func TestSetupIsNotOfferedOnAConfiguredInstallation(t *testing.T) {
	f := newFixture(t)
	f.add("someone", RoleViewer)

	if _, err := f.act("installation.setup-link", func(m audit.Mutation) error {
		_, _, err := MintSetup(context.Background(), m, f.now)
		return err
	}); !errors.Is(err, ErrSetupDone) {
		t.Errorf("minting on a configured installation returned %v, want ErrSetupDone", err)
	}
	if pending, err := SetupPending(context.Background(), f.db.Read(), f.now); err != nil || pending {
		t.Errorf("SetupPending = %v, %v; want false", pending, err)
	}
}
