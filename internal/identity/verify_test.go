package identity

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/nodarynet/nodary/internal/audit"
	"github.com/nodarynet/nodary/internal/store"
)

const aPassword = "correct horse battery staple"

// The load-bearing test for the denial of service the review measured.
//
// PBKDF2 at 600,000 iterations takes around 68ms and internal/store caps the
// writer pool at one connection, so running the hash inside the login's write
// transaction let roughly fifteen unauthenticated attempts a second hold the
// write lock continuously — blocking audit records, agent status posts and
// usage rows behind somebody who had not authenticated.
//
// Verifying against a handle that physically cannot write is the strongest
// available statement that it no longer does. A signature is a promise; this is
// the database refusing.
func TestAPasswordIsVerifiedWithoutAWritableHandle(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	addUserWithPassword(t, f, "alice", aPassword)

	ro, err := store.OpenReadOnly(ctx, filepath.Join(f.dir, "nodary.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer ro.Close()

	u, rehash, _, err := VerifyPassword(ctx, ro.Read(), "alice", aPassword)
	if err != nil {
		t.Fatalf("verifying against a read-only handle: %v", err)
	}
	if u.Name != "alice" {
		t.Errorf("verified %q", u.Name)
	}
	if rehash.Pending() {
		t.Error("a freshly set password reported a pending upgrade")
	}
}

// A stored hash behind the current parameters still verifies, and the upgrade
// it earns is carried out rather than performed — so the expensive half is
// outside the caller's transaction too.
func TestAStaleHashVerifiesAndReportsAPendingUpgrade(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	addUserWithPassword(t, f, "alice", aPassword)

	// Rewritten at an iteration count the current build considers behind.
	stale, err := encodeHash(aPassword, []byte("0123456789abcdef0123456789abcdef"), 1000)
	if err != nil {
		t.Fatal(err)
	}
	setHash(t, f, "alice", stale)

	u, rehash, _, err := VerifyPassword(ctx, f.db.Read(), "alice", aPassword)
	if err != nil {
		t.Fatalf("a stale hash refused a correct password: %v", err)
	}
	if !rehash.Pending() {
		t.Fatal("a stale hash reported no pending upgrade")
	}

	// Applied inside a transaction, as the login that earned it commits.
	if _, err := f.log.Act(ctx, audit.Request{Actor: LocalRoot().Actor, Action: "auth.login"},
		func(m audit.Mutation) error { return rehash.Apply(ctx, m) }); err != nil {
		t.Fatal(err)
	}
	if got := currentHash(t, f, u.ID); got == stale {
		t.Error("the upgrade did not replace the stale hash")
	}
	// And the new one still opens the account.
	if _, _, _, err := VerifyPassword(ctx, f.db.Read(), "alice", aPassword); err != nil {
		t.Errorf("the upgraded hash refuses the same password: %v", err)
	}
}

// Between the read that verified and the write that upgrades, somebody may have
// changed the password. Rehashing the old plaintext over a new password would
// silently roll it back — so the write is guarded on the hash it verified
// against and does nothing when that has moved.
func TestAnUpgradeNeverClobbersAPasswordChangedInBetween(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	addUserWithPassword(t, f, "alice", aPassword)

	stale, err := encodeHash(aPassword, []byte("0123456789abcdef0123456789abcdef"), 1000)
	if err != nil {
		t.Fatal(err)
	}
	setHash(t, f, "alice", stale)

	u, rehash, _, err := VerifyPassword(ctx, f.db.Read(), "alice", aPassword)
	if err != nil {
		t.Fatal(err)
	}

	// The password changes after the verification and before the upgrade.
	const newPassword = "an entirely different passphrase"
	if _, err := f.log.Act(ctx, audit.Request{Actor: LocalRoot().Actor, Action: "user.passwd"},
		func(m audit.Mutation) error {
			return SetPassword(ctx, m, RoleAdmin, "alice", newPassword)
		}); err != nil {
		t.Fatal(err)
	}
	changed := currentHash(t, f, u.ID)

	if _, err := f.log.Act(ctx, audit.Request{Actor: LocalRoot().Actor, Action: "auth.login"},
		func(m audit.Mutation) error { return rehash.Apply(ctx, m) }); err != nil {
		t.Fatal(err)
	}
	if got := currentHash(t, f, u.ID); got != changed {
		t.Fatal("a stale upgrade overwrote a password changed after it was computed")
	}
	// The new password works and the old one does not.
	if _, _, _, err := VerifyPassword(ctx, f.db.Read(), "alice", newPassword); err != nil {
		t.Errorf("the new password was rolled back: %v", err)
	}
	if _, _, _, err := VerifyPassword(ctx, f.db.Read(), "alice", aPassword); !errors.Is(err, ErrBadPassword) {
		t.Errorf("the old password still works: %v", err)
	}
}

// An unknown account, a suspended one and one with no password are all
// ErrBadPassword, and the reason travels separately for the audit record.
func TestEveryFailureIsTheSameErrorWithItsOwnReason(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	addUserWithPassword(t, f, "alice", aPassword)
	addUser(t, f, "bob") // no password
	addUserWithPassword(t, f, "carol", aPassword)
	if _, err := f.log.Act(ctx, audit.Request{Actor: LocalRoot().Actor, Action: "user.suspend"},
		func(m audit.Mutation) error {
			_, err := Suspend(ctx, m, RoleAdmin, f.now, "carol")
			return err
		}); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct{ user, password, reason string }{
		{"nobody", aPassword, "no such account"},
		{"alice", "wrong", "wrong password"},
		{"bob", aPassword, "no password is set"},
		{"carol", aPassword, "account is suspended"},
	} {
		_, _, reason, err := VerifyPassword(ctx, f.db.Read(), tc.user, tc.password)
		if !errors.Is(err, ErrBadPassword) {
			t.Errorf("%s: err = %v, want ErrBadPassword", tc.user, err)
		}
		if reason != tc.reason {
			t.Errorf("%s: reason = %q, want %q", tc.user, reason, tc.reason)
		}
	}
}

func addUser(t *testing.T, f *fixture, name string) {
	t.Helper()
	if _, err := f.log.Act(context.Background(),
		audit.Request{Actor: LocalRoot().Actor, Action: "user.add"},
		func(m audit.Mutation) error {
			_, err := Add(context.Background(), m, RoleAdmin, f.now, name, "", RoleUser)
			return err
		}); err != nil {
		t.Fatal(err)
	}
}

func addUserWithPassword(t *testing.T, f *fixture, name, password string) {
	t.Helper()
	addUser(t, f, name)
	if _, err := f.log.Act(context.Background(),
		audit.Request{Actor: LocalRoot().Actor, Action: "user.passwd"},
		func(m audit.Mutation) error {
			return SetPassword(context.Background(), m, RoleAdmin, name, password)
		}); err != nil {
		t.Fatal(err)
	}
}

func setHash(t *testing.T, f *fixture, name, hash string) {
	t.Helper()
	if _, err := f.log.Act(context.Background(),
		audit.Request{Actor: LocalRoot().Actor, Action: "user.passwd"},
		func(m audit.Mutation) error {
			_, err := m.Tx().ExecContext(context.Background(),
				`UPDATE user SET password_hash = ? WHERE name = ?`, hash, name)
			return err
		}); err != nil {
		t.Fatal(err)
	}
}

func currentHash(t *testing.T, f *fixture, userID string) string {
	t.Helper()
	var h string
	if err := f.db.Read().QueryRowContext(context.Background(),
		`SELECT password_hash FROM user WHERE id = ?`, userID).Scan(&h); err != nil {
		t.Fatal(err)
	}
	return h
}
