package identity

import (
	"context"
	"database/sql"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/nodarynet/nodary/internal/audit"
)

func TestAddCreatesAnActiveUserAndSaysSoInTheRecord(t *testing.T) {
	f := newFixture(t)
	var u User
	rec, err := f.act("user.add", func(m audit.Mutation) error {
		var err error
		u, err = Add(context.Background(), m, RoleAdmin, f.now, "alice", "alice@example.test",
			RoleOperator)
		return err
	})
	if err != nil {
		t.Fatalf("Add: %v", err)
	}

	if !strings.HasPrefix(u.ID, "usr_") {
		t.Errorf("id %q does not carry its kind", u.ID)
	}
	if u.State != StateActive || !u.Active() {
		t.Errorf("state = %q, want active", u.State)
	}
	if u.Role != RoleOperator || u.Email != "alice@example.test" {
		t.Errorf("stored %+v", u)
	}

	if rec.Outcome != audit.OutcomeSuccess {
		t.Errorf("outcome = %q, want success", rec.Outcome)
	}
	// The record has to say who was created and as what. "a user was added" is
	// not evidence anybody can act on.
	if got := rec.Detail["name"]; got != "alice" {
		t.Errorf("detail[name] = %v, want alice", got)
	}
	if got := rec.Detail["role"]; got != "operator" {
		t.Errorf("detail[role] = %v, want operator", got)
	}

	read, err := f.get("alice")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if read.ID != u.ID || !read.CreatedAt.Equal(u.CreatedAt) {
		t.Errorf("read back %+v, want %+v", read, u)
	}
	if read.TOTPEnrolled {
		t.Error("a new user must not be enrolled in TOTP")
	}
}

func TestOnlyAnAdminManagesUsers(t *testing.T) {
	f := newFixture(t)
	f.add("alice", RoleUser)

	for _, by := range []Role{RoleViewer, RoleUser, RoleOperator, Role("")} {
		for _, tc := range []struct {
			verb string
			run  func(m audit.Mutation) error
		}{
			{"add", func(m audit.Mutation) error {
				_, err := Add(context.Background(), m, by, f.now, "mallory", "", RoleAdmin)
				return err
			}},
			{"suspend", func(m audit.Mutation) error {
				_, err := Suspend(context.Background(), m, by, f.now, "alice")
				return err
			}},
			{"delete", func(m audit.Mutation) error {
				_, err := Delete(context.Background(), m, by, f.now, "alice")
				return err
			}},
		} {
			rec, err := f.act("user."+tc.verb, tc.run)
			if !errors.Is(err, ErrDenied) {
				t.Errorf("%s as %q: error = %v, want ErrDenied", tc.verb, by, err)
			}
			// A refused attempt is exactly what an audit chain is for. If the
			// check happened before Act rather than inside the mutation, this
			// is where that would show up.
			if rec.Outcome != audit.OutcomeFailure {
				t.Errorf("%s as %q: outcome = %q, want failure", tc.verb, by, rec.Outcome)
			}
			if rec.Seq == 0 {
				t.Errorf("%s as %q: refusal left no record", tc.verb, by)
			}
		}
	}

	if got := f.users(true); len(got) != 1 {
		t.Errorf("users = %v, want only alice; a refusal changed state", names(got))
	}
	if u, _ := f.get("alice"); u.State != StateActive {
		t.Errorf("alice is %q; a refusal changed her state", u.State)
	}
}

func TestTheStateMachineIsForwardOnly(t *testing.T) {
	f := newFixture(t)
	f.add("alice", RoleUser)

	suspend := func() error {
		_, err := f.act("user.suspend", func(m audit.Mutation) error {
			_, err := Suspend(context.Background(), m, RoleAdmin, f.now, "alice")
			return err
		})
		return err
	}
	del := func(name string) error {
		_, err := f.act("user.delete", func(m audit.Mutation) error {
			_, err := Delete(context.Background(), m, RoleAdmin, f.now, name)
			return err
		})
		return err
	}

	if err := suspend(); err != nil {
		t.Fatalf("active to suspended: %v", err)
	}
	if err := suspend(); !errors.Is(err, ErrBadTransition) {
		t.Errorf("suspended to suspended: error = %v, want ErrBadTransition", err)
	}
	if err := del("alice"); err != nil {
		t.Fatalf("suspended to deleted: %v", err)
	}
	err := del("alice")
	if !errors.Is(err, ErrBadTransition) {
		t.Fatalf("deleted to deleted: error = %v, want ErrBadTransition", err)
	}
	// The message has to name the state it found, or an operator cannot tell
	// "already gone" from "never existed".
	if !strings.Contains(err.Error(), "deleted") {
		t.Errorf("error does not say what state it found: %v", err)
	}

	f.add("bob", RoleUser)
	if err := del("bob"); err != nil {
		t.Fatalf("active to deleted: %v", err)
	}
}

// TestADeletedNameComesBack is the reason the unique index is partial.
func TestADeletedNameComesBack(t *testing.T) {
	f := newFixture(t)
	first := f.add("alice", RoleUser)

	_, err := f.act("user.add", func(m audit.Mutation) error {
		_, err := Add(context.Background(), m, RoleAdmin, f.now, "alice", "", RoleUser)
		return err
	})
	if !errors.Is(err, ErrNameTaken) {
		t.Fatalf("adding a live name: error = %v, want ErrNameTaken", err)
	}

	if _, err := f.act("user.delete", func(m audit.Mutation) error {
		_, err := Delete(context.Background(), m, RoleAdmin, f.now, "alice")
		return err
	}); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	second := f.add("alice", RoleAdmin)
	if second.ID == first.ID {
		t.Fatal("reusing a name must create a new user, not revive the old one")
	}

	// Both rows survive, because audit records name the old alice by id.
	if got := len(f.users(true)); got != 2 {
		t.Errorf("rows = %d, want 2; the deleted user was not kept", got)
	}
	if got := f.users(false); len(got) != 1 || got[0].ID != second.ID {
		t.Errorf("live users = %v, want only the new alice", names(got))
	}
	// A lookup by name must find the live one; the old row stays reachable by
	// the id an audit record carries.
	if u, err := f.get("alice"); err != nil || u.ID != second.ID || u.Role != RoleAdmin {
		t.Errorf("Get(alice) = %+v, %v; want the live row", u, err)
	}
	old, err := GetByID(context.Background(), f.db.Read(), first.ID)
	if err != nil || old.State != StateDeleted {
		t.Errorf("GetByID(%s) = %+v, %v; want the deleted row", first.ID, old, err)
	}
}

// TestDeleteScrubsTheSeedAndRevokesTokens writes the rows directly, so it tests
// what deletion does to them rather than what minting produced.
func TestDeleteScrubsTheSeedAndRevokesTokens(t *testing.T) {
	f := newFixture(t)
	alice := f.add("alice", RoleUser)
	bob := f.add("bob", RoleUser)
	ctx := context.Background()

	seed := func(id string) {
		t.Helper()
		if err := f.db.WriteTx(ctx, func(tx *sql.Tx) error {
			_, err := tx.ExecContext(ctx,
				`UPDATE user SET totp_secret_enc = ?, totp_enrolled_at = ?, totp_last_step = ?
				 WHERE id = ?`, []byte("sealed"), "2026-09-01T12:00:00.000Z", 42, id)
			return err
		}); err != nil {
			t.Fatalf("seeding %s: %v", id, err)
		}
	}
	token := func(user, id, fill string) {
		t.Helper()
		if err := f.db.WriteTx(ctx, func(tx *sql.Tx) error {
			_, err := tx.ExecContext(ctx,
				`INSERT INTO token (id, user_id, kind, hash, prefix, created_at)
				 VALUES (?, ?, 'pt', ?, 'nodary_pt_aaaa', '2026-09-01T12:00:00.000Z')`,
				id, user, strings.Repeat(fill, 64))
			return err
		}); err != nil {
			t.Fatalf("inserting a token for %s: %v", user, err)
		}
	}
	seed(alice.ID)
	seed(bob.ID)
	token(alice.ID, "tok_a", "a")
	token(bob.ID, "tok_b", "b")

	rec, err := f.act("user.delete", func(m audit.Mutation) error {
		_, err := Delete(ctx, m, RoleAdmin, f.now, "alice")
		return err
	})
	if err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if got := rec.Detail["tokens_revoked"]; got != float64(1) && got != int64(1) {
		t.Errorf("detail[tokens_revoked] = %#v, want 1", got)
	}

	var enc []byte
	var step, enrolled any
	if err := f.db.Read().QueryRowContext(ctx,
		`SELECT totp_secret_enc, totp_last_step, totp_enrolled_at FROM user WHERE id = ?`,
		alice.ID).Scan(&enc, &step, &enrolled); err != nil {
		t.Fatalf("reading alice: %v", err)
	}
	if enc != nil || step != nil || enrolled != nil {
		t.Errorf("deletion left seed=%v step=%v enrolled=%v", enc, step, enrolled)
	}

	var revoked any
	if err := f.db.Read().QueryRowContext(ctx,
		`SELECT revoked_at FROM token WHERE id = 'tok_a'`).Scan(&revoked); err != nil {
		t.Fatalf("reading tok_a: %v", err)
	}
	if revoked == nil {
		t.Error("alice's token was not revoked")
	}

	// Bob is untouched. A delete that revokes more than it was asked to is the
	// same bug as one that revokes less.
	if err := f.db.Read().QueryRowContext(ctx,
		`SELECT revoked_at FROM token WHERE id = 'tok_b'`).Scan(&revoked); err != nil {
		t.Fatalf("reading tok_b: %v", err)
	}
	if revoked != nil {
		t.Error("bob's token was revoked by alice's deletion")
	}
	if err := f.db.Read().QueryRowContext(ctx,
		`SELECT totp_secret_enc FROM user WHERE id = ?`, bob.ID).Scan(&enc); err != nil {
		t.Fatalf("reading bob: %v", err)
	}
	if enc == nil {
		t.Error("bob's seed was scrubbed by alice's deletion")
	}
}

func TestAddRejectsNamesThatCannotBeUsed(t *testing.T) {
	f := newFixture(t)
	bad := []string{
		"",
		" ",
		"alice bob",
		"alice\n",
		"alice\t",
		" alice",
		strings.Repeat("a", maxNameLength+1),
		"\xff\xfe",
	}
	for _, name := range bad {
		_, err := f.act("user.add", func(m audit.Mutation) error {
			_, err := Add(context.Background(), m, RoleAdmin, f.now, name, "", RoleUser)
			return err
		})
		if !errors.Is(err, ErrBadName) {
			t.Errorf("Add(%q): error = %v, want ErrBadName", name, err)
		}
	}
	for _, email := range []string{"a b@example.test", "a\nb@example.test", strings.Repeat("a", 300)} {
		_, err := f.act("user.add", func(m audit.Mutation) error {
			_, err := Add(context.Background(), m, RoleAdmin, f.now, "carol", email, RoleUser)
			return err
		})
		if !errors.Is(err, ErrBadName) {
			t.Errorf("Add(email %q): error = %v, want ErrBadName", email, err)
		}
	}
	if got := f.users(true); len(got) != 0 {
		t.Errorf("a rejected name created %v", names(got))
	}
}

func TestAddRejectsAnUnknownRole(t *testing.T) {
	f := newFixture(t)
	_, err := f.act("user.add", func(m audit.Mutation) error {
		_, err := Add(context.Background(), m, RoleAdmin, f.now, "alice", "", Role("root"))
		return err
	})
	if !errors.Is(err, ErrUnknownRole) {
		t.Fatalf("error = %v, want ErrUnknownRole", err)
	}
	if got := f.users(true); len(got) != 0 {
		t.Errorf("an unknown role created %v", names(got))
	}
}

func TestGetAndListOnAnUnknownUser(t *testing.T) {
	f := newFixture(t)
	if _, err := f.get("nobody"); !errors.Is(err, ErrNotFound) {
		t.Errorf("Get: error = %v, want ErrNotFound", err)
	}
	if _, err := GetByID(context.Background(), f.db.Read(), "usr_missing"); !errors.Is(err, ErrNotFound) {
		t.Errorf("GetByID: error = %v, want ErrNotFound", err)
	}
	if got := f.users(true); len(got) != 0 {
		t.Errorf("empty database listed %v", names(got))
	}
}

func TestListOrdersByNameAndHidesDeleted(t *testing.T) {
	f := newFixture(t)
	for _, n := range []string{"carol", "alice", "bob"} {
		f.add(n, RoleUser)
	}
	if _, err := f.act("user.delete", func(m audit.Mutation) error {
		_, err := Delete(context.Background(), m, RoleAdmin, f.now, "bob")
		return err
	}); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	got := names(f.users(false))
	want := []string{"alice/active", "carol/active"}
	if !slices.Equal(got, want) {
		t.Errorf("List(false) = %v, want %v", got, want)
	}
	got = names(f.users(true))
	want = []string{"alice/active", "bob/deleted", "carol/active"}
	if !slices.Equal(got, want) {
		t.Errorf("List(true) = %v, want %v", got, want)
	}
}

// TestEmailIsNullWhenUnset keeps absent and empty distinguishable in the
// column, which is the same rule the audit record follows for its optionals.
func TestEmailIsNullWhenUnset(t *testing.T) {
	f := newFixture(t)
	u := f.add("alice", RoleUser)
	var email any
	if err := f.db.Read().QueryRowContext(context.Background(),
		`SELECT email FROM user WHERE id = ?`, u.ID).Scan(&email); err != nil {
		t.Fatalf("reading email: %v", err)
	}
	if email != nil {
		t.Errorf("email = %#v, want NULL", email)
	}
}
