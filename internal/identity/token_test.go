package identity

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nodarynet/nodary/internal/audit"
)

// mint issues a token and returns it with its plaintext.
func (f *fixture) mint(user string, kind Kind, name string, expires time.Time) (Token, string) {
	f.t.Helper()
	var (
		tok   Token
		plain string
	)
	if _, err := f.act("token.create", func(m audit.Mutation) error {
		var err error
		tok, plain, err = MintToken(context.Background(), m, RoleAdmin, f.now, user, kind,
			name, expires)
		return err
	}); err != nil {
		f.t.Fatalf("minting a %s for %q: %v", kind, user, err)
	}
	return tok, plain
}

func TestMintedTokensCarryTheirKindsPrefix(t *testing.T) {
	f := newFixture(t)
	f.add("alice", RoleOperator)

	for _, kind := range userKinds {
		tok, plain := f.mint("alice", kind, "laptop", time.Time{})
		want := "nodary_" + string(kind) + "_"
		if !strings.HasPrefix(plain, want) {
			t.Errorf("%s plaintext %q does not start with %q", kind, plain, want)
		}
		// R1-21: the prefix has to survive into what gets logged, or the kinds
		// stop being greppable exactly when somebody needs to grep for them.
		if !strings.HasPrefix(tok.Prefix, want) {
			t.Errorf("%s stored prefix %q does not start with %q", kind, tok.Prefix, want)
		}
		if tok.Prefix == plain {
			t.Errorf("%s stored the whole credential as its display prefix", kind)
		}
		if len(plain) < 50 {
			t.Errorf("%s plaintext is only %d characters", kind, len(plain))
		}
	}

	j, plain := f.mintJoin(3, f.now.Add(time.Hour))
	if !strings.HasPrefix(plain, "nodary_jt_") || !strings.HasPrefix(j.Prefix, "nodary_jt_") {
		t.Errorf("join token %q / %q does not carry its prefix", plain, j.Prefix)
	}
}

// TestNoPlaintextIsStoredAnywhere is R1-21's load-bearing claim, checked
// against the bytes on disk rather than against an API that could be hiding
// one. It is the test that catches a display struct quietly gaining a field.
func TestNoPlaintextIsStoredAnywhere(t *testing.T) {
	f := newFixture(t)
	f.add("alice", RoleOperator)
	tok, plain := f.mint("alice", KindPersonal, "laptop", time.Time{})
	_, joinPlain := f.mintJoin(2, f.now.Add(time.Hour))

	// Everything a caller can read back.
	list, err := ListTokens(context.Background(), f.db.Read(), tok.UserID)
	if err != nil {
		t.Fatal(err)
	}
	byID, err := TokenByID(context.Background(), f.db.Read(), tok.ID)
	if err != nil {
		t.Fatal(err)
	}
	joins, err := ListJoinTokens(context.Background(), f.db.Read())
	if err != nil {
		t.Fatal(err)
	}
	for what, v := range map[string]any{
		"the returned token": tok,
		"token list":         list,
		"token show":         byID,
		"join token list":    joins,
	} {
		encoded, err := json.Marshal(v)
		if err != nil {
			t.Fatalf("encoding %s: %v", what, err)
		}
		for _, secret := range []string{plain, joinPlain} {
			if bytes.Contains(encoded, []byte(secret)) {
				t.Errorf("%s carries a plaintext credential: %s", what, encoded)
			}
		}
	}

	// And on disk, WAL included: a credential is a hash at rest or it is not.
	if err := f.db.Close(); err != nil {
		t.Fatalf("closing: %v", err)
	}
	for _, name := range []string{"nodary.db", "nodary.db-wal", "nodary.db-shm"} {
		b, err := os.ReadFile(filepath.Join(f.dir, name))
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			t.Fatalf("reading %s: %v", name, err)
		}
		for _, secret := range []string{plain, joinPlain} {
			if bytes.Contains(b, []byte(secret)) {
				t.Errorf("%s contains a plaintext credential", name)
			}
		}
		if !bytes.Contains(b, []byte(hashToken(plain))) && name == "nodary.db" {
			t.Log("note: the hash is in the WAL rather than the main file")
		}
	}
}

func TestAuthenticateResolvesTheUser(t *testing.T) {
	f := newFixture(t)
	alice := f.add("alice", RoleOperator)
	tok, plain := f.mint("alice", KindPersonal, "laptop", time.Time{})

	got, gotTok, err := Authenticate(context.Background(), f.db.Read(), f.now, plain)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if got.ID != alice.ID || got.Role != RoleOperator {
		t.Errorf("resolved %+v, want alice as an operator", got)
	}
	if gotTok.ID != tok.ID {
		t.Errorf("resolved token %s, want %s", gotTok.ID, tok.ID)
	}
}

// TestAnUnknownCredentialIsUniform keeps the one case where the presenter has
// proved nothing from telling them anything.
func TestAnUnknownCredentialIsUniform(t *testing.T) {
	f := newFixture(t)
	f.add("alice", RoleOperator)
	_, plain := f.mint("alice", KindPersonal, "", time.Time{})

	for _, presented := range []string{
		"",
		"hunter2",
		"nodary_pt_",
		"nodary_xx_" + strings.Repeat("a", 52),
		"nodary_pt_" + strings.Repeat("a", 52),
		plain + "a",
		strings.TrimSuffix(plain, plain[len(plain)-1:]),
		// The right secret under the wrong kind: the hash would match if the
		// prefix were not part of what is hashed.
		strings.Replace(plain, "nodary_pt_", "nodary_sk_", 1),
	} {
		_, _, err := Authenticate(context.Background(), f.db.Read(), f.now, presented)
		if !errors.Is(err, ErrBadToken) {
			t.Errorf("Authenticate(%q): error = %v, want ErrBadToken", presented, err)
		}
	}
}

func TestRevocationTakesEffectImmediately(t *testing.T) {
	f := newFixture(t)
	f.add("alice", RoleOperator)
	tok, plain := f.mint("alice", KindPersonal, "", time.Time{})

	if _, _, err := Authenticate(context.Background(), f.db.Read(), f.now, plain); err != nil {
		t.Fatalf("before revocation: %v", err)
	}
	if _, err := f.act("token.revoke", func(m audit.Mutation) error {
		_, err := RevokeToken(context.Background(), m, RoleAdmin, f.now, tok.ID)
		return err
	}); err != nil {
		t.Fatalf("RevokeToken: %v", err)
	}

	_, _, err := Authenticate(context.Background(), f.db.Read(), f.now, plain)
	if !errors.Is(err, ErrTokenRevoked) {
		t.Fatalf("after revocation: error = %v, want ErrTokenRevoked", err)
	}
	// The row stays, so a report can still say the credential existed and when
	// it stopped working.
	back, err := TokenByID(context.Background(), f.db.Read(), tok.ID)
	if err != nil || !back.Revoked() {
		t.Fatalf("read back %+v, %v", back, err)
	}

	// Revoking twice is a state error, not a silent success that rewrites when
	// the credential stopped working.
	_, err = f.act("token.revoke", func(m audit.Mutation) error {
		_, err := RevokeToken(context.Background(), m, RoleAdmin, f.now.Add(time.Hour), tok.ID)
		return err
	})
	if !errors.Is(err, ErrBadTransition) {
		t.Fatalf("second revocation: error = %v, want ErrBadTransition", err)
	}
	again, _ := TokenByID(context.Background(), f.db.Read(), tok.ID)
	if !again.RevokedAt.Equal(back.RevokedAt) {
		t.Errorf("the revocation time moved from %s to %s", back.RevokedAt, again.RevokedAt)
	}
}

func TestExpiryIsRefusedAtItsInstant(t *testing.T) {
	f := newFixture(t)
	f.add("alice", RoleOperator)
	expires := f.now.Add(time.Hour).Truncate(time.Millisecond)
	_, plain := f.mint("alice", KindService, "", expires)

	if _, _, err := Authenticate(context.Background(), f.db.Read(),
		expires.Add(-time.Millisecond), plain); err != nil {
		t.Errorf("a millisecond before expiry: %v", err)
	}
	for _, at := range []time.Time{expires, expires.Add(time.Second)} {
		_, _, err := Authenticate(context.Background(), f.db.Read(), at, plain)
		if !errors.Is(err, ErrTokenExpired) {
			t.Errorf("at %s: error = %v, want ErrTokenExpired", at, err)
		}
	}
}

func TestMintRefusesAnExpiryAlreadyPast(t *testing.T) {
	f := newFixture(t)
	f.add("alice", RoleOperator)
	_, err := f.act("token.create", func(m audit.Mutation) error {
		_, _, err := MintToken(context.Background(), m, RoleAdmin, f.now, "alice",
			KindPersonal, "", f.now.Add(-time.Second))
		return err
	})
	if !errors.Is(err, ErrBadName) {
		t.Fatalf("error = %v, want a refusal", err)
	}
}

func TestATokenStopsWorkingWithItsUser(t *testing.T) {
	f := newFixture(t)
	f.add("alice", RoleOperator)
	f.add("bob", RoleOperator)
	_, alicePlain := f.mint("alice", KindPersonal, "", time.Time{})
	_, bobPlain := f.mint("bob", KindPersonal, "", time.Time{})

	if _, err := f.act("user.suspend", func(m audit.Mutation) error {
		_, err := Suspend(context.Background(), m, RoleAdmin, f.now, "alice")
		return err
	}); err != nil {
		t.Fatal(err)
	}
	// Suspension revokes nothing: it is the account that is out, not the
	// credential, and the refusal has to come from the user's state.
	_, _, err := Authenticate(context.Background(), f.db.Read(), f.now, alicePlain)
	if !errors.Is(err, ErrNotActive) {
		t.Errorf("suspended user: error = %v, want ErrNotActive", err)
	}

	if _, err := f.act("user.delete", func(m audit.Mutation) error {
		_, err := Delete(context.Background(), m, RoleAdmin, f.now, "bob")
		return err
	}); err != nil {
		t.Fatal(err)
	}
	// Deletion does revoke, so the credential reports as withdrawn — which is
	// what `token list` will show an auditor afterwards.
	_, _, err = Authenticate(context.Background(), f.db.Read(), f.now, bobPlain)
	if !errors.Is(err, ErrTokenRevoked) {
		t.Errorf("deleted user: error = %v, want ErrTokenRevoked", err)
	}
}

func TestTouchRecordsTheUse(t *testing.T) {
	f := newFixture(t)
	f.add("alice", RoleOperator)
	tok, _ := f.mint("alice", KindPersonal, "", time.Time{})
	if !tok.LastUsedAt.IsZero() {
		t.Fatalf("a new token reports a last use of %s", tok.LastUsedAt)
	}

	used := f.now.Add(90 * time.Minute)
	if _, err := f.act("user.add", func(m audit.Mutation) error {
		return Touch(context.Background(), m, used, tok.ID)
	}); err != nil {
		t.Fatalf("Touch: %v", err)
	}
	back, err := TokenByID(context.Background(), f.db.Read(), tok.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !back.LastUsedAt.Equal(used.Truncate(time.Millisecond)) {
		t.Errorf("last used = %s, want %s", back.LastUsedAt, used)
	}
}

func TestOnlyAnAdminMintsAndRevokes(t *testing.T) {
	f := newFixture(t)
	f.add("alice", RoleOperator)
	tok, _ := f.mint("alice", KindPersonal, "", time.Time{})

	for _, by := range []Role{RoleViewer, RoleUser, RoleOperator} {
		_, err := f.act("token.create", func(m audit.Mutation) error {
			_, _, err := MintToken(context.Background(), m, by, f.now, "alice",
				KindPersonal, "", time.Time{})
			return err
		})
		if !errors.Is(err, ErrDenied) {
			t.Errorf("mint as %q: error = %v, want ErrDenied", by, err)
		}
		_, err = f.act("token.revoke", func(m audit.Mutation) error {
			_, err := RevokeToken(context.Background(), m, by, f.now, tok.ID)
			return err
		})
		if !errors.Is(err, ErrDenied) {
			t.Errorf("revoke as %q: error = %v, want ErrDenied", by, err)
		}
		_, err = f.act("token.join", func(m audit.Mutation) error {
			_, _, err := MintJoinToken(context.Background(), m, by, f.now, "root", 1,
				f.now.Add(time.Hour))
			return err
		})
		if !errors.Is(err, ErrDenied) {
			t.Errorf("join as %q: error = %v, want ErrDenied", by, err)
		}
	}

	list, err := ListTokens(context.Background(), f.db.Read(), "")
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 || list[0].Revoked() {
		t.Errorf("a refusal changed the token set: %+v", list)
	}
}

func TestMintRefusesTheWrongKindForAUser(t *testing.T) {
	f := newFixture(t)
	f.add("alice", RoleOperator)
	for _, kind := range []Kind{KindJoin, Kind("xx"), Kind("")} {
		_, err := f.act("token.create", func(m audit.Mutation) error {
			_, _, err := MintToken(context.Background(), m, RoleAdmin, f.now, "alice",
				kind, "", time.Time{})
			return err
		})
		if !errors.Is(err, ErrUnknownKind) {
			t.Errorf("kind %q: error = %v, want ErrUnknownKind", kind, err)
		}
	}
}

func TestAJoinTokenMustExpireAndBeUsable(t *testing.T) {
	f := newFixture(t)
	for _, tc := range []struct {
		what    string
		uses    int
		expires time.Time
	}{
		{"no uses", 0, f.now.Add(time.Hour)},
		{"negative uses", -1, f.now.Add(time.Hour)},
		{"no expiry", 1, time.Time{}},
		{"expiry in the past", 1, f.now.Add(-time.Second)},
	} {
		_, err := f.act("token.join", func(m audit.Mutation) error {
			_, _, err := MintJoinToken(context.Background(), m, RoleAdmin, f.now, "root",
				tc.uses, tc.expires)
			return err
		})
		if !errors.Is(err, ErrBadName) {
			t.Errorf("%s: error = %v, want a refusal", tc.what, err)
		}
	}
	list, err := ListJoinTokens(context.Background(), f.db.Read())
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 0 {
		t.Errorf("a refused mint created %+v", list)
	}
}

func TestParseKind(t *testing.T) {
	for _, in := range []string{"pt", "nodary_pt_", "nodary_pt"} {
		got, err := ParseKind(in)
		if err != nil || got != KindPersonal {
			t.Errorf("ParseKind(%q) = %q, %v", in, got, err)
		}
	}
	if _, err := ParseKind("personal"); !errors.Is(err, ErrUnknownKind) {
		t.Errorf("ParseKind(personal): error = %v, want ErrUnknownKind", err)
	}
}

// TestThePrefixIsPartOfWhatIsHashed and the kind check below are two guards
// against one attack: presenting a real secret under another kind's prefix.
// Either alone closes it, so each needs its own test or the pair rots into one.
func TestThePrefixIsPartOfWhatIsHashed(t *testing.T) {
	body := strings.Repeat("a", 52)
	if hashToken("nodary_pt_"+body) == hashToken(body) {
		t.Error("the prefix does not affect the hash")
	}
	if hashToken("nodary_pt_"+body) == hashToken("nodary_sk_"+body) {
		t.Error("two kinds of the same secret hash alike")
	}
}

// TestARowWhoseKindDisagreesWithItsPrefixIsRefused covers a tampered or
// corrupted row: the hash matches what was presented, and the stored kind does
// not match what the credential claims to be.
func TestARowWhoseKindDisagreesWithItsPrefixIsRefused(t *testing.T) {
	f := newFixture(t)
	alice := f.add("alice", RoleOperator)

	presented := "nodary_sk_" + strings.Repeat("b", 52)
	if _, err := f.act("token.create", func(m audit.Mutation) error {
		_, err := m.Tx().ExecContext(context.Background(),
			`INSERT INTO token (id, user_id, kind, hash, prefix, created_at)
			 VALUES ('tok_forged', ?, 'pt', ?, 'nodary_pt_bbbbbbbb', ?)`,
			alice.ID, hashToken(presented), formatTime(truncateTime(f.now)))
		return err
	}); err != nil {
		t.Fatalf("planting the row: %v", err)
	}

	if _, _, err := Authenticate(context.Background(), f.db.Read(), f.now, presented); !errors.Is(err, ErrBadToken) {
		t.Fatalf("error = %v, want ErrBadToken", err)
	}
}

// TestStoredTimesRoundTrip keeps what Mint returns and what the database holds
// the same value. They are compared against each other constantly — a report
// against a row, a revocation against a creation — and a difference of
// microseconds is a difference that only shows up in a confusing diff.
func TestStoredTimesRoundTrip(t *testing.T) {
	f := newFixture(t)
	f.add("alice", RoleOperator)
	expires := f.now.Add(48 * time.Hour)
	tok, _ := f.mint("alice", KindService, "ci", expires)

	back, err := TokenByID(context.Background(), f.db.Read(), tok.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !back.CreatedAt.Equal(tok.CreatedAt) {
		t.Errorf("created_at round-tripped %s, want %s", back.CreatedAt, tok.CreatedAt)
	}
	if !back.ExpiresAt.Equal(tok.ExpiresAt) {
		t.Errorf("expires_at round-tripped %s, want %s", back.ExpiresAt, tok.ExpiresAt)
	}
	if back.Name != "ci" || back.Kind != KindService || back.UserID != tok.UserID {
		t.Errorf("read back %+v, want %+v", back, tok)
	}
}
