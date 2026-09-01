package identity

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nodarynet/nodary/internal/audit"
	"github.com/nodarynet/nodary/internal/secret"
)

func TestEnrollSealsTheSeedOnlyAfterTheCodeConfirmsIt(t *testing.T) {
	f := newFixture(t)
	u := f.add("alice", RoleOperator)
	seed, err := NewSeed()
	if err != nil {
		t.Fatal(err)
	}

	// A wrong code writes nothing. An enrollment marked active on display
	// alone locks an account out when the QR is mis-scanned.
	_, err = f.act("user.totp", func(m audit.Mutation) error {
		_, err := Enroll(context.Background(), m, RoleAdmin, f.now, f.key, "alice", seed, "000000")
		return err
	})
	if !errors.Is(err, ErrBadCode) {
		t.Fatalf("wrong code: error = %v, want ErrBadCode", err)
	}
	if got, _ := f.get("alice"); got.TOTPEnrolled {
		t.Fatal("a refused enrollment was recorded")
	}
	if id := f.boundKey(); id != "" {
		t.Errorf("a refused enrollment bound the key as %q", id)
	}

	code := codeAt(seed, stepAt(f.now), totpDigits)
	rec, err := f.act("user.totp", func(m audit.Mutation) error {
		_, err := Enroll(context.Background(), m, RoleAdmin, f.now, f.key, "alice", seed, code)
		return err
	})
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	if got := rec.Detail["replaced"]; got != false {
		t.Errorf("detail[replaced] = %#v, want false on a first enrollment", got)
	}

	got, err := f.get("alice")
	if err != nil || !got.TOTPEnrolled {
		t.Fatalf("read back %+v, %v", got, err)
	}

	// R1-19: the seed is displayed once and never readable back. What the
	// database holds is a ciphertext, and it does not contain the seed.
	sealed := f.sealedSeed(u.ID)
	if len(sealed) == 0 {
		t.Fatal("nothing was sealed")
	}
	if bytes.Contains(sealed, seed) {
		t.Fatal("the stored blob contains the seed in the clear")
	}
	opened, err := f.key.Open("totp", u.ID, sealed)
	if err != nil || !bytes.Equal(opened, seed) {
		t.Fatalf("the sealed seed does not round-trip: %v", err)
	}
}

// TestASealedSeedCannotBeMovedBetweenUsers is what the label binding in
// secret.Seal buys: an attacker with database write access cannot promote
// themselves by copying somebody else's enrollment into their own row.
func TestASealedSeedCannotBeMovedBetweenUsers(t *testing.T) {
	f := newFixture(t)
	alice := f.add("alice", RoleUser)
	bob := f.add("bob", RoleUser)
	f.enroll("alice")

	if _, err := f.key.Open("totp", bob.ID, f.sealedSeed(alice.ID)); err == nil {
		t.Fatal("alice's sealed seed opened under bob's identity")
	}
}

func TestEnrollRefusesAUserWhoCannotAuthenticate(t *testing.T) {
	f := newFixture(t)
	f.add("alice", RoleUser)
	if _, err := f.act("user.suspend", func(m audit.Mutation) error {
		_, err := Suspend(context.Background(), m, RoleAdmin, f.now, "alice")
		return err
	}); err != nil {
		t.Fatal(err)
	}

	seed, err := NewSeed()
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.act("user.totp", func(m audit.Mutation) error {
		_, err := Enroll(context.Background(), m, RoleAdmin, f.now, f.key, "alice", seed,
			codeAt(seed, stepAt(f.now), totpDigits))
		return err
	})
	if !errors.Is(err, ErrNotActive) {
		t.Fatalf("error = %v, want ErrNotActive", err)
	}
}

func TestOnlyAnAdminEnrolls(t *testing.T) {
	f := newFixture(t)
	f.add("alice", RoleUser)
	seed, err := NewSeed()
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.act("user.totp", func(m audit.Mutation) error {
		_, err := Enroll(context.Background(), m, RoleOperator, f.now, f.key, "alice", seed,
			codeAt(seed, stepAt(f.now), totpDigits))
		return err
	})
	if !errors.Is(err, ErrDenied) {
		t.Fatalf("error = %v, want ErrDenied", err)
	}
}

func TestReEnrollmentReplacesTheSeedAndSaysSo(t *testing.T) {
	f := newFixture(t)
	u := f.add("alice", RoleUser)
	first := f.enroll("alice")
	before := f.sealedSeed(u.ID)

	second, err := NewSeed()
	if err != nil {
		t.Fatal(err)
	}
	rec, err := f.act("user.totp", func(m audit.Mutation) error {
		_, err := Enroll(context.Background(), m, RoleAdmin, f.now, f.key, "alice", second,
			codeAt(second, stepAt(f.now), totpDigits))
		return err
	})
	if err != nil {
		t.Fatalf("re-enrolling: %v", err)
	}
	// Replacing a seed is how an account locked out of its authenticator gets
	// back in. It is a different event from a first enrollment and the chain
	// has to say which one happened.
	if got := rec.Detail["replaced"]; got != true {
		t.Errorf("detail[replaced] = %#v, want true", got)
	}

	after := f.sealedSeed(u.ID)
	if bytes.Equal(before, after) {
		t.Fatal("the sealed seed did not change")
	}
	opened, err := f.key.Open("totp", u.ID, after)
	if err != nil || bytes.Equal(opened, first) {
		t.Fatalf("the old seed survived re-enrollment: %v", err)
	}
}

func TestVerifySpendsTheCode(t *testing.T) {
	f := newFixture(t)
	f.add("alice", RoleUser)
	seed := f.enroll("alice")

	// The enrolling code is already spent, because whoever watched the
	// enrollment saw it.
	at := f.now.Add(31 * 1e9)
	code := codeAt(seed, stepAt(at), totpDigits)

	verify := func(code string) error {
		_, err := f.act("user.totp.verify", func(m audit.Mutation) error {
			_, err := VerifyTOTP(context.Background(), m, at, f.key, "alice", code)
			return err
		})
		return err
	}
	if err := verify(code); err != nil {
		t.Fatalf("first use: %v", err)
	}
	if err := verify(code); !errors.Is(err, ErrBadCode) {
		t.Fatalf("second use: error = %v, want ErrBadCode", err)
	}
	if err := verify(codeAt(seed, stepAt(f.now), totpDigits)); !errors.Is(err, ErrBadCode) {
		t.Fatalf("an earlier code: error = %v, want ErrBadCode", err)
	}
}

func TestVerifyRefusesTheUnenrolledAndTheInactive(t *testing.T) {
	f := newFixture(t)
	f.add("alice", RoleUser)
	f.add("bob", RoleUser)
	seed := f.enroll("bob")

	_, err := f.act("user.totp.verify", func(m audit.Mutation) error {
		_, err := VerifyTOTP(context.Background(), m, f.now, f.key, "alice", "123456")
		return err
	})
	if !errors.Is(err, ErrNotEnrolled) {
		t.Fatalf("unenrolled: error = %v, want ErrNotEnrolled", err)
	}

	if _, err := f.act("user.delete", func(m audit.Mutation) error {
		_, err := Delete(context.Background(), m, RoleAdmin, f.now, "bob")
		return err
	}); err != nil {
		t.Fatal(err)
	}
	at := f.now.Add(31 * 1e9)
	_, err = f.act("user.totp.verify", func(m audit.Mutation) error {
		_, err := VerifyTOTP(context.Background(), m, at, f.key, "bob",
			codeAt(seed, stepAt(at), totpDigits))
		return err
	})
	if !errors.Is(err, ErrNotActive) {
		t.Fatalf("deleted: error = %v, want ErrNotActive", err)
	}
}

// TestTheKeyBindingRefusesAStrangerKey is R1-36. Deleting secret.key and
// restarting must be refused, not answered by minting a fresh one — which
// would leave every sealed seed permanently unreadable behind a clean start.
func TestTheKeyBindingRefusesAStrangerKey(t *testing.T) {
	f := newFixture(t)

	// Nothing is sealed yet, so nothing is bound and any key is acceptable.
	stranger := newKey(t, filepath.Join(f.dir, "stranger.key"))
	if err := f.checkKey(stranger); err != nil {
		t.Fatalf("an unbound database refused a key: %v", err)
	}

	f.add("alice", RoleUser)
	f.enroll("alice")

	if got, want := f.boundKey(), f.key.ID(); got != want {
		t.Fatalf("bound key = %q, want %q", got, want)
	}
	if err := f.checkKey(f.key); err != nil {
		t.Fatalf("the sealing key was refused: %v", err)
	}

	err := f.checkKey(stranger)
	if !errors.Is(err, ErrKeyMismatch) {
		t.Fatalf("error = %v, want ErrKeyMismatch", err)
	}
	// The message is the whole deliverable: the two states behind it are
	// unrecoverable in opposite directions, so it has to name both ids and say
	// what not to do.
	for _, want := range []string{f.key.ID(), stranger.ID(), "retired", "permanently unreadable"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("message should mention %q: %v", want, err)
		}
	}
}

// TestARetiredKeyStillSatisfiesTheBinding is what makes rotation possible: the
// binding advances when the last ciphertext has been resealed, not when a new
// key appears.
func TestARetiredKeyStillSatisfiesTheBinding(t *testing.T) {
	f := newFixture(t)
	f.add("alice", RoleUser)
	f.enroll("alice")

	newPath := filepath.Join(f.dir, "rotated.key")
	if _, err := secret.Create(newPath); err != nil {
		t.Fatal(err)
	}
	ring, err := secret.Load(newPath, filepath.Join(f.dir, "secret.key"))
	if err != nil {
		t.Fatalf("loading the rotated keyring: %v", err)
	}
	if ring.ID() == f.key.ID() {
		t.Fatal("the rotated key has the same id as the old one")
	}
	if err := f.checkKey(ring); err != nil {
		t.Fatalf("a keyring holding the sealing key as retired was refused: %v", err)
	}
	// And the binding is left alone, because nothing has been resealed.
	if got, want := f.boundKey(), f.key.ID(); got != want {
		t.Errorf("bound key = %q, want it to stay %q until a reseal", got, want)
	}
}

// TestTheEnrollingCodeIsAlreadySpent closes the window the enrollment itself
// opens: the confirming code was displayed to whoever was standing there.
func TestTheEnrollingCodeIsAlreadySpent(t *testing.T) {
	f := newFixture(t)
	f.add("alice", RoleUser)
	seed := f.enroll("alice")

	_, err := f.act("user.totp.verify", func(m audit.Mutation) error {
		_, err := VerifyTOTP(context.Background(), m, f.now, f.key, "alice",
			codeAt(seed, stepAt(f.now), totpDigits))
		return err
	})
	if !errors.Is(err, ErrBadCode) {
		t.Fatalf("the enrolling code verified again: error = %v, want ErrBadCode", err)
	}
}

// TestTheBindingNamesTheOldestKeyStillNeeded is the rule that makes the
// recorded id useful: it is the key that must not be lost, so a seal under a
// newer key does not move it while ciphertexts under the older one remain.
func TestTheBindingNamesTheOldestKeyStillNeeded(t *testing.T) {
	f := newFixture(t)
	f.add("alice", RoleUser)
	f.enroll("alice")
	original := f.boundKey()

	newPath := filepath.Join(f.dir, "rotated.key")
	if _, err := secret.Create(newPath); err != nil {
		t.Fatal(err)
	}
	ring, err := secret.Load(newPath, filepath.Join(f.dir, "secret.key"))
	if err != nil {
		t.Fatal(err)
	}

	f.add("bob", RoleUser)
	seed, err := NewSeed()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.act("user.totp", func(m audit.Mutation) error {
		_, err := Enroll(context.Background(), m, RoleAdmin, f.now, ring, "bob", seed,
			codeAt(seed, stepAt(f.now), totpDigits))
		return err
	}); err != nil {
		t.Fatalf("enrolling under the rotated keyring: %v", err)
	}

	if got := f.boundKey(); got != original {
		t.Errorf("bound key moved to %q; alice's seed is still under %q", got, original)
	}
	// And the old key alone must still satisfy nothing it cannot open — a
	// keyring without the new key can no longer open bob's seed, which is what
	// the retired-key argument is about.
	if _, err := f.key.Open("totp", f.mustGet("bob").ID, f.sealedSeed(f.mustGet("bob").ID)); err == nil {
		t.Error("the retired key opened a seed sealed under the new one")
	}
}
