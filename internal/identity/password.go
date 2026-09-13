package identity

import (
	"context"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"

	"github.com/nodarynet/nodary/internal/audit"
)

// Password hashing is PBKDF2-SHA256 (docs/adr/0006-cui-boundary-and-fips.md).
//
// argon2id is the stronger password KDF and is not FIPS-approved. ADR 0006 puts
// nodary inside a CUI boundary, and arguing to an assessor that password
// hashing does not protect CUI confidentiality is more expensive than the
// change — the argument may well be right and it still costs a meeting.
const (
	// pbkdf2SaltBytes is 16 because Go's FIPS module refuses a salt shorter
	// than 128 bits. Measured, not chosen: under GODEBUG=fips140=only a 15-byte
	// salt is an error, so this is a correctness requirement rather than a
	// preference (docs/spike-fips-and-manifest.md).
	pbkdf2SaltBytes = 16
	// pbkdf2Iterations is ours to pick: Go enforces no floor. It is stored with
	// each hash so it can be raised without invalidating anything.
	pbkdf2Iterations = 600_000
	pbkdf2KeyBytes   = 32
	pbkdf2Scheme     = "pbkdf2-sha256"
)

var (
	// ErrBadPassword is a failed verification. It is deliberately the same
	// error whether the user exists or the password is wrong: the login path
	// must not say which.
	ErrBadPassword = errors.New("incorrect username or password")
	// ErrNoPassword means the account has never had one set. R5's one-time
	// setup URL is how the first administrator gets one, and until then this is
	// the honest answer rather than a hash that can never match.
	ErrNoPassword = errors.New("no password is set for this account")
	// ErrWeakPassword is a password below the floor.
	ErrWeakPassword = errors.New("password is too short")
)

// minPasswordRunes is a floor, not a policy. Composition rules push people
// towards predictable substitutions; length is what actually helps, and the
// active profile has no say because a profile adjusts ceremony and retention,
// never whether a control exists.
const minPasswordRunes = 12

// HashPassword produces a self-describing hash: scheme, iterations, salt, key.
//
// Everything needed to verify it and to notice that it was made under older
// parameters is in the string, so raising the cost is a one-line change and
// existing hashes keep working until their owner next logs in.
func HashPassword(plain string) (string, error) {
	if n := len([]rune(plain)); n < minPasswordRunes {
		return "", fmt.Errorf("%w: %d characters, want at least %d", ErrWeakPassword, n, minPasswordRunes)
	}
	salt := make([]byte, pbkdf2SaltBytes)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("generating a salt: %w", err)
	}
	return encodeHash(plain, salt, pbkdf2Iterations)
}

func encodeHash(plain string, salt []byte, iterations int) (string, error) {
	key, err := pbkdf2.Key(sha256.New, plain, salt, iterations, pbkdf2KeyBytes)
	if err != nil {
		return "", fmt.Errorf("hashing the password: %w", err)
	}
	return strings.Join([]string{
		pbkdf2Scheme,
		strconv.Itoa(iterations),
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key),
	}, "$"), nil
}

// checkPassword verifies a plaintext against a stored hash and reports whether
// the hash should be replaced because it was made under older parameters.
func checkPassword(stored, plain string) (ok, stale bool) {
	parts := strings.Split(stored, "$")
	if len(parts) != 4 || parts[0] != pbkdf2Scheme {
		return false, false
	}
	iterations, err := strconv.Atoi(parts[1])
	if err != nil || iterations < 1 {
		return false, false
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[2])
	if err != nil {
		return false, false
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[3])
	if err != nil {
		return false, false
	}
	got, err := pbkdf2.Key(sha256.New, plain, salt, iterations, len(want))
	if err != nil {
		return false, false
	}
	if subtle.ConstantTimeCompare(got, want) != 1 {
		return false, false
	}
	return true, iterations < pbkdf2Iterations || len(salt) < pbkdf2SaltBytes
}

// SetPassword stores a password. It takes an audit.Mutation, so setting one
// cannot happen without a record — and the record never carries the password.
func SetPassword(ctx context.Context, m audit.Mutation, by Role, name, plain string) error {
	if err := Authorize(by, PermUserManage); err != nil {
		return err
	}
	u, err := Get(ctx, m.Tx(), name)
	if err != nil {
		return err
	}
	hash, err := HashPassword(plain)
	if err != nil {
		return err
	}
	if _, err := m.Tx().ExecContext(ctx,
		`UPDATE user SET password_hash = ? WHERE id = ?`, hash, u.ID); err != nil {
		return fmt.Errorf("setting the password for %q: %w", name, err)
	}
	m.Detail("user", u.Name)
	return nil
}

// Rehash is a password upgrade waiting for a transaction to write it in.
//
// The hashing is already done by the time one of these exists — that is the
// point of it. See VerifyPassword.
type Rehash struct {
	userID string
	// was is the stored hash the verification actually ran against, so the
	// write can refuse to clobber a password changed in between.
	was   string
	fresh string
}

// Pending reports whether there is anything to write.
func (r Rehash) Pending() bool { return r.fresh != "" }

// Apply writes the upgrade inside the transaction of the login that earned it.
//
// Guarded on the hash it verified against: between the read and this write the
// account's password may have been changed by somebody else, and rehashing the
// old plaintext over a new password would silently roll it back.
func (r Rehash) Apply(ctx context.Context, m audit.Mutation) error {
	if !r.Pending() {
		return nil
	}
	res, err := m.Tx().ExecContext(ctx,
		`UPDATE user SET password_hash = ? WHERE id = ? AND password_hash = ?`,
		r.fresh, r.userID, r.was)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 1 {
		m.Detail("password_rehashed", true)
	}
	return nil
}

// VerifyPassword authenticates a password against a read-only handle, and
// reports any stored-parameter upgrade the caller should write.
//
// **It holds no transaction, and that is the whole point.** PBKDF2 at 600,000
// iterations measures around 68ms, and internal/store caps the writer pool at
// one connection by design — so running the hash inside the login's write
// transaction let roughly fifteen unauthenticated attempts a second hold the
// write lock continuously, blocking audit records, agent status posts and usage
// rows behind somebody who had not authenticated. The rehash still belongs in
// the same transaction as the login it authorized; only the arithmetic moved
// out, and Rehash is what carries the result across.
//
// Every failure is ErrBadPassword. An unknown account, a suspended one and one
// with no password set are indistinguishable to a caller — the comment on
// ErrBadPassword always said so and the code did not, which is username
// enumeration on the one endpoint reachable before any credential exists. The
// real reason travels in `reason` instead, for the audit record: an operator
// investigating gets it and an attacker does not.
func VerifyPassword(ctx context.Context, q Querier, name, plain string) (u User, _ Rehash, reason string, err error) {
	u, getErr := Get(ctx, q, name)
	if getErr != nil {
		// Hashed anyway. Returning here without doing the work answers an
		// unknown account in microseconds and a real one in 68ms, which is the
		// same enumeration oracle by a different route.
		equalizeTiming(plain)
		return User{}, Rehash{}, "no such account", ErrBadPassword
	}
	if !u.Active() {
		equalizeTiming(plain)
		return User{}, Rehash{}, "account is " + string(u.State), ErrBadPassword
	}

	var stored *string
	if err := q.QueryRowContext(ctx,
		`SELECT password_hash FROM user WHERE id = ?`, u.ID).Scan(&stored); err != nil {
		return User{}, Rehash{}, "", fmt.Errorf("reading the password for %q: %w", name, err)
	}
	if stored == nil {
		equalizeTiming(plain)
		return User{}, Rehash{}, "no password is set", ErrBadPassword
	}

	ok, stale := checkPassword(*stored, plain)
	if !ok {
		return User{}, Rehash{}, "wrong password", ErrBadPassword
	}
	if !stale {
		return u, Rehash{}, "", nil
	}
	// Computed here rather than in Apply, so the second expensive operation is
	// also outside the caller's transaction.
	fresh, err := HashPassword(plain)
	if err != nil {
		// An upgrade that cannot be computed is not a reason to refuse a
		// correct password; it is simply not upgraded this time.
		return u, Rehash{}, "", nil
	}
	return u, Rehash{userID: u.ID, was: *stored, fresh: fresh}, "", nil
}

// equalizeTiming spends what a real verification would spend.
//
// Against a hash computed once and reused, because the cost being equalized is
// the comparison's, not a salt's. sync.OnceValue rather than a constant so it
// tracks pbkdf2Iterations instead of going stale the moment that changes.
var timingHash = sync.OnceValue(func() string {
	h, err := HashPassword(strings.Repeat("x", minPasswordRunes))
	if err != nil {
		return ""
	}
	return h
})

func equalizeTiming(plain string) {
	if h := timingHash(); h != "" {
		checkPassword(h, plain)
	}
}
