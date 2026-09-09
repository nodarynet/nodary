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

// Authenticate a password, and rehash on success when the stored parameters are
// behind.
//
// It takes an audit.Mutation because the rehash is a write and belongs in the
// same transaction as the login it authorized — the alternative is a successful
// login that silently failed to upgrade, forever.
func VerifyPassword(ctx context.Context, m audit.Mutation, name, plain string) (User, error) {
	u, err := Get(ctx, m.Tx(), name)
	if err != nil {
		// Same error as a wrong password: the login path must not say which.
		return User{}, ErrBadPassword
	}
	if !u.Active() {
		return User{}, fmt.Errorf("%w: %q is %s", ErrNotActive, name, u.State)
	}

	var stored *string
	if err := m.Tx().QueryRowContext(ctx,
		`SELECT password_hash FROM user WHERE id = ?`, u.ID).Scan(&stored); err != nil {
		return User{}, fmt.Errorf("reading the password for %q: %w", name, err)
	}
	if stored == nil {
		return User{}, ErrNoPassword
	}

	ok, stale := checkPassword(*stored, plain)
	if !ok {
		return User{}, ErrBadPassword
	}
	if stale {
		// Replaced on the next successful verification, which is the only
		// moment the plaintext is available to rehash with.
		if fresh, err := HashPassword(plain); err == nil {
			if _, err := m.Tx().ExecContext(ctx,
				`UPDATE user SET password_hash = ? WHERE id = ?`, fresh, u.ID); err == nil {
				m.Detail("password_rehashed", true)
			}
		}
	}
	return u, nil
}
