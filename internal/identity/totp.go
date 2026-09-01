package identity

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"database/sql"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/nodarynet/nodary/internal/audit"
	"github.com/nodarynet/nodary/internal/secret"
)

// TOTP as RFC 6238 defines it, with the parameters every authenticator
// application assumes: HMAC-SHA1, six digits, a thirty-second step.
//
// Written rather than depended on. The algorithm is forty lines and the
// specification publishes its own test vectors, so correctness is checked
// against the standard itself; the usual library brings QR-code and image
// packages an appliance never renders.
//
// SHA-1 here is not a weakness. HOTP uses it as an HMAC, whose security rests
// on the key rather than on collision resistance, and RFC 6238 §1.2 keeps it
// for exactly that reason. The alternative is codes no authenticator app
// accepts.
const (
	// totpDigits is what a user types.
	totpDigits = 6
	// totpStepSeconds is the window a code stands for.
	totpStepSeconds = 30
	// totpSeedBytes is 20: RFC 4226 §4 requires at least 128 bits and
	// recommends 160, which is also the HMAC-SHA1 block-friendly size every
	// provisioning URI in the wild uses.
	totpSeedBytes = 20
	// totpSkew is how many steps either side of now are accepted, per RFC 6238
	// §5.2's allowance for clock drift and typing time. One step is 30 seconds
	// in each direction; more turns a code into a password.
	totpSkew = 1
)

// seedEncoding is the base32 alphabet every authenticator expects in an
// otpauth:// URI: uppercase, unpadded.
var seedEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)

var (
	// ErrNotEnrolled is a TOTP check against a user who has no seed. Exit 3.
	ErrNotEnrolled = errors.New("user is not enrolled in TOTP")
	// ErrBadCode is a code that does not verify — wrong, expired, or already
	// spent. The three are deliberately one error: telling a caller which
	// tells an attacker which.
	ErrBadCode = errors.New("that code is not valid")
	// ErrNotActive is an operation on a user who cannot authenticate. Exit 3.
	ErrNotActive = errors.New("user is not active")
)

// NewSeed mints a TOTP seed.
func NewSeed() ([]byte, error) {
	seed := make([]byte, totpSeedBytes)
	if _, err := rand.Read(seed); err != nil {
		return nil, fmt.Errorf("generating a TOTP seed: %w", err)
	}
	return seed, nil
}

// EncodeSeed renders a seed for an operator to type into an authenticator.
func EncodeSeed(seed []byte) string { return seedEncoding.EncodeToString(seed) }

// URI is the otpauth:// provisioning URI a QR code encodes.
//
// The issuer appears twice — in the label and as a parameter — because that is
// what the de facto specification asks for: older applications read the label
// prefix and newer ones read the parameter.
func URI(issuer, account string, seed []byte) string {
	label := url.PathEscape(issuer + ":" + account)
	q := url.Values{
		"secret":    {EncodeSeed(seed)},
		"issuer":    {issuer},
		"algorithm": {"SHA1"},
		"digits":    {fmt.Sprint(totpDigits)},
		"period":    {fmt.Sprint(totpStepSeconds)},
	}
	return "otpauth://totp/" + label + "?" + q.Encode()
}

// stepAt is the counter a time falls in.
func stepAt(t time.Time) int64 { return t.UTC().Unix() / totpStepSeconds }

// codeAt is RFC 4226's HOTP over an RFC 6238 time step.
//
// digits is a parameter only so the RFC's published eight-digit vectors can be
// checked; everything in nodary uses totpDigits.
func codeAt(seed []byte, step int64, digits int) string {
	var counter [8]byte
	binary.BigEndian.PutUint64(counter[:], uint64(step))

	mac := hmac.New(sha1.New, seed)
	mac.Write(counter[:])
	sum := mac.Sum(nil)

	// RFC 4226 §5.4 dynamic truncation: the low nibble of the last byte picks
	// a four-byte window, and the top bit is cleared so the result does not
	// depend on how a platform signs an integer.
	offset := sum[len(sum)-1] & 0x0f
	value := binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff

	mod := uint32(1)
	for range digits {
		mod *= 10
	}
	return fmt.Sprintf("%0*d", digits, value%mod)
}

// normaliseCode accepts what an authenticator displays. Applications group the
// digits — "123 456" — and an operator pasting that should not be told their
// code is wrong.
//
// The length check is redundant against the comparison, and measured as such:
// ConstantTimeCompare returns 0 for operands of different lengths, so removing
// it breaks no test. It stays for two reasons — it declines to run three HMACs
// over input that cannot match, and it keeps the digit count a property of
// this file rather than an emergent consequence of how the comparison is
// spelled.
func normaliseCode(code string) (string, bool) {
	var b strings.Builder
	for _, r := range code {
		switch {
		case r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == ' ' || r == '-':
		default:
			return "", false
		}
	}
	s := b.String()
	return s, len(s) == totpDigits
}

// verifyCode reports the step a code matches, or false.
//
// A step at or below floor is refused however well it verifies: a code is spent
// once used. Without that, a code stands for its whole thirty-second window —
// ninety seconds once skew is allowed — and anyone who saw it typed can replay
// it, which is precisely what docs/specs/07-identity-audit.md §2's re-entry is
// there to prevent.
func verifyCode(seed []byte, code string, now time.Time, floor int64) (int64, bool) {
	digits, ok := normaliseCode(code)
	if !ok {
		return 0, false
	}
	current := stepAt(now)
	matched, found := int64(0), false
	for delta := -totpSkew; delta <= totpSkew; delta++ {
		step := current + int64(delta)
		if step <= floor {
			continue
		}
		// Constant time, and no early exit: comparing all candidates keeps the
		// work independent of which one matched.
		if subtle.ConstantTimeCompare([]byte(codeAt(seed, step, totpDigits)), []byte(digits)) == 1 {
			matched, found = step, true
		}
	}
	return matched, found
}

// Issuer is the label an authenticator shows beside a code.
const Issuer = "nodary"

// Enroll seals a seed for a user, after that user has proved the seed reached
// their authenticator.
//
// The confirming code is the whole point of the two-argument shape. Marking an
// enrollment active on display alone means a mis-scanned QR locks the account
// out, and R1 has no reset path that is not an admin enrolling them again.
// Nothing is written until the code verifies, so an abandoned enrollment leaves
// the account exactly as it was rather than half-configured.
//
// Re-enrolling replaces the seed, which is the reset path.
func Enroll(ctx context.Context, m audit.Mutation, by Role, now time.Time, k *secret.Key,
	name string, seed []byte, code string) (User, error) {
	if err := Authorize(by, PermUserManage); err != nil {
		return User{}, err
	}
	if len(seed) != totpSeedBytes {
		return User{}, fmt.Errorf("%w: a seed must be %d bytes", ErrBadCode, totpSeedBytes)
	}
	u, err := Get(ctx, m.Tx(), name)
	if err != nil {
		return User{}, err
	}
	if !u.Active() {
		return User{}, fmt.Errorf("%w: %q is %s", ErrNotActive, name, u.State)
	}
	step, ok := verifyCode(seed, code, now, -1)
	if !ok {
		return User{}, fmt.Errorf("%w: enrollment was not confirmed", ErrBadCode)
	}

	// The first seal is what binds this database to this key. Before it there
	// is nothing to lose; after it, losing the key is unrecoverable.
	if err := BindKey(ctx, m.Tx(), now, k); err != nil {
		return User{}, err
	}
	sealed, err := k.Seal("totp", u.ID, seed)
	if err != nil {
		return User{}, fmt.Errorf("sealing the TOTP seed for %q: %w", name, err)
	}

	// The confirming code is spent as it is stored. It has already been shown
	// to whoever was watching the enrollment.
	if _, err := m.Tx().ExecContext(ctx,
		`UPDATE user SET totp_secret_enc = ?, totp_enrolled_at = ?, totp_last_step = ?
		 WHERE id = ?`,
		sealed, now.UTC().Truncate(time.Millisecond).Format(audit.TimeFormat), step, u.ID,
	); err != nil {
		return User{}, fmt.Errorf("recording the TOTP enrollment for %q: %w", name, err)
	}

	m.Detail("name", u.Name)
	// Replacing a seed is a different event from adding one: it is how an
	// account locked out of its authenticator gets back in, and it is the
	// event worth noticing in a chain.
	m.Detail("replaced", u.TOTPEnrolled)
	u.TOTPEnrolled = true
	return u, nil
}

// VerifyTOTP consumes one code for a user.
//
// It mutates — spending the step is the point — so it takes a Mutation and
// commits with whatever act it authorises. In docs/specs/07-identity-audit.md
// §2's terms it is the re-authentication, and it belongs in the same
// transaction as the change it attests to.
func VerifyTOTP(ctx context.Context, m audit.Mutation, now time.Time, k *secret.Key,
	name, code string) (User, error) {
	u, err := Get(ctx, m.Tx(), name)
	if err != nil {
		return User{}, err
	}
	if !u.Active() {
		return User{}, fmt.Errorf("%w: %q is %s", ErrNotActive, name, u.State)
	}

	var (
		sealed []byte
		last   sql.NullInt64
	)
	if err := m.Tx().QueryRowContext(ctx,
		`SELECT totp_secret_enc, totp_last_step FROM user WHERE id = ?`, u.ID,
	).Scan(&sealed, &last); err != nil {
		return User{}, fmt.Errorf("reading the TOTP seed for %q: %w", name, err)
	}
	if sealed == nil {
		return User{}, fmt.Errorf("%w: %q", ErrNotEnrolled, name)
	}
	seed, err := k.Open("totp", u.ID, sealed)
	if err != nil {
		return User{}, fmt.Errorf("opening the TOTP seed for %q: %w", name, err)
	}

	floor := int64(-1)
	if last.Valid {
		floor = last.Int64
	}
	step, ok := verifyCode(seed, code, now, floor)
	if !ok {
		return User{}, ErrBadCode
	}

	// The condition is what spends the code rather than merely recording it.
	//
	// Deliberately redundant, and measured as such: writers serialise under
	// the store's immediate transactions, so removing the WHERE clause breaks
	// no test. It stays because the guarantee would then rest entirely on a
	// connection setting made in another package, which a later change to that
	// setting could remove without anything here failing.
	res, err := m.Tx().ExecContext(ctx,
		`UPDATE user SET totp_last_step = ?
		 WHERE id = ? AND (totp_last_step IS NULL OR totp_last_step < ?)`, step, u.ID, step)
	if err != nil {
		return User{}, fmt.Errorf("spending the TOTP code for %q: %w", name, err)
	}
	if n, err := res.RowsAffected(); err != nil || n != 1 {
		return User{}, ErrBadCode
	}
	m.Detail("totp", "verified")
	return u, nil
}
