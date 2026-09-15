package identity

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/nodarynet/nodary/internal/audit"
)

// The projections of an account and a credential that a front end renders.
//
// They live here rather than in either front end because both render them and
// both must render the same thing: dev/specs/10-cli.md §1's constraint is that
// the CLI and the HTTP API call the same core functions, and a listing is where
// that quietly stops being true. It had — `nodary token list` showed a
// credential's name, its expiry, when it was last used and the outstanding join
// tokens, and `GET /tokens` showed none of them, so the same question answered
// differently depending on which road it took. The shapes are the CLI's,
// because those are the ones a `--format json` consumer already depends on.
//
// **There is no field for a secret in any of them.** dev/specs/10-cli.md §4
// keeps a plaintext credential out of every list; the prefix is what identifies
// one to a human.

// UserReport is the stable shape of an account.
type UserReport struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	// Email is omitted for a caller who does not manage users. 07 §1 gives a
	// viewer "read state", and a contact address is personal data attached to a
	// person rather than fleet state.
	Email        string `json:"email,omitempty"`
	Role         string `json:"role"`
	State        string `json:"state"`
	TOTPEnrolled bool   `json:"totp_enrolled"`
	CreatedAt    string `json:"created_at"`
}

func NewUserReport(u User) UserReport {
	return UserReport{
		ID:           u.ID,
		Name:         u.Name,
		Email:        u.Email,
		Role:         string(u.Role),
		State:        string(u.State),
		TOTPEnrolled: u.TOTPEnrolled,
		CreatedAt:    u.CreatedAt.Format(audit.TimeFormat),
	}
}

// TokenState says why a credential does or does not work, in one word.
func TokenState(t Token, now time.Time) string {
	switch {
	case t.Revoked():
		return "revoked"
	case t.Expired(now):
		return "expired"
	}
	return "active"
}

// TokenReport is the stable shape of a credential.
type TokenReport struct {
	ID         string `json:"id"`
	UserID     string `json:"user_id"`
	Kind       string `json:"kind"`
	Prefix     string `json:"prefix"`
	Name       string `json:"name,omitempty"`
	State      string `json:"state"`
	Unattended bool   `json:"unattended,omitempty"`
	ExpiresAt  string `json:"expires_at,omitempty"`
	RevokedAt  string `json:"revoked_at,omitempty"`
	LastUsedAt string `json:"last_used_at,omitempty"`
	CreatedAt  string `json:"created_at"`
}

func NewTokenReport(t Token, now time.Time) TokenReport {
	r := TokenReport{
		ID:         t.ID,
		UserID:     t.UserID,
		Kind:       string(t.Kind),
		Prefix:     t.Prefix,
		Name:       t.Name,
		State:      TokenState(t, now),
		Unattended: t.Unattended,
		CreatedAt:  t.CreatedAt.Format(audit.TimeFormat),
	}
	for _, f := range []struct {
		at  time.Time
		out *string
	}{{t.ExpiresAt, &r.ExpiresAt}, {t.RevokedAt, &r.RevokedAt}, {t.LastUsedAt, &r.LastUsedAt}} {
		if !f.at.IsZero() {
			*f.out = f.at.Format(audit.TimeFormat)
		}
	}
	return r
}

func TokenReports(ts []Token, now time.Time) []TokenReport {
	out := make([]TokenReport, len(ts))
	for i, t := range ts {
		out[i] = NewTokenReport(t, now)
	}
	return out
}

// JoinReport is the stable shape of a join token.
type JoinReport struct {
	ID        string `json:"id"`
	Prefix    string `json:"prefix"`
	UsesLeft  int    `json:"uses_left"`
	ExpiresAt string `json:"expires_at"`
	CreatedBy string `json:"created_by"`
	CreatedAt string `json:"created_at"`
}

func JoinReports(js []JoinToken) []JoinReport {
	out := make([]JoinReport, len(js))
	for i, j := range js {
		out[i] = JoinReport{
			ID:        j.ID,
			Prefix:    j.Prefix,
			UsesLeft:  j.UsesLeft,
			ExpiresAt: j.ExpiresAt.Format(audit.TimeFormat),
			CreatedBy: j.CreatedBy,
			CreatedAt: j.CreatedAt.Format(audit.TimeFormat),
		}
	}
	return out
}

// DefaultLifetime per kind, from dev/specs/02-enrollment.md §4: a service key
// defaults to a year, a personal token is session-scoped or explicit — ninety
// days is the explicit default — and a join token lives minutes to hours.
var DefaultLifetime = map[Kind]time.Duration{
	KindPersonal: 90 * 24 * time.Hour,
	KindService:  365 * 24 * time.Hour,
	KindJoin:     time.Hour,
}

// ParseLifetime reads a duration, accepting days and the word "never".
//
// Go's own parser stops at hours, and every lifetime an operator thinks in is
// longer than that. "never" is spelled out rather than given as 0, because a
// credential that never expires should be typed deliberately.
func ParseLifetime(s string) (time.Duration, error) {
	switch s {
	case "":
		return 0, fmt.Errorf("an empty lifetime is not a duration")
	case "never":
		return 0, nil
	}
	if days, ok := strings.CutSuffix(s, "d"); ok {
		n, err := strconv.Atoi(days)
		if err != nil || n < 0 {
			return 0, fmt.Errorf("%q is not a number of days", s)
		}
		return time.Duration(n) * 24 * time.Hour, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("%q is not a duration (try 30d, 12h, or never)", s)
	}
	if d < 0 {
		return 0, fmt.Errorf("%q is a negative lifetime", s)
	}
	return d, nil
}

// ExpiryFor turns a requested lifetime into the instant a credential of this
// kind expires. A zero time means it never does.
//
// Both front ends call it, so a credential minted over HTTP lives as long as
// the same request on the host. `POST /tokens` used to hardcode ninety days,
// which made it silently wrong in both directions: it ignored `--expires`, and
// it ignored a profile capping credentials at less — so a regulated install's
// `token_max_ttl_days` was enforced on the CLI and not on the API beside it.
// The cap itself is attest.AllowTokenLifetime and still belongs to the caller,
// because only a caller knows the active profile.
func ExpiryFor(kind Kind, lifetime string, now time.Time) (time.Time, error) {
	d := DefaultLifetime[kind]
	if lifetime != "" {
		var err error
		if d, err = ParseLifetime(lifetime); err != nil {
			return time.Time{}, err
		}
	}
	if d == 0 {
		return time.Time{}, nil
	}
	return now.Add(d), nil
}
