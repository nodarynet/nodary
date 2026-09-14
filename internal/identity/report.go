package identity

import (
	"time"

	"github.com/nodarynet/nodary/internal/audit"
)

// The projections of an account and a credential that a front end renders.
//
// They live here rather than in either front end because both render them and
// both must render the same thing: docs/specs/10-cli.md §1's constraint is that
// the CLI and the HTTP API call the same core functions, and a listing is where
// that quietly stops being true. It had — `nodary token list` showed a
// credential's name, its expiry, when it was last used and the outstanding join
// tokens, and `GET /tokens` showed none of them, so the same question answered
// differently depending on which road it took. The shapes are the CLI's,
// because those are the ones a `--format json` consumer already depends on.
//
// **There is no field for a secret in any of them.** docs/specs/10-cli.md §4
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
