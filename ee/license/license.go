// Package license verifies and stores the commercial licence key.
//
// Commercial. See ee/LICENSE.
//
// Two properties from docs/adr/0005-editions-and-the-advisory-feed.md are not
// negotiable and are implemented here rather than promised:
//
//  1. An unlicensed install carries every commercial verb and explains what it
//     would produce. Nothing in this package hides a feature; it answers
//     whether one is licensed and the verb decides what to say.
//  2. An expired licence never makes existing evidence unreadable. Nothing here
//     touches the chain, `audit export`, or a bundle already written. Expiry
//     stops new bundles being produced and does nothing else.
package license

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/nodarynet/nodary/internal/audit"
	"github.com/nodarynet/nodary/internal/identity"
	"github.com/nodarynet/nodary/internal/minisign"
)

// The public key this build trusts. A release stamps the real one in; a
// development build carries the placeholder and refuses to verify anything,
// which is the same shape install.sh uses for its release key.
//
// It is a variable rather than a constant so the release build can set it with
// -ldflags, and so a test can point at a key it generated.
var TrustedKey = placeholder

const placeholder = "untrusted comment: placeholder\nPLACEHOLDER-NOT-A-REAL-KEY\n"

var (
	ErrNone    = errors.New("no licence has been applied")
	ErrExpired = errors.New("the licence has expired")
	ErrInvalid = errors.New("the licence is not valid")
)

// License is what a customer is entitled to.
type License struct {
	Customer string `toml:"customer"`
	Issued   string `toml:"issued"`
	Expires  string `toml:"expires"`
	// Features is deliberately a list rather than a set of booleans: a licence
	// naming a feature this build does not know about must not fail to parse,
	// because the customer's binary is older than the licence more often than
	// the reverse.
	Features []string `toml:"features"`
}

type document struct {
	License License `toml:"license"`
}

// Feature names. One per paid capability.
const FeatureEvidence = "evidence"

// Parse reads and verifies a licence, and reports whether it has expired.
//
// Expiry is returned as a distinct error rather than folded into invalidity: an
// expired licence is a customer to talk to, an invalid one is a support
// incident, and telling them apart is the difference between the two
// conversations.
func Parse(src, signature string, now time.Time) (License, error) {
	pub, err := minisign.ParsePublicKey(TrustedKey)
	if err != nil {
		if strings.Contains(TrustedKey, "PLACEHOLDER") {
			return License{}, fmt.Errorf("%w: %w", ErrInvalid, minisign.ErrPlaceholder)
		}
		return License{}, fmt.Errorf("%w: the trusted key is unreadable: %w", ErrInvalid, err)
	}
	if _, err := minisign.Verify(pub, []byte(src), signature); err != nil {
		return License{}, fmt.Errorf("%w: %w", ErrInvalid, err)
	}

	var doc document
	md, err := toml.Decode(src, &doc)
	if err != nil {
		return License{}, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	// Unlike a policy profile, an unknown key here is tolerated: see Features.
	_ = md
	l := doc.License

	if strings.TrimSpace(l.Customer) == "" {
		return License{}, fmt.Errorf("%w: it names no customer", ErrInvalid)
	}
	expiry, err := time.Parse(time.RFC3339, l.Expires)
	if err != nil {
		return License{}, fmt.Errorf("%w: expires %q is not an RFC 3339 timestamp", ErrInvalid, l.Expires)
	}
	if now.After(expiry) {
		return l, fmt.Errorf("%w: it ran out on %s", ErrExpired, expiry.UTC().Format(time.DateOnly))
	}
	return l, nil
}

// Covers reports whether the licence entitles this install to a feature.
func (l License) Covers(feature string) bool {
	for _, f := range l.Features {
		if f == feature || f == "*" {
			return true
		}
	}
	return false
}

// Active reads the applied licence and verifies it again.
//
// Re-verifying on every read rather than trusting a stored verdict: the row is
// in a database an administrator can write, and a licence that was checked once
// at apply time is a licence that can be edited afterwards.
func Active(ctx context.Context, q interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}, now time.Time) (License, error) {
	var src, sig string
	err := q.QueryRowContext(ctx, `SELECT source, signature FROM license WHERE singleton = 1`).
		Scan(&src, &sig)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return License{}, ErrNone
	case err != nil:
		return License{}, fmt.Errorf("reading the licence: %w", err)
	}
	return Parse(src, sig, now)
}

// Apply records a licence. It takes an audit.Mutation, so applying one cannot
// happen without a record.
func Apply(ctx context.Context, m audit.Mutation, by identity.Role, now time.Time, src, sig string) (License, error) {
	if err := identity.Authorize(by, identity.PermConfigWrite); err != nil {
		return License{}, err
	}
	l, err := Parse(src, sig, now)
	if err != nil {
		// An expired licence is refused at apply: accepting one would record a
		// grant that was never in force.
		return License{}, err
	}
	if _, err := m.Tx().ExecContext(ctx, `
		INSERT INTO license (singleton, source, signature, applied_at) VALUES (1, ?, ?, ?)
		ON CONFLICT (singleton) DO UPDATE SET
			source = excluded.source, signature = excluded.signature, applied_at = excluded.applied_at`,
		src, sig, now.UTC().Truncate(time.Millisecond).Format(audit.TimeFormat),
	); err != nil {
		return License{}, fmt.Errorf("applying the licence: %w", err)
	}
	m.Detail("customer", l.Customer)
	m.Detail("expires", l.Expires)
	m.Detail("features", strings.Join(l.Features, ","))
	return l, nil
}
