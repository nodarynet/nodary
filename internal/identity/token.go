package identity

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/nodarynet/nodary/internal/audit"
)

// Kind is a token's purpose: docs/specs/02-enrollment.md §4.
type Kind string

const (
	// KindPersonal authenticates a user to the CLI and the API.
	KindPersonal Kind = "pt"
	// KindService authenticates a caller to the inference gateway.
	KindService Kind = "sk"
	// KindJoin enrolls a node, and belongs to no user.
	KindJoin Kind = "jt"
)

// Kinds is every kind, in the order §4 lists them.
var Kinds = []Kind{KindJoin, KindService, KindPersonal}

// userKinds are the kinds that belong to a user and live in the token table.
var userKinds = []Kind{KindPersonal, KindService}

// Prefix is what the plaintext starts with.
//
// A distinct prefix per kind is not decoration: it makes a leaked credential
// greppable in a log and recognisable to a secret scanner, which is the
// difference between finding out from a scanner and finding out from an
// incident.
func (k Kind) Prefix() string { return "nodary_" + string(k) + "_" }

// Valid reports whether k is one of the three kinds.
func (k Kind) Valid() bool { return slices.Contains(Kinds, k) }

// ParseKind reads a kind, accepting the bare form and the prefix.
func ParseKind(s string) (Kind, error) {
	k := Kind(strings.TrimSuffix(strings.TrimPrefix(s, "nodary_"), "_"))
	if !k.Valid() {
		return "", fmt.Errorf("%w %q (want pt, sk or jt)", ErrUnknownKind, s)
	}
	return k, nil
}

var (
	// ErrUnknownKind is a token kind outside the three. Exit code 2.
	ErrUnknownKind = errors.New("unknown token kind")
	// ErrBadToken is a credential that authenticates as nothing. It covers a
	// malformed string and an unknown one together, deliberately: the two are
	// the only cases where the presenter has not proved they hold a real
	// token, so they are the only cases worth being uniform about.
	ErrBadToken = errors.New("that credential is not valid")
	// ErrTokenRevoked is a real token that was withdrawn. Exit code 3.
	ErrTokenRevoked = errors.New("that credential has been revoked")
	// ErrTokenExpired is a real token past its date. Exit code 3.
	ErrTokenExpired = errors.New("that credential has expired")
	// ErrNoTokens reports that a revoke names nothing. Exit code 1.
	ErrNoTokens = errors.New("no such token")
)

// secretBytes is the random part of a token: 256 bits.
//
// Stored as SHA-256 rather than under a slow hash, which
// docs/specs/02-enrollment.md §4 asks for and which is right. A password needs
// a KDF because it is low-entropy and an offline attacker runs a dictionary;
// there is no dictionary for a uniform 256-bit value, and an attacker who can
// invert SHA-256 on one has already won everywhere. A KDF here would only put
// a deliberate delay on every authenticated request.
const secretBytes = 32

// displayPrefixChars is how much of the secret `token list` shows.
//
// Enough to tell two credentials apart in a report, and 40 bits out of 256, so
// what remains is not a target. GitHub shows the same amount for the same
// reason: an operator revoking one of five tokens has to know which.
const displayPrefixChars = 8

// Token is one row of the token table. There is no field for the secret: a
// struct that carries one is a struct that reaches a log line eventually.
type Token struct {
	ID         string
	UserID     string
	Kind       Kind
	Prefix     string
	Name       string
	ExpiresAt  time.Time
	RevokedAt  time.Time
	LastUsedAt time.Time
	CreatedAt  time.Time
}

// Revoked reports whether the token has been withdrawn.
func (t Token) Revoked() bool { return !t.RevokedAt.IsZero() }

// Expired reports whether the token is past its date at now. A zero ExpiresAt
// never expires.
func (t Token) Expired(now time.Time) bool {
	return !t.ExpiresAt.IsZero() && !now.Before(t.ExpiresAt)
}

// Usable reports whether the token would authenticate at now, ignoring the
// state of the user it belongs to.
func (t Token) Usable(now time.Time) bool { return !t.Revoked() && !t.Expired(now) }

// hashToken is what the database stores: SHA-256 over the whole presented
// string, prefix included, so authentication hashes exactly what was pasted.
func hashToken(presented string) string {
	sum := sha256.Sum256([]byte(presented))
	return hex.EncodeToString(sum[:])
}

// mintSecret returns a plaintext token of the given kind.
func mintSecret(k Kind) (string, error) {
	b := make([]byte, secretBytes)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generating a token: %w", err)
	}
	return k.Prefix() + strings.ToLower(idAlphabet.EncodeToString(b)), nil
}

// displayPrefix is the non-secret span kept for reports.
func displayPrefix(plaintext string, k Kind) string {
	body := strings.TrimPrefix(plaintext, k.Prefix())
	if len(body) > displayPrefixChars {
		body = body[:displayPrefixChars]
	}
	return k.Prefix() + body
}

// MintToken issues a personal token or a service key for a user.
//
// The plaintext is returned and never stored. It is the only moment it exists
// outside the holder's hands, which is what docs/specs/10-cli.md §4 means by
// printed exactly once.
func MintToken(ctx context.Context, m audit.Mutation, by Role, now time.Time,
	userName string, kind Kind, name string, expires time.Time) (Token, string, error) {
	if err := Authorize(by, PermTokenManage); err != nil {
		return Token{}, "", err
	}
	if !slices.Contains(userKinds, kind) {
		return Token{}, "", fmt.Errorf("%w %q for a user (want pt or sk)", ErrUnknownKind, kind)
	}
	if name != "" {
		if err := checkEmail(name); err != nil {
			return Token{}, "", fmt.Errorf("%w: a token label may not contain whitespace", ErrBadName)
		}
	}
	u, err := Get(ctx, m.Tx(), userName)
	if err != nil {
		return Token{}, "", err
	}
	if !u.Active() {
		return Token{}, "", fmt.Errorf("%w: %q is %s", ErrNotActive, userName, u.State)
	}
	if !expires.IsZero() && !expires.After(now) {
		return Token{}, "", fmt.Errorf("%w: an expiry of %s is already past",
			ErrBadName, expires.UTC().Format(audit.TimeFormat))
	}

	plaintext, err := mintSecret(kind)
	if err != nil {
		return Token{}, "", err
	}
	id, err := newID("tok_")
	if err != nil {
		return Token{}, "", err
	}
	t := Token{
		ID:        id,
		UserID:    u.ID,
		Kind:      kind,
		Prefix:    displayPrefix(plaintext, kind),
		Name:      name,
		ExpiresAt: truncateTime(expires),
		CreatedAt: truncateTime(now),
	}
	if _, err := m.Tx().ExecContext(ctx,
		`INSERT INTO token (id, user_id, kind, hash, prefix, name, expires_at, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		t.ID, t.UserID, string(t.Kind), hashToken(plaintext), t.Prefix, nullable(t.Name),
		nullableTime(t.ExpiresAt), formatTime(t.CreatedAt),
	); err != nil {
		return Token{}, "", fmt.Errorf("issuing a token for %q: %w", userName, err)
	}

	m.Detail("user", u.Name)
	m.Detail("kind", string(kind))
	// The display prefix, never the secret. It is what makes this record and a
	// later revocation refer to the same credential.
	m.Detail("prefix", t.Prefix)
	return t, plaintext, nil
}

// Authenticate resolves a presented credential to its user, without writing.
//
// It cannot write: last_used_at is stamped by Touch inside the audited act
// that follows, because nothing in this package may reach the database outside
// a mutation. That is the seam working as intended rather than a limitation to
// route around.
func Authenticate(ctx context.Context, q Querier, now time.Time, presented string) (User, Token, error) {
	kind, ok := kindOf(presented)
	if !ok {
		return User{}, Token{}, ErrBadToken
	}
	t, err := tokenByHash(ctx, q, hashToken(presented))
	switch {
	case errors.Is(err, ErrNoTokens):
		// Uniform with a malformed string: this is the one case where the
		// presenter has not proved they hold anything.
		return User{}, Token{}, ErrBadToken
	case err != nil:
		return User{}, Token{}, err
	}
	if t.Kind != kind {
		return User{}, Token{}, ErrBadToken
	}

	// Past this point the presenter demonstrably holds a real credential, so
	// naming its state tells them nothing they do not already have.
	if t.Revoked() {
		return User{}, Token{}, fmt.Errorf("%w: %s", ErrTokenRevoked, t.Prefix)
	}
	if t.Expired(now) {
		return User{}, Token{}, fmt.Errorf("%w on %s: %s",
			ErrTokenExpired, t.ExpiresAt.Format(audit.TimeFormat), t.Prefix)
	}

	u, err := GetByID(ctx, q, t.UserID)
	if err != nil {
		return User{}, Token{}, err
	}
	if !u.Active() {
		return User{}, Token{}, fmt.Errorf("%w: %q is %s", ErrNotActive, u.Name, u.State)
	}
	return u, t, nil
}

// Touch records that a token was used. It runs inside the act it authorised,
// so a credential's last use and the change it made commit together.
//
// An empty id is an error rather than a no-op. A caller reaching here without a
// credential has confused a local invocation with an authenticated one, and an
// UPDATE matching no rows would let that pass silently — leaving last_used_at
// permanently blank for every credential and nothing to say why.
func Touch(ctx context.Context, m audit.Mutation, now time.Time, id string) error {
	if id == "" {
		return fmt.Errorf("%w: recording a use with no credential", ErrNoTokens)
	}
	if _, err := m.Tx().ExecContext(ctx,
		`UPDATE token SET last_used_at = ? WHERE id = ?`, formatTime(truncateTime(now)), id,
	); err != nil {
		return fmt.Errorf("recording the use of %s: %w", id, err)
	}
	return nil
}

// RevokeToken withdraws a credential immediately.
//
// Revocation is a timestamp rather than a delete, so `token list` can still
// show that the credential existed and when it stopped working. A row that
// vanishes cannot be told apart from one that never existed.
func RevokeToken(ctx context.Context, m audit.Mutation, by Role, now time.Time,
	id string) (Token, error) {
	if err := Authorize(by, PermTokenManage); err != nil {
		return Token{}, err
	}
	t, err := TokenByID(ctx, m.Tx(), id)
	if err != nil {
		return Token{}, err
	}
	if t.Revoked() {
		return Token{}, fmt.Errorf("%w: %s was revoked on %s",
			ErrBadTransition, t.Prefix, t.RevokedAt.Format(audit.TimeFormat))
	}
	if _, err := m.Tx().ExecContext(ctx,
		`UPDATE token SET revoked_at = ? WHERE id = ?`, formatTime(truncateTime(now)), t.ID,
	); err != nil {
		return Token{}, fmt.Errorf("revoking %s: %w", id, err)
	}
	t.RevokedAt = truncateTime(now)

	m.Detail("prefix", t.Prefix)
	m.Detail("kind", string(t.Kind))
	return t, nil
}

// tokenColumns is the read shape, in one place so the SELECT and the scan
// cannot drift apart.
const tokenColumns = `id, user_id, kind, prefix, name, expires_at, revoked_at,
	last_used_at, created_at`

// TokenByID reads one token.
func TokenByID(ctx context.Context, q Querier, id string) (Token, error) {
	t, err := scanToken(q.QueryRowContext(ctx,
		`SELECT `+tokenColumns+` FROM token WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return Token{}, fmt.Errorf("%w: %q", ErrNoTokens, id)
	}
	return t, err
}

func tokenByHash(ctx context.Context, q Querier, hash string) (Token, error) {
	t, err := scanToken(q.QueryRowContext(ctx,
		`SELECT `+tokenColumns+` FROM token WHERE hash = ?`, hash))
	if errors.Is(err, sql.ErrNoRows) {
		return Token{}, ErrNoTokens
	}
	return t, err
}

// ListTokens returns a user's tokens, newest first. An empty userID lists them
// all, which is what an admin auditing credentials needs.
func ListTokens(ctx context.Context, q Querier, userID string) ([]Token, error) {
	query := `SELECT ` + tokenColumns + ` FROM token`
	args := []any{}
	if userID != "" {
		query += ` WHERE user_id = ?`
		args = append(args, userID)
	}
	query += ` ORDER BY created_at DESC, id`

	rows, err := q.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("listing tokens: %w", err)
	}
	defer rows.Close()

	var out []Token
	for rows.Next() {
		t, err := scanToken(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

func scanToken(row interface{ Scan(...any) error }) (Token, error) {
	var (
		t                      Token
		kind, created          string
		name                   sql.NullString
		expires, revoked, used sql.NullString
	)
	if err := row.Scan(&t.ID, &t.UserID, &kind, &t.Prefix, &name,
		&expires, &revoked, &used, &created); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Token{}, err
		}
		return Token{}, fmt.Errorf("reading a token row: %w", err)
	}
	t.Kind = Kind(kind)
	t.Name = name.String
	for _, f := range []struct {
		raw   sql.NullString
		field *time.Time
		what  string
	}{
		{expires, &t.ExpiresAt, "expires_at"},
		{revoked, &t.RevokedAt, "revoked_at"},
		{used, &t.LastUsedAt, "last_used_at"},
	} {
		if !f.raw.Valid {
			continue
		}
		ts, err := time.Parse(audit.TimeFormat, f.raw.String)
		if err != nil {
			return Token{}, fmt.Errorf("token %s has an unreadable %s %q: %w",
				t.ID, f.what, f.raw.String, err)
		}
		*f.field = ts
	}
	ts, err := time.Parse(audit.TimeFormat, created)
	if err != nil {
		return Token{}, fmt.Errorf("token %s has an unreadable created_at %q: %w",
			t.ID, created, err)
	}
	t.CreatedAt = ts
	return t, nil
}

// kindOf reads the kind a plaintext credential declares.
func kindOf(presented string) (Kind, bool) {
	for _, k := range Kinds {
		if strings.HasPrefix(presented, k.Prefix()) {
			return k, true
		}
	}
	return "", false
}

// truncateTime drops what the stored format cannot hold, so a value written and
// read back compares equal.
func truncateTime(t time.Time) time.Time {
	if t.IsZero() {
		return t
	}
	return t.UTC().Truncate(time.Millisecond)
}

func formatTime(t time.Time) string { return t.UTC().Format(audit.TimeFormat) }

func nullableTime(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return formatTime(t)
}

// JoinToken enrolls a node. It belongs to no user and carries a use count
// instead of a subject, which is why docs/specs/08-data-model.md §1 gives it a
// table of its own.
type JoinToken struct {
	ID        string
	Prefix    string
	UsesLeft  int
	ExpiresAt time.Time
	CreatedBy string
	CreatedAt time.Time
}

// MintJoinToken issues a join token.
//
// Redeeming one is node enrollment, which is R2 and R4. Minting is here
// because the machinery is the same and docs/specs/02-enrollment.md §4 names
// all three prefixes together — a kind that arrives later is a kind that
// arrives with its own second implementation.
func MintJoinToken(ctx context.Context, m audit.Mutation, by Role, now time.Time,
	createdBy string, uses int, expires time.Time) (JoinToken, string, error) {
	if err := Authorize(by, PermTokenManage); err != nil {
		return JoinToken{}, "", err
	}
	if uses < 1 {
		return JoinToken{}, "", fmt.Errorf("%w: a join token needs at least one use", ErrBadName)
	}
	// Unlike a personal token, this one must expire. A join token that never
	// does is a permanent enrollment credential sitting in somebody's history.
	if expires.IsZero() || !expires.After(now) {
		return JoinToken{}, "", fmt.Errorf("%w: a join token must expire in the future", ErrBadName)
	}
	if createdBy == "" {
		return JoinToken{}, "", fmt.Errorf("%w: a join token has to record who minted it", ErrBadName)
	}

	plaintext, err := mintSecret(KindJoin)
	if err != nil {
		return JoinToken{}, "", err
	}
	id, err := newID("jt_")
	if err != nil {
		return JoinToken{}, "", err
	}
	j := JoinToken{
		ID:        id,
		Prefix:    displayPrefix(plaintext, KindJoin),
		UsesLeft:  uses,
		ExpiresAt: truncateTime(expires),
		CreatedBy: createdBy,
		CreatedAt: truncateTime(now),
	}
	if _, err := m.Tx().ExecContext(ctx,
		`INSERT INTO join_token (id, hash, prefix, uses_left, expires_at, created_by, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		j.ID, hashToken(plaintext), j.Prefix, j.UsesLeft, formatTime(j.ExpiresAt), j.CreatedBy,
		formatTime(j.CreatedAt),
	); err != nil {
		return JoinToken{}, "", fmt.Errorf("issuing a join token: %w", err)
	}

	m.Detail("kind", string(KindJoin))
	m.Detail("prefix", j.Prefix)
	m.Detail("uses", uses)
	m.Detail("expires", formatTime(j.ExpiresAt))
	return j, plaintext, nil
}

// ListJoinTokens returns the join tokens, newest first.
func ListJoinTokens(ctx context.Context, q Querier) ([]JoinToken, error) {
	rows, err := q.QueryContext(ctx,
		`SELECT id, prefix, uses_left, expires_at, created_by, created_at
		 FROM join_token ORDER BY created_at DESC, id`)
	if err != nil {
		return nil, fmt.Errorf("listing join tokens: %w", err)
	}
	defer rows.Close()

	var out []JoinToken
	for rows.Next() {
		var (
			j                JoinToken
			expires, created string
		)
		if err := rows.Scan(&j.ID, &j.Prefix, &j.UsesLeft, &expires, &j.CreatedBy,
			&created); err != nil {
			return nil, fmt.Errorf("reading a join token row: %w", err)
		}
		for _, f := range []struct {
			raw   string
			field *time.Time
			what  string
		}{{expires, &j.ExpiresAt, "expires_at"}, {created, &j.CreatedAt, "created_at"}} {
			ts, err := time.Parse(audit.TimeFormat, f.raw)
			if err != nil {
				return nil, fmt.Errorf("join token %s has an unreadable %s %q: %w",
					j.ID, f.what, f.raw, err)
			}
			*f.field = ts
		}
		out = append(out, j)
	}
	return out, rows.Err()
}
