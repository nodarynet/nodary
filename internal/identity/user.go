package identity

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/nodarynet/nodary/internal/audit"
)

// State is a user's lifecycle state: docs/specs/07-identity-audit.md §1's
// active → suspended → deleted.
type State string

const (
	// StateActive can authenticate.
	StateActive State = "active"
	// StateSuspended cannot authenticate and can still be deleted.
	StateSuspended State = "suspended"
	// StateDeleted is the end. The row remains so audit records naming it
	// still resolve to a name; its sealed TOTP seed does not.
	StateDeleted State = "deleted"
)

// transitions is the state machine, forward-only.
//
// There is no way back from suspended, and that is the specification rather
// than an omission: §1 draws the states as a one-way sequence and
// docs/specs/10-cli.md §1 lists `user add|list|show|suspend|delete|passwd|totp`
// with no verb that reactivates. Inventing one here would put a capability in
// the binary that no spec asked for and no audit action names.
var transitions = map[State][]State{
	StateActive:    {StateSuspended, StateDeleted},
	StateSuspended: {StateDeleted},
	StateDeleted:   nil,
}

// User is one row of the user table, without anything sealed.
//
// The TOTP seed is deliberately absent rather than unexported: a struct that
// holds a secret is a struct that eventually reaches a log line or a JSON
// encoder. Enrollment is reported as a boolean, which is all any caller needs.
type User struct {
	ID           string
	Name         string
	Email        string
	Role         Role
	State        State
	TOTPEnrolled bool
	CreatedAt    time.Time
}

// Active reports whether the user may authenticate.
func (u User) Active() bool { return u.State == StateActive }

var (
	// ErrNotFound is an unknown user. It maps to exit code 1.
	ErrNotFound = errors.New("no such user")
	// ErrNameTaken is a live user already holding the name. Exit code 4.
	ErrNameTaken = errors.New("name is already taken")
	// ErrBadName rejects a name that cannot be used unambiguously. Exit 2.
	ErrBadName = errors.New("unusable name")
	// ErrBadTransition is a state change the machine does not allow. Exit 4.
	ErrBadTransition = errors.New("state change is not allowed")
)

// Querier is what a read needs: a *sql.DB, a *sql.Tx, or a read-only handle.
// Reads take one rather than a *store.DB so a read inside a mutation sees the
// mutation's own transaction.
type Querier interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// maxNameLength bounds a name. It is generous for a person and small enough
// that a name cannot be used to pad an audit record.
const maxNameLength = 64

// checkName rejects a name that could not be used unambiguously on a command
// line, in an audit record, or in a report.
//
// Whitespace and control characters are the whole rule. A name is an argument
// an operator types and a value a report prints; a tab or a newline inside one
// produces output that cannot be read back, and an invisible leading space
// produces two users who look identical.
func checkName(name string) error {
	switch {
	case name == "":
		return fmt.Errorf("%w: a name is required", ErrBadName)
	case !utf8.ValidString(name):
		return fmt.Errorf("%w: %q is not valid UTF-8", ErrBadName, name)
	case len(name) > maxNameLength:
		return fmt.Errorf("%w: %q is longer than %d bytes", ErrBadName, name, maxNameLength)
	}
	for _, r := range name {
		if unicode.IsSpace(r) || unicode.IsControl(r) {
			return fmt.Errorf("%w: %q contains whitespace or a control character",
				ErrBadName, name)
		}
	}
	return nil
}

// checkEmail applies the same legibility rule and nothing more.
//
// Validating the address itself is left alone deliberately: the grammar is
// famously larger than the intuition about it, every hand-rolled check rejects
// somebody's real address, and nothing in R1 sends mail. It is a label.
func checkEmail(email string) error {
	if email == "" {
		return nil
	}
	if !utf8.ValidString(email) {
		return fmt.Errorf("%w: an email address must be valid UTF-8", ErrBadName)
	}
	if len(email) > maxNameLength*4 {
		return fmt.Errorf("%w: email address is too long", ErrBadName)
	}
	for _, r := range email {
		if unicode.IsSpace(r) || unicode.IsControl(r) {
			return fmt.Errorf("%w: an email address may not contain whitespace", ErrBadName)
		}
	}
	return nil
}

// Add creates a user. It records the name and role on the mutation, so the
// audit record says who was created and as what, not merely that a user was.
func Add(ctx context.Context, m audit.Mutation, by Role, now time.Time,
	name, email string, role Role) (User, error) {
	if err := Authorize(by, PermUserManage); err != nil {
		return User{}, err
	}
	if err := checkName(name); err != nil {
		return User{}, err
	}
	if err := checkEmail(email); err != nil {
		return User{}, err
	}
	if !role.Valid() {
		return User{}, fmt.Errorf("%w %q (want %s)", ErrUnknownRole, role, JoinRoles())
	}

	// The unique index is the guarantee; this lookup is the message. Left to
	// the index alone, a name collision surfaces as a driver's constraint text
	// naming an index, which is not something to show an operator.
	//
	// It asks for a live user, not any user. Get finds a deleted one, which is
	// correct for `show` and would be wrong here: the partial index exists
	// precisely so a deleted name can be taken again.
	switch _, err := getLive(ctx, m.Tx(), name); {
	case err == nil:
		return User{}, fmt.Errorf("%w: %q", ErrNameTaken, name)
	case !errors.Is(err, ErrNotFound):
		return User{}, err
	}

	id, err := newID("usr_")
	if err != nil {
		return User{}, err
	}
	u := User{
		ID:        id,
		Name:      name,
		Email:     email,
		Role:      role,
		State:     StateActive,
		CreatedAt: now.UTC().Truncate(time.Millisecond),
	}
	_, err = m.Tx().ExecContext(ctx,
		`INSERT INTO user (id, name, email, role, state, created_at) VALUES (?, ?, ?, ?, ?, ?)`,
		u.ID, u.Name, nullable(u.Email), string(u.Role), string(u.State),
		u.CreatedAt.Format(audit.TimeFormat))
	if err != nil {
		return User{}, fmt.Errorf("creating user %q: %w", name, err)
	}

	m.Detail("name", u.Name)
	m.Detail("role", string(u.Role))
	return u, nil
}

// Suspend moves a user out of active. Its tokens stop authenticating because
// Authenticate requires an active user, not because anything is revoked —
// suspension is about the account, and revocation is about a credential.
func Suspend(ctx context.Context, m audit.Mutation, by Role, now time.Time, name string) (User, error) {
	u, err := prepare(ctx, m, by, name, StateSuspended)
	if err != nil {
		return User{}, err
	}
	return u, writeState(ctx, m, &u, StateSuspended)
}

// Delete ends a user, scrubs its sealed TOTP seed and revokes its tokens.
//
// The row stays. Every audit record naming this user carries the id, and
// evidence that cannot be resolved to a name is worth less; the name itself
// comes back, because the unique index covers only live rows.
func Delete(ctx context.Context, m audit.Mutation, by Role, now time.Time, name string) (User, error) {
	u, err := prepare(ctx, m, by, name, StateDeleted)
	if err != nil {
		return User{}, err
	}

	// Before the state changes, not after. The schema refuses a deleted row
	// that still holds a seed, so writing the state first fails the CHECK --
	// which is the constraint working, and the reason the scrub cannot be an
	// afterthought bolted onto the transition.
	if _, err := m.Tx().ExecContext(ctx,
		`UPDATE user SET totp_secret_enc = NULL, totp_enrolled_at = NULL, totp_last_step = NULL
		 WHERE id = ?`, u.ID); err != nil {
		return User{}, fmt.Errorf("scrubbing the TOTP seed for %q: %w", name, err)
	}
	u.TOTPEnrolled = false

	// Authenticate refuses a token whose user is not active, so this is not
	// what stops the credential working. It is what makes `token list` tell
	// the truth afterwards, which is what an auditor reads.
	res, err := m.Tx().ExecContext(ctx,
		`UPDATE token SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL`,
		now.UTC().Format(audit.TimeFormat), u.ID)
	if err != nil {
		return User{}, fmt.Errorf("revoking tokens for %q: %w", name, err)
	}
	if n, err := res.RowsAffected(); err == nil {
		m.Detail("tokens_revoked", n)
	}

	return u, writeState(ctx, m, &u, StateDeleted)
}

// prepare authorizes the caller, reads the user and checks that the transition
// is one the machine allows. It writes nothing, so a caller can do the work a
// state change implies before the state changes.
func prepare(ctx context.Context, m audit.Mutation, by Role, name string, to State) (User, error) {
	if err := Authorize(by, PermUserManage); err != nil {
		return User{}, err
	}
	u, err := Get(ctx, m.Tx(), name)
	if err != nil {
		return User{}, err
	}
	if !slices.Contains(transitions[u.State], to) {
		return User{}, fmt.Errorf("%w: %q is %s and cannot become %s",
			ErrBadTransition, name, u.State, to)
	}
	return u, nil
}

// writeState performs the transition prepare validated and records it.
func writeState(ctx context.Context, m audit.Mutation, u *User, to State) error {
	if _, err := m.Tx().ExecContext(ctx,
		`UPDATE user SET state = ? WHERE id = ?`, string(to), u.ID); err != nil {
		return fmt.Errorf("changing the state of %q: %w", u.Name, err)
	}
	m.Detail("name", u.Name)
	m.Detail("from", string(u.State))
	m.Detail("to", string(to))
	u.State = to
	return nil
}

// userColumns is the read shape, in one place so the SELECT and the scan
// cannot drift apart.
const userColumns = `id, name, email, role, state, totp_enrolled_at IS NOT NULL, created_at`

// Get reads a user by name.
//
// A deleted user is found by name only while no live user holds it, which falls
// out of the query being ordered: the live row wins because a deleted one
// sorts after it. That is what lets a name be reused without `show` becoming
// ambiguous.
func Get(ctx context.Context, q Querier, name string) (User, error) {
	row := q.QueryRowContext(ctx,
		`SELECT `+userColumns+` FROM user WHERE name = ?
		 ORDER BY state = 'deleted', created_at DESC LIMIT 1`, name)
	u, err := scanUser(row)
	if errors.Is(err, sql.ErrNoRows) {
		return User{}, fmt.Errorf("%w: %q", ErrNotFound, name)
	}
	return u, err
}

// getLive finds a user by name among those that are not deleted, which is the
// set the unique index constrains.
func getLive(ctx context.Context, q Querier, name string) (User, error) {
	row := q.QueryRowContext(ctx,
		`SELECT `+userColumns+` FROM user WHERE name = ? AND state <> 'deleted'`, name)
	u, err := scanUser(row)
	if errors.Is(err, sql.ErrNoRows) {
		return User{}, fmt.Errorf("%w: %q", ErrNotFound, name)
	}
	return u, err
}

// GetByID reads a user by identifier, which is what an audit record carries.
func GetByID(ctx context.Context, q Querier, id string) (User, error) {
	u, err := scanUser(q.QueryRowContext(ctx, `SELECT `+userColumns+` FROM user WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return User{}, fmt.Errorf("%w: %q", ErrNotFound, id)
	}
	return u, err
}

// List returns users by name. Deleted users are excluded unless asked for:
// they are history, and history does not belong in the output an operator
// reads to decide who exists.
func List(ctx context.Context, q Querier, includeDeleted bool) ([]User, error) {
	query := `SELECT ` + userColumns + ` FROM user`
	if !includeDeleted {
		query += ` WHERE state <> 'deleted'`
	}
	query += ` ORDER BY name, created_at`

	rows, err := q.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("listing users: %w", err)
	}
	defer rows.Close()

	var out []User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// scanUser reads one row in userColumns order.
func scanUser(row interface{ Scan(...any) error }) (User, error) {
	var (
		u        User
		email    sql.NullString
		role     string
		state    string
		enrolled bool
		created  string
	)
	if err := row.Scan(&u.ID, &u.Name, &email, &role, &state, &enrolled, &created); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return User{}, err
		}
		return User{}, fmt.Errorf("reading a user row: %w", err)
	}
	ts, err := time.Parse(audit.TimeFormat, created)
	if err != nil {
		return User{}, fmt.Errorf("user %s has an unreadable created_at %q: %w", u.ID, created, err)
	}
	u.Email = email.String
	u.Role = Role(role)
	u.State = State(state)
	u.TOTPEnrolled = enrolled
	u.CreatedAt = ts
	return u, nil
}

// nullable maps "" to NULL, so an unset optional is absent rather than empty.
// The two are different things, and a report that renders them identically is
// a report that has already lost the distinction.
func nullable(s string) any {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	return s
}
