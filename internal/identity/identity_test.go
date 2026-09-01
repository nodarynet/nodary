package identity

import (
	"context"
	"io"
	"path/filepath"
	"testing"
	"time"

	"github.com/nodarynet/nodary/internal/audit"
	"github.com/nodarynet/nodary/internal/secret"
	"github.com/nodarynet/nodary/internal/store"
)

// fixture is a migrated database with an audit log over it. Every mutating
// function in this package takes an audit.Mutation, so there is no way to
// exercise one without a log — which is the guarantee, not an inconvenience.
type fixture struct {
	t   *testing.T
	db  *store.DB
	log *audit.Log
	key *secret.Key
	dir string
	now time.Time
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	ctx := context.Background()
	dir := t.TempDir()
	db, err := store.Open(ctx, filepath.Join(dir, "nodary.db"))
	if err != nil {
		t.Fatalf("opening: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	if err := db.Migrate(ctx); err != nil {
		t.Fatalf("migrating: %v", err)
	}
	f := &fixture{
		t:   t,
		db:  db,
		dir: dir,
		key: newKey(t, filepath.Join(dir, "secret.key")),
		now: time.Date(2026, 9, 1, 12, 0, 0, 123456789, time.UTC),
	}
	f.log = audit.New(db, audit.NewDelivery(nil, audit.Warn, io.Discard),
		audit.WithClock(func() time.Time { return f.now }))
	return f
}

// act runs one audited mutation, returning the record and whatever the
// mutation returned.
func (f *fixture) act(action string, fn func(audit.Mutation) error) (audit.Record, error) {
	f.t.Helper()
	return f.log.Act(context.Background(), audit.Request{
		Actor:  audit.Actor{ID: "root", Method: "local"},
		Action: action,
	}, fn)
}

// add creates a user as an admin and fails the test if it does not work.
func (f *fixture) add(name string, role Role) User {
	f.t.Helper()
	var u User
	_, err := f.act("user.add", func(m audit.Mutation) error {
		var err error
		u, err = Add(context.Background(), m, RoleAdmin, f.now, name, "", role)
		return err
	})
	if err != nil {
		f.t.Fatalf("adding %q: %v", name, err)
	}
	return u
}

func (f *fixture) users(includeDeleted bool) []User {
	f.t.Helper()
	out, err := List(context.Background(), f.db.Read(), includeDeleted)
	if err != nil {
		f.t.Fatalf("listing: %v", err)
	}
	return out
}

func (f *fixture) get(name string) (User, error) {
	f.t.Helper()
	return Get(context.Background(), f.db.Read(), name)
}

// names renders a user list for a comparison message.
func names(us []User) []string {
	out := make([]string, len(us))
	for i, u := range us {
		out[i] = u.Name + "/" + string(u.State)
	}
	return out
}

// newKey creates a keyring at path. secret.Create checks that the file is owned
// by the reader rather than by root specifically, so this works in a test.
func newKey(t *testing.T, path string) *secret.Key {
	t.Helper()
	k, err := secret.Create(path)
	if err != nil {
		t.Fatalf("creating a key at %s: %v", path, err)
	}
	return k
}

// enroll puts a user through TOTP enrollment and returns the seed, so a test
// can generate codes the way an authenticator would.
func (f *fixture) enroll(name string) []byte {
	f.t.Helper()
	seed, err := NewSeed()
	if err != nil {
		f.t.Fatal(err)
	}
	code := codeAt(seed, stepAt(f.now), totpDigits)
	if _, err := f.act("user.totp", func(m audit.Mutation) error {
		_, err := Enroll(context.Background(), m, RoleAdmin, f.now, f.key, name, seed, code)
		return err
	}); err != nil {
		f.t.Fatalf("enrolling %q: %v", name, err)
	}
	return seed
}

// sealedSeed returns the ciphertext stored for a user.
func (f *fixture) sealedSeed(id string) []byte {
	f.t.Helper()
	var blob []byte
	if err := f.db.Read().QueryRowContext(context.Background(),
		`SELECT totp_secret_enc FROM user WHERE id = ?`, id).Scan(&blob); err != nil {
		f.t.Fatalf("reading the sealed seed for %s: %v", id, err)
	}
	return blob
}

// boundKey is the key id this database records, or "".
func (f *fixture) boundKey() string {
	f.t.Helper()
	id, err := BoundKeyID(context.Background(), f.db.Read())
	if err != nil {
		f.t.Fatalf("reading the bound key: %v", err)
	}
	return id
}

func (f *fixture) checkKey(k *secret.Key) error {
	f.t.Helper()
	return CheckKey(context.Background(), f.db.Read(), k)
}

// mustGet reads a user or fails the test.
func (f *fixture) mustGet(name string) User {
	f.t.Helper()
	u, err := f.get(name)
	if err != nil {
		f.t.Fatalf("Get(%q): %v", name, err)
	}
	return u
}

// mintJoin issues a join token and returns it with its plaintext.
func (f *fixture) mintJoin(uses int, expires time.Time) (JoinToken, string) {
	f.t.Helper()
	var (
		j     JoinToken
		plain string
	)
	if _, err := f.act("token.join", func(m audit.Mutation) error {
		var err error
		j, plain, err = MintJoinToken(context.Background(), m, RoleAdmin, f.now, "root",
			uses, expires)
		return err
	}); err != nil {
		f.t.Fatalf("minting a join token: %v", err)
	}
	return j, plain
}
