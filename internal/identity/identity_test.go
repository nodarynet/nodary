package identity

import (
	"context"
	"io"
	"path/filepath"
	"testing"
	"time"

	"github.com/nodarynet/nodary/internal/audit"
	"github.com/nodarynet/nodary/internal/store"
)

// fixture is a migrated database with an audit log over it. Every mutating
// function in this package takes an audit.Mutation, so there is no way to
// exercise one without a log — which is the guarantee, not an inconvenience.
type fixture struct {
	t   *testing.T
	db  *store.DB
	log *audit.Log
	now time.Time
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	ctx := context.Background()
	db, err := store.Open(ctx, filepath.Join(t.TempDir(), "nodary.db"))
	if err != nil {
		t.Fatalf("opening: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	if err := db.Migrate(ctx); err != nil {
		t.Fatalf("migrating: %v", err)
	}
	f := &fixture{t: t, db: db, now: time.Date(2026, 9, 1, 12, 0, 0, 123456789, time.UTC)}
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
