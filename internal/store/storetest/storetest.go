// Package storetest builds the database a test starts from.
//
// **Every command migrates, and that is not the thing to change.** An
// operator's first command reaches an unmigrated database, so
// dev/specs/08-data-model.md §5 has any process that opens it for writing
// apply migrations — internal/cli's openSession does, and so does the server.
// What that costs is paid per *process* in production and per *test* here,
// and a package with a database per test pays it hundreds of times: applying
// all of them was 38% of internal/cli's CPU under the race detector, because
// modernc's SQLite is transpiled C and every statement its parser touches is
// instrumented twice over.
//
// So the migrations run once for the whole test binary and the resulting file
// is copied. Migrate still runs on each copy — nothing about the path under
// test is skipped — it simply finds nothing left to do.
package storetest

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/nodarynet/nodary/internal/store"
)

// Place writes an empty, fully migrated database at path.
//
// The bytes rather than a shared path: two tests pointed at one file would
// share its locks, and a database per test is the point.
func Place(tb testing.TB, path string) {
	tb.Helper()
	if err := os.WriteFile(path, schema(), 0o600); err != nil {
		tb.Fatal(err)
	}
}

// schema panics rather than reporting: it runs once, under sync.OnceValue,
// where there is no particular test to fail and every caller would fail
// anyway. A panic names the line; an error returned to whoever happened to be
// first would name a test that did nothing wrong.
var schema = sync.OnceValue(func() []byte {
	dir, err := os.MkdirTemp("", "nodary-schema-")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(dir)

	path := filepath.Join(dir, "nodary.db")
	db, err := store.Open(context.Background(), path)
	if err != nil {
		panic(err)
	}
	if err := db.Migrate(context.Background()); err != nil {
		panic(err)
	}
	// Closing the last connection checkpoints the WAL and deletes it, so the
	// one file is the whole database. Asserted rather than assumed: a
	// surviving -wal would mean copying the file silently loses what it held,
	// and the tests that then failed would name anything but this.
	if err := db.Close(); err != nil {
		panic(err)
	}
	if _, err := os.Stat(path + "-wal"); err == nil {
		panic("storetest: the WAL survived Close, so this file is not the whole database")
	}
	body, err := os.ReadFile(path)
	if err != nil {
		panic(err)
	}
	return body
})
