package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"time"
)

// ErrSchemaBehind is returned when a read-only open finds migrations this
// binary has and the database does not.
//
// docs/specs/08-data-model.md §5: a read-only open refuses when the schema is
// behind rather than changing it underneath a reader. The alternative — migrate
// on the way to answering a query — means `nodary audit verify` alters the file
// it was asked to inspect, which is the one thing an evidence tool must not do.
var ErrSchemaBehind = errors.New("database schema is behind this binary")

// ErrReadOnly is returned by WriteTx on a handle from OpenReadOnly.
var ErrReadOnly = errors.New("database was opened read-only")

// readOnlyDSN opens an existing file for queries and nothing else.
//
// mode=rw rather than the writer's implicit rwc: without it SQLite creates the
// database, so pointing `audit verify` at a typo would report an empty chain
// against a file it had just invented. _query_only then refuses writes at the
// SQL layer.
//
// mode=ro was rejected. It is stricter at the OS layer and buys nothing here —
// SQLite still needs the -shm index to read a WAL database, so the sidecars
// appear either way — while it cannot recover a -wal left by a writer that
// crashed. Refusing to read the chain after a crash would break `verify` at
// exactly the moment someone needs it, and WAL recovery replays committed
// frames rather than changing what the records say.
//
// No journal_mode: this must never convert the file it is reading.
func readOnlyDSN(path string) string {
	return "file:" + path + "?mode=rw&_query_only=1&_pragma=busy_timeout(5000)"
}

// OpenReadOnly opens an existing database for queries.
//
// It refuses a file that is missing, is not nodary's, or carries a schema this
// binary would have to migrate. It never creates, migrates or converts
// anything: the -wal and -shm sidecars may appear, because SQLite requires the
// shared-memory index to read a WAL database at all, but the database content
// is untouched.
func OpenReadOnly(ctx context.Context, path string) (*DB, error) {
	// Checked before opening so the message names the file rather than
	// surfacing SQLite's "unable to open database file (14)", which is the same
	// error for a missing file, a missing directory and a permission problem.
	switch fi, err := os.Stat(path); {
	case errors.Is(err, os.ErrNotExist):
		return nil, fmt.Errorf("%s: no database here", path)
	case err != nil:
		return nil, fmt.Errorf("reading %s: %w", path, err)
	case fi.IsDir():
		return nil, fmt.Errorf("%s is a directory, not a database", path)
	}

	read, err := sql.Open("sqlite", readOnlyDSN(path))
	if err != nil {
		return nil, fmt.Errorf("opening %s for reading: %w", path, err)
	}
	read.SetMaxOpenConns(maxReaders)
	read.SetConnMaxIdleTime(time.Minute)

	db := &DB{read: read, path: path}

	// A writer holding the lock is ordinary rather than exceptional: an
	// operator runs `audit verify` while the server is running.
	if err := retryWhileLocked(ctx, func() error { return read.PingContext(ctx) }); err != nil {
		db.Close()
		return nil, fmt.Errorf("opening %s: %w", path, err)
	}
	if err := db.checkIdentity(ctx); err != nil {
		db.Close()
		return nil, err
	}
	if err := db.checkSchema(ctx); err != nil {
		db.Close()
		return nil, err
	}
	return db, nil
}

// checkIdentity reads application_id without stamping it.
//
// Open's establishIdentity stamps a fresh database; here there is nothing to
// stamp, so an unstamped file is somebody else's by definition — a reader has
// no business claiming a file for nodary.
func (db *DB) checkIdentity(ctx context.Context) error {
	var id int64
	if err := db.read.QueryRowContext(ctx, "PRAGMA application_id").Scan(&id); err != nil {
		return fmt.Errorf("reading application_id: %w", err)
	}
	if id != applicationID {
		return fmt.Errorf("%w: application_id is %#x, want %#x",
			ErrNotNodaryDatabase, id, applicationID)
	}
	return nil
}

// checkSchema refuses every schema this binary cannot read as it stands.
//
// It runs the same reconciliation the migrator does, so a downgrade, a checksum
// mismatch and an out-of-order gap are reported here in the same words rather
// than as a confusing "no such column" three queries later.
func (db *DB) checkSchema(ctx context.Context) error {
	want, err := loadMigrations(migrationsFS, "migrations")
	if err != nil {
		return err
	}
	applied, err := appliedMigrations(dbQuerier{ctx, db.read})
	if err != nil {
		return err
	}
	if err := reconcile(want, applied); err != nil {
		return err
	}
	for _, m := range want {
		if _, done := applied[m.version]; !done {
			return fmt.Errorf("%w: %04d_%s has not been applied; run a nodary command that opens %s for writing",
				ErrSchemaBehind, m.version, m.name, db.path)
		}
	}
	return nil
}

// querier is the subset of *sql.Tx and *sql.DB the schema reads need, so
// appliedMigrations serves both the migrator inside its write transaction and
// the read-only open outside one.
type querier interface {
	Query(query string, args ...any) (*sql.Rows, error)
	QueryRow(query string, args ...any) *sql.Row
}

// dbQuerier carries a context onto a *sql.DB, which *sql.Tx already has bound.
type dbQuerier struct {
	ctx context.Context
	db  *sql.DB
}

func (q dbQuerier) Query(query string, args ...any) (*sql.Rows, error) {
	return q.db.QueryContext(q.ctx, query, args...)
}

func (q dbQuerier) QueryRow(query string, args ...any) *sql.Row {
	return q.db.QueryRowContext(q.ctx, query, args...)
}
