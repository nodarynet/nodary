package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	sqlite "modernc.org/sqlite"
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

// sqliteReadOnlyDirectory is SQLITE_READONLY_DIRECTORY: the database itself is
// readable, but its directory is not writable and SQLite cannot create the -shm
// index it needs to read a WAL file.
const sqliteReadOnlyDirectory = 1544

func isReadOnlyDirectory(err error) bool {
	var se *sqlite.Error
	return errors.As(err, &se) && se.Code() == sqliteReadOnlyDirectory
}

// readOnlyDSN opens an existing file for queries and nothing else.
//
// mode=ro rather than the writer's implicit rwc: without it SQLite creates the
// database, so pointing `audit verify` at a typo would report an empty chain
// against a file it had just invented. _query_only then refuses writes at the
// SQL layer as well.
//
// mode=rw was rejected, and the reason it was once preferred does not survive
// measurement. _query_only gates the SQL layer, not the pager: under mode=rw
// the last connection to close takes an exclusive lock, checkpoints the -wal
// into the database and unlinks it. An auditor who hashes a db/-wal pair for
// chain of custody and then runs `audit verify` gets a different hash and no
// -wal back, while the command prints "chain: verified" — the tool altering the
// evidence it was asked to inspect. mode=ro leaves both files byte-identical
// and still reads every committed frame in an uncheckpointed -wal, so nothing
// is given up: it is immutable=1, which this does not use, that would serve a
// stale pre-WAL snapshot.
//
// No journal_mode: this must never convert the file it is reading.
func readOnlyDSN(path string) string {
	return fileURI(path, "mode=ro&_query_only=1&_pragma=busy_timeout(5000)")
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
		if isReadOnlyDirectory(err) {
			// SQLite needs to create the -shm index beside the database to read
			// a WAL file at all, so a database on read-only media or in a
			// locked-down custody directory fails here. Named, because
			// "attempt to write a readonly database (1544)" about a read-only
			// open reads as a contradiction and sends the operator looking at
			// the file's mode rather than its directory's.
			return nil, fmt.Errorf(
				"opening %s: %s is not writable, and SQLite must create the -shm index there to read a WAL database; copy the database and its -wal to a writable directory first",
				path, filepath.Dir(path))
		}
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
	switch {
	case id == applicationID:
		return nil
	case id != 0:
		return foreignApplicationID(id)
	}
	// Classified the same way Open does, so one file gets one explanation
	// whichever command names it. Unlike Open there is nothing to stamp: an
	// unstamped file is somebody else's, empty or not.
	var objects int
	if err := db.read.QueryRowContext(ctx,
		"SELECT count(*) FROM sqlite_master").Scan(&objects); err != nil {
		return fmt.Errorf("inspecting schema: %w", err)
	}
	return unstampedDatabase(objects)
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
	// One transaction, so the two statements see one snapshot. The read pool
	// hands out up to maxReaders connections, so as separate autocommit reads
	// they can straddle a concurrent migration: the count finds no
	// schema_migration table, the applied set comes back empty, and a database
	// that is fully migrated by the time the message prints is reported as
	// behind, telling the operator to do what they have already done. The
	// migrator takes the same care for the same reason — see MigrateFS.
	tx, err := db.read.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return fmt.Errorf("reading the schema of %s: %w", db.path, err)
	}
	defer func() { _ = tx.Rollback() }()

	applied, err := appliedMigrations(tx)
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
