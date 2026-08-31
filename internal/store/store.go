// Package store opens the nodary SQLite database and owns the one path
// through which writes happen.
//
// The database is at /var/lib/nodary/nodary.db in WAL mode
// (docs/specs/08-data-model.md), through modernc.org/sqlite so the binary stays
// cgo-free and genuinely static (docs/adr/0002-go-with-package-manager-wrappers.md).
//
// Two things here are load-bearing rather than incidental:
//
// The writer opens with _txlock=immediate and WriteTx is the only way to write.
// R1-07 requires that concurrent writers cannot produce two records claiming the
// same seq, and that guarantee cannot come from Go: database/sql returns a
// connection to the pool between calls, so a read-then-write pair interleaves
// even on a pool capped at one connection — and the CLI writes to the same file
// as the server, so the writers are separate processes anyway. Assigning seq
// inside a single immediate transaction is what actually serialises them.
//
// synchronous=FULL rather than NORMAL. WAL with NORMAL can lose the most recent
// commits on power loss, and what would be lost here is evidence.
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/nodarynet/nodary/internal/paths"

	sqlite "modernc.org/sqlite"
)

// applicationID stamps the file as nodary's. Without it, pointing at an
// unrelated SQLite database would silently run migrations against someone
// else's data instead of reporting a misconfiguration.
//
// The value is ASCII "NODA", which makes it legible in a hex dump.
const applicationID = 0x4E4F4441

// ErrNotNodaryDatabase is returned when the file is a valid SQLite database
// belonging to something else.
var ErrNotNodaryDatabase = errors.New("file is not a nodary database")

// DB is a handle to the database: one pool for reads, one for writes.
type DB struct {
	write *sql.DB
	read  *sql.DB
	path  string
}

// pragmas are applied through the DSN on every connection in a pool, not once
// at open. A pool opens connections lazily, so a pragma set on the first
// connection would silently not apply to the rest.
const pragmas = "_pragma=busy_timeout(5000)" +
	"&_pragma=journal_mode(WAL)" +
	"&_pragma=foreign_keys(1)" +
	"&_pragma=synchronous(FULL)"

func writerDSN(path string) string {
	// _txlock=immediate takes the write lock at BEGIN rather than at the first
	// write. Under the default deferred mode a WAL transaction that reads and
	// then writes returns SQLITE_BUSY_SNAPSHOT *without* invoking the busy
	// handler, so busy_timeout does not apply and the failure surfaces as a
	// spurious error under exactly the concurrency this is meant to handle.
	return "file:" + path + "?_txlock=immediate&" + pragmas
}

func readerDSN(path string) string {
	return "file:" + path + "?" + pragmas
}

// Open opens the database, creating it and its parent directory if absent.
func Open(ctx context.Context, path string) (*DB, error) {
	if err := os.MkdirAll(filepath.Dir(path), paths.ModeDataDir); err != nil {
		return nil, fmt.Errorf("creating %s: %w", filepath.Dir(path), err)
	}

	write, err := sql.Open("sqlite", writerDSN(path))
	if err != nil {
		return nil, fmt.Errorf("opening database for writing: %w", err)
	}
	// A single writer connection is a cheap in-process guard against wasted
	// lock contention. It is not the serialisation mechanism — see WriteTx.
	write.SetMaxOpenConns(1)

	read, err := sql.Open("sqlite", readerDSN(path))
	if err != nil {
		write.Close()
		return nil, fmt.Errorf("opening database for reading: %w", err)
	}

	db := &DB{write: write, read: read, path: path}

	if err := db.initialise(ctx); err != nil {
		db.Close()
		return nil, err
	}
	if err := db.restrictPermissions(); err != nil {
		db.Close()
		return nil, err
	}
	return db, nil
}

// SQLite result codes. Named here rather than imported from
// modernc.org/sqlite/lib, which is a very large package to pull in for two
// integers.
const (
	sqliteBusy   = 5
	sqliteLocked = 6
)

// initialise establishes the first connection and stamps the database,
// retrying while another process is doing the same thing.
//
// The retry is not defensive padding. Converting a fresh database to WAL takes
// an exclusive lock, and SQLite does not run the busy handler for a
// journal_mode change — so busy_timeout cannot cover it however it is ordered.
// Two processes reaching a brand-new database together is an ordinary event
// here: on a first install the systemd unit and an operator's first CLI command
// race, and "database is locked" would be the very first thing nodary ever said.
func (db *DB) initialise(ctx context.Context) error {
	const attempts = 40
	delay := 5 * time.Millisecond

	var err error
	for range attempts {
		if err = db.write.PingContext(ctx); err == nil {
			if err = db.checkIdentity(ctx); err == nil {
				return nil
			}
		}
		if !isLocked(err) {
			return fmt.Errorf("opening %s: %w", db.path, err)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(delay):
		}
		if delay < 200*time.Millisecond {
			delay *= 2
		}
	}
	return fmt.Errorf("opening %s: still locked after %d attempts: %w", db.path, attempts, err)
}

func isLocked(err error) bool {
	var se *sqlite.Error
	if errors.As(err, &se) {
		return se.Code() == sqliteBusy || se.Code() == sqliteLocked
	}
	return false
}

// checkIdentity stamps a fresh database and refuses somebody else's.
func (db *DB) checkIdentity(ctx context.Context) error {
	var id int64
	if err := db.write.QueryRowContext(ctx, "PRAGMA application_id").Scan(&id); err != nil {
		return fmt.Errorf("reading application_id: %w", err)
	}
	if id == applicationID {
		return nil
	}
	if id != 0 {
		return fmt.Errorf("%w: application_id is %#x, want %#x", ErrNotNodaryDatabase, id, applicationID)
	}

	// application_id 0 is either a database nodary has not stamped yet, or one
	// created by a tool that never sets it. An empty file is the former.
	var objects int
	if err := db.write.QueryRowContext(ctx,
		"SELECT count(*) FROM sqlite_master").Scan(&objects); err != nil {
		return fmt.Errorf("inspecting schema: %w", err)
	}
	if objects != 0 {
		return fmt.Errorf("%w: it has %d objects and no application_id", ErrNotNodaryDatabase, objects)
	}
	if _, err := db.write.ExecContext(ctx,
		fmt.Sprintf("PRAGMA application_id = %d", applicationID)); err != nil {
		return fmt.Errorf("stamping application_id: %w", err)
	}
	return nil
}

// restrictPermissions tightens the database and its WAL sidecars.
//
// The -wal file holds committed-but-uncheckpointed rows: audit records and
// encrypted secrets alike. SQLite creates the sidecars from the process umask,
// so a permissive umask would otherwise leave evidence world-readable
// (docs/specs/08-data-model.md §4).
func (db *DB) restrictPermissions() error {
	for _, p := range []string{db.path, db.path + "-wal", db.path + "-shm"} {
		switch err := os.Chmod(p, paths.ModeDatabase); {
		case err == nil, errors.Is(err, os.ErrNotExist):
			// The sidecars appear only once WAL mode has written; absent is fine.
		default:
			return fmt.Errorf("restricting %s: %w", p, err)
		}
	}
	return nil
}

// WriteTx runs fn inside a single immediate transaction. It is the only write
// path: everything that mutates state goes through here, so that assigning a
// sequence number and writing the row that claims it cannot be split apart by
// another writer in another process.
func (db *DB) WriteTx(ctx context.Context, fn func(*sql.Tx) error) error {
	tx, err := db.write.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("beginning write transaction: %w", err)
	}
	if err := fn(tx); err != nil {
		// The rollback error is deliberately discarded: the caller's error is
		// what explains the failure, and reporting a rollback problem instead
		// would bury it.
		_ = tx.Rollback()
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("committing write transaction: %w", err)
	}
	return nil
}

// Read returns the pool for queries. It carries no write privileges by
// convention only — SQLite has no read-only connection here — but keeping reads
// off the writer is what stops a long query from holding the write lock.
func (db *DB) Read() *sql.DB { return db.read }

// Path is the database file this handle was opened from.
func (db *DB) Path() string { return db.path }

// Close checkpoints the WAL and closes both pools.
//
// The checkpoint matters: readers holding open transactions prevent WAL
// truncation, so without one the -wal file grows without bound. It also leaves
// the database as close to self-contained as WAL allows, which is what makes a
// backup taken after a clean shutdown trustworthy.
func (db *DB) Close() error {
	var errs []error
	if db.write != nil {
		if _, err := db.write.Exec("PRAGMA wal_checkpoint(TRUNCATE)"); err != nil {
			errs = append(errs, fmt.Errorf("checkpointing WAL: %w", err))
		}
		if err := db.write.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if db.read != nil {
		if err := db.read.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}
