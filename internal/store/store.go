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
// inside a single immediate transaction is what actually serialises them. The
// reader pool is opened _query_only, so "WriteTx is the only write path" is
// enforced by SQLite rather than by callers remembering.
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

// maxReaders bounds the read pool. This is not about throughput: an open read
// transaction pins the write-ahead log, so an unbounded pool lets a few leaked
// *sql.Rows grow the WAL until the disk fills — which stops audit writes.
// Bounding the pool bounds how much can accumulate.
const maxReaders = 8

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
//
// busy_timeout comes first deliberately: the driver applies these in the order
// given, so journal_mode ahead of it would convert a fresh database with no
// busy handler set at all.
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
	// _query_only makes the read pool genuinely read-only: SQLite refuses a
	// write on it rather than trusting callers not to try. A stray Exec here
	// would be a deferred-mode read-then-write — the exact lost-update path
	// _txlock=immediate exists to prevent.
	return "file:" + path + "?_query_only=1&" + pragmas
}

// identityDSN deliberately carries no journal_mode. Opening with
// journal_mode(WAL) converts the file before anything has checked whose it is,
// so pointing at another application's database would rewrite it and leave
// -wal and -shm sidecars behind — damage done in the course of reporting a
// misconfiguration.
func identityDSN(path string) string {
	return "file:" + path + "?_txlock=immediate&_pragma=busy_timeout(5000)"
}

// Open opens the database, creating it and its parent directory if absent.
func Open(ctx context.Context, path string) (*DB, error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, paths.ModeDataDir); err != nil {
		return nil, fmt.Errorf("creating %s: %w", dir, err)
	}
	// MkdirAll does nothing to a directory that already exists, and in a real
	// install this one arrives from a package postinst or an earlier release —
	// which is precisely the case 0700 exists for.
	if err := os.Chmod(dir, paths.ModeDataDir); err != nil {
		return nil, fmt.Errorf("restricting %s: %w", dir, err)
	}

	// Settle whose file this is before converting it to WAL.
	if err := establishIdentity(ctx, path); err != nil {
		return nil, err
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
	read.SetMaxOpenConns(maxReaders)
	read.SetConnMaxIdleTime(time.Minute)

	db := &DB{write: write, read: read, path: path}

	// The first real connection converts the file to WAL, which needs an
	// exclusive lock — the second place a concurrent start can collide.
	if err := retryWhileLocked(ctx, func() error { return db.write.PingContext(ctx) }); err != nil {
		db.Close()
		return nil, fmt.Errorf("opening %s: %w", path, err)
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

// IsBusy reports whether err is SQLite declining because someone else holds a
// lock, rather than anything being wrong. Exported so a caller holding a record
// it must not drop can tell "try again" from "give up".
func IsBusy(err error) bool {
	var se *sqlite.Error
	if errors.As(err, &se) {
		return se.Code() == sqliteBusy || se.Code() == sqliteLocked
	}
	return false
}

// retryWhileLocked runs fn until it stops reporting a lock conflict.
//
// This is not defensive padding. Converting a fresh database to WAL takes an
// exclusive lock, and SQLite does not run the busy handler for a journal_mode
// change — so busy_timeout cannot cover it however it is ordered. Two processes
// reaching a brand-new database together is an ordinary event here: on a first
// install the systemd unit and an operator's first CLI command race, and
// "database is locked" would be the very first thing nodary ever said.
//
// The budget bounds the whole loop rather than counting attempts, because each
// attempt can itself block for a full busy_timeout — counting attempts hid a
// worst case of several minutes of a unit sitting silent at boot.
func retryWhileLocked(ctx context.Context, fn func() error) error {
	const budget = 15 * time.Second
	deadline := time.Now().Add(budget)
	delay := 5 * time.Millisecond

	for {
		err := fn()
		if err == nil || !IsBusy(err) {
			return err
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("still locked after %s: %w", budget, err)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(delay):
		}
		if delay*2 <= 200*time.Millisecond {
			delay *= 2
		}
	}
}

// establishIdentity stamps a fresh database and refuses somebody else's.
//
// All three steps happen inside one immediate transaction. As separate
// statements, two starting processes interleave: the second reads
// application_id as 0 before the first stamps, then counts sqlite_master after
// the first has stamped *and* migrated, and concludes the file belongs to
// someone else. That refusal is permanent, wrong, and lands on exactly the
// first-install race the retry above exists for.
func establishIdentity(ctx context.Context, path string) error {
	probe, err := sql.Open("sqlite", identityDSN(path))
	if err != nil {
		return fmt.Errorf("opening %s: %w", path, err)
	}
	probe.SetMaxOpenConns(1)
	defer probe.Close()

	return retryWhileLocked(ctx, func() error {
		tx, err := probe.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		committed := false
		defer func() {
			if !committed {
				_ = tx.Rollback()
			}
		}()

		var id int64
		if err := tx.QueryRowContext(ctx, "PRAGMA application_id").Scan(&id); err != nil {
			return fmt.Errorf("reading application_id: %w", err)
		}
		switch {
		case id == applicationID:
			committed = true
			return tx.Commit()
		case id != 0:
			return fmt.Errorf("%w: application_id is %#x, want %#x",
				ErrNotNodaryDatabase, id, applicationID)
		}

		// application_id 0 is either a database nodary has not stamped yet, or
		// one created by a tool that never sets it. An empty file is the former.
		var objects int
		if err := tx.QueryRowContext(ctx,
			"SELECT count(*) FROM sqlite_master").Scan(&objects); err != nil {
			return fmt.Errorf("inspecting schema: %w", err)
		}
		if objects != 0 {
			return fmt.Errorf("%w: it has %d objects and no application_id",
				ErrNotNodaryDatabase, objects)
		}
		if _, err := tx.ExecContext(ctx,
			fmt.Sprintf("PRAGMA application_id = %d", applicationID)); err != nil {
			return fmt.Errorf("stamping application_id: %w", err)
		}
		committed = true
		return tx.Commit()
	})
}

// restrictPermissions tightens the database and its WAL sidecars.
//
// The -wal file holds committed-but-uncheckpointed rows: audit records and
// encrypted secrets alike. SQLite derives the sidecar modes from the database
// file, so those are belt-and-braces — but the database file itself is created
// from the process umask.
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
	var tx *sql.Tx
	// Retrying BEGIN is unconditionally safe — nothing in fn has run. Not
	// retrying drops an audit record because someone else happened to be
	// migrating or taking a backup, and busy_timeout's five seconds is thin
	// against either.
	err := retryWhileLocked(ctx, func() error {
		var err error
		tx, err = db.write.BeginTx(ctx, nil)
		return err
	})
	if err != nil {
		return fmt.Errorf("beginning write transaction: %w", err)
	}

	committed := false
	defer func() {
		if committed {
			return
		}
		// Without this, a panic inside fn leaves the transaction unfinished:
		// the pool's one connection is never returned, and BEGIN IMMEDIATE's
		// write lock stays held on the *file*. Every writer on the machine
		// stops — this process and every other, since the CLI writes to the
		// same database — and Close blocks forever. One bad Scan in a chain
		// writer would end the audit log without a word.
		_ = tx.Rollback()
	}()

	if err := fn(tx); err != nil {
		// A cancelled context otherwise surfaces as "sql: transaction has
		// already been committed or rolled back", which tells the caller
		// nothing about why its write did not happen.
		if ctxErr := ctx.Err(); ctxErr != nil {
			return errors.Join(ctxErr, err)
		}
		return err
	}
	if err := tx.Commit(); err != nil {
		// Cancellation can also land here: the callback may finish before the
		// context is observed, leaving Commit to fail with ErrTxDone, which
		// says nothing about why.
		if ctxErr := ctx.Err(); ctxErr != nil {
			return errors.Join(ctxErr, err)
		}
		return fmt.Errorf("committing write transaction: %w", err)
	}
	committed = true
	return nil
}

// Read returns the pool for queries. It is opened _query_only, so SQLite
// refuses a write on it rather than relying on callers to keep away.
func (db *DB) Read() *sql.DB { return db.read }

// Path is the database file this handle was opened from.
func (db *DB) Path() string { return db.path }

// Close checkpoints the WAL and closes both pools.
//
// Readers are closed first, and the checkpoint's *result* is read rather than
// its error. An open read transaction pins the log, and wal_checkpoint reports
// that by returning busy=1 in its result row while returning no error at all —
// so checkpointing before closing the readers would contend with them for a
// full busy_timeout and then silently do nothing, which is how a backup taken
// after a clean shutdown ends up missing its most recent records.
func (db *DB) Close() error {
	var errs []error
	if db.read != nil {
		if err := db.read.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if db.write != nil {
		var busy, logFrames, checkpointed int
		switch err := db.write.QueryRow("PRAGMA wal_checkpoint(TRUNCATE)").
			Scan(&busy, &logFrames, &checkpointed); {
		case err != nil:
			errs = append(errs, fmt.Errorf("checkpointing WAL: %w", err))
		case busy != 0:
			errs = append(errs, fmt.Errorf(
				"checkpointing WAL: blocked by an open reader, %d frames left in %s-wal",
				logFrames, db.path))
		}
		if err := db.write.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}
