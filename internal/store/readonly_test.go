package store

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// migratedDB returns the path of a database that is open, migrated and closed.
func migratedDB(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "nodary.db")
	db, err := Open(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}

func openRO(t *testing.T, path string) *DB {
	t.Helper()
	db, err := OpenReadOnly(context.Background(), path)
	if err != nil {
		t.Fatalf("OpenReadOnly: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

// _query_only alone still creates the database. Pointing `audit verify` at a
// mistyped path would then report an empty chain against a file it had just
// invented, which is the most misleading answer an evidence tool can give.
func TestOpenReadOnlyRefusesAMissingFileAndDoesNotCreateIt(t *testing.T) {
	path := filepath.Join(t.TempDir(), "absent.db")

	db, err := OpenReadOnly(context.Background(), path)
	if err == nil {
		db.Close()
		t.Fatal("opened a database that does not exist")
	}
	if !strings.Contains(err.Error(), path) {
		t.Errorf("error = %v, want it to name the path", err)
	}
	for _, p := range []string{path, path + "-wal", path + "-shm"} {
		if _, err := os.Stat(p); err == nil {
			t.Errorf("%s was created while refusing to open it", p)
		}
	}
}

// The os.Stat in OpenReadOnly is there for the error message; mode=rw is the
// mechanism, and without a test aimed at it the Stat would hide its removal.
func TestReadOnlyDSNRefusesToCreateTheFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "absent.db")
	db, err := sql.Open("sqlite", readOnlyDSN(path))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Ping(); err == nil {
		t.Error("the read-only DSN opened a database that does not exist")
	}
	if _, err := os.Stat(path); err == nil {
		t.Error("the read-only DSN created the database file")
	}
}

func TestOpenReadOnlyRefusesADirectory(t *testing.T) {
	dir := t.TempDir()
	db, err := OpenReadOnly(context.Background(), dir)
	if err == nil {
		db.Close()
		t.Fatal("opened a directory as a database")
	}
}

func TestOpenReadOnlyRefusesAForeignDatabase(t *testing.T) {
	for _, tc := range []struct {
		name  string
		setup func(t *testing.T, path string)
	}{
		{"unstamped", func(t *testing.T, path string) {
			other, err := sql.Open("sqlite", "file:"+path)
			if err != nil {
				t.Fatal(err)
			}
			defer other.Close()
			if _, err := other.Exec(`CREATE TABLE theirs(x INTEGER)`); err != nil {
				t.Fatal(err)
			}
		}},
		{"another application_id", func(t *testing.T, path string) {
			other, err := sql.Open("sqlite", "file:"+path)
			if err != nil {
				t.Fatal(err)
			}
			defer other.Close()
			if _, err := other.Exec(`PRAGMA application_id = 305419896; CREATE TABLE theirs(x INTEGER)`); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "someone-elses.db")
			tc.setup(t, path)

			db, err := OpenReadOnly(context.Background(), path)
			if err == nil {
				db.Close()
				t.Fatal("opened a foreign database")
			}
			if !errors.Is(err, ErrNotNodaryDatabase) {
				t.Errorf("error = %v, want ErrNotNodaryDatabase", err)
			}
		})
	}
}

// docs/specs/08-data-model.md §5: a read-only open refuses when the schema is
// behind rather than changing it underneath a reader.
func TestOpenReadOnlyRefusesASchemaBehindTheBinaryAndLeavesItAlone(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nodary.db")
	db, err := Open(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil { // stamped, never migrated
		t.Fatal(err)
	}

	ro, err := OpenReadOnly(context.Background(), path)
	if err == nil {
		ro.Close()
		t.Fatal("opened a database with migrations outstanding")
	}
	if !errors.Is(err, ErrSchemaBehind) {
		t.Fatalf("error = %v, want ErrSchemaBehind", err)
	}
	if !strings.Contains(err.Error(), "0001_") {
		t.Errorf("error = %v, want it to name the migration", err)
	}

	// The refusal must not have been a migration in disguise.
	check, err := sql.Open("sqlite", readOnlyDSN(path))
	if err != nil {
		t.Fatal(err)
	}
	defer check.Close()
	var present int
	if err := check.QueryRow(
		`SELECT count(*) FROM sqlite_master WHERE type='table' AND name='schema_migration'`).
		Scan(&present); err != nil {
		t.Fatal(err)
	}
	if present != 0 {
		t.Error("the read-only open migrated the database it was refusing")
	}
}

// A downgrade and a checksum mismatch are reported in the migrator's own words
// rather than as "no such column" three queries later.
func TestOpenReadOnlyReportsADowngrade(t *testing.T) {
	path := migratedDB(t)

	db, err := Open(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.WriteTx(context.Background(), func(tx *sql.Tx) error {
		_, err := tx.Exec(
			`INSERT INTO schema_migration(version, name, checksum, applied_at) VALUES (9999, 'from_the_future', 'x', '2026-01-01T00:00:00.000Z')`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	db.Close()

	ro, err := OpenReadOnly(context.Background(), path)
	if err == nil {
		ro.Close()
		t.Fatal("opened a database written by a newer binary")
	}
	if !errors.Is(err, ErrDowngrade) {
		t.Errorf("error = %v, want ErrDowngrade", err)
	}
}

func TestOpenReadOnlyReadsAndRefusesEveryWritePath(t *testing.T) {
	path := migratedDB(t)
	db := openRO(t, path)

	var n int
	if err := db.Read().QueryRow(`SELECT count(*) FROM schema_migration`).Scan(&n); err != nil {
		t.Fatalf("read-only handle cannot read: %v", err)
	}
	if n == 0 {
		t.Error("no migrations recorded")
	}

	if _, err := db.Read().Exec(`CREATE TABLE sneaked(x INTEGER)`); err == nil {
		t.Error("the read-only pool accepted a write")
	}

	err := db.WriteTx(context.Background(), func(tx *sql.Tx) error { return nil })
	if !errors.Is(err, ErrReadOnly) {
		t.Errorf("WriteTx error = %v, want ErrReadOnly", err)
	}
	if err := db.Migrate(context.Background()); !errors.Is(err, ErrReadOnly) {
		t.Errorf("Migrate error = %v, want ErrReadOnly", err)
	}
}

// An operator runs `audit verify` while the server is running, so a read-only
// open must not need the write lock.
func TestOpenReadOnlyWorksWhileAWriterHoldsTheLock(t *testing.T) {
	path := migratedDB(t)

	writer, err := Open(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()

	held := make(chan struct{})
	release := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- writer.WriteTx(context.Background(), func(tx *sql.Tx) error {
			if _, err := tx.Exec(`CREATE TABLE held(x INTEGER)`); err != nil {
				return err
			}
			close(held)
			<-release
			return nil
		})
	}()
	<-held

	db := openRO(t, path)
	var n int
	if err := db.Read().QueryRow(`SELECT count(*) FROM schema_migration`).Scan(&n); err != nil {
		t.Errorf("read blocked behind a writer: %v", err)
	}

	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

// Close on a read-only handle has no writer pool to checkpoint through and must
// not report a failure for not having one.
func TestReadOnlyCloseSucceeds(t *testing.T) {
	path := migratedDB(t)
	db, err := OpenReadOnly(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
}

// _query_only gates the SQL layer, not the pager. Under mode=rw the last
// connection to close checkpoints the -wal into the database and unlinks it, so
// hashing a db/-wal pair for chain of custody and then running `audit verify`
// changed both — the evidence tool altering the evidence.
func TestOpenReadOnlyLeavesTheWALAlone(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "nodary.db")
	db, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	// wal_autocheckpoint(0) is what leaves an uncheckpointed -wal behind, which
	// is the state a crashed writer leaves and the state this is about.
	w, err := sql.Open("sqlite", writerDSN(path)+"&_pragma=wal_autocheckpoint(0)")
	if err != nil {
		t.Fatal(err)
	}
	const rows = 400
	for i := range rows {
		prev := sha256.Sum256([]byte{byte(i), byte(i >> 8), 1})
		this := sha256.Sum256([]byte{byte(i), byte(i >> 8), 2})
		if _, err := w.Exec(`
			INSERT INTO audit (seq, v, install, ts, actor_method, action,
			                   outcome, detail_json, prev_hash, hash)
			VALUES (?, 1, 'ins_x', '2026-01-01T00:00:00.000Z', 'local', 'a',
			        'success', '{}', ?, ?)`,
			i+1, hex.EncodeToString(prev[:]), hex.EncodeToString(this[:])); err != nil {
			t.Fatal(err)
		}
	}

	// Copied while the frames are still only in the -wal, the way an auditor
	// pulls a pair off a running or crashed appliance.
	custody := filepath.Join(t.TempDir(), "nodary.db")
	for _, sfx := range []string{"", "-wal", "-shm"} {
		b, err := os.ReadFile(path + sfx)
		if err != nil {
			continue
		}
		if err := os.WriteFile(custody+sfx, b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	w.Close()
	db.Close()

	before, err := os.ReadFile(custody)
	if err != nil {
		t.Fatal(err)
	}
	beforeWAL, err := os.ReadFile(custody + "-wal")
	if err != nil {
		t.Fatalf("the copy has no -wal, so this test would prove nothing: %v", err)
	}

	ro := openRO(t, custody)
	var n int
	if err := ro.Read().QueryRow(`SELECT count(*) FROM audit`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if err := ro.Close(); err != nil {
		t.Fatal(err)
	}

	// Read every committed frame, and left both files exactly as they were.
	if n != rows {
		t.Errorf("read %d records, want %d: the uncheckpointed -wal was not read", n, rows)
	}
	after, err := os.ReadFile(custody)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Errorf("a read-only open changed the database: %d bytes became %d",
			len(before), len(after))
	}
	afterWAL, err := os.ReadFile(custody + "-wal")
	if err != nil {
		t.Fatalf("a read-only open deleted the -wal: %v", err)
	}
	if !bytes.Equal(beforeWAL, afterWAL) {
		t.Errorf("a read-only open changed the -wal: %d bytes became %d",
			len(beforeWAL), len(afterWAL))
	}
}

// Both the driver and SQLite split a DSN at the first '?', and SQLite
// percent-decodes what precedes it. Concatenating a path into the URI therefore
// opened a different file than the operator named: `--db no%64ary.db` reported
// nodary.db's chain under the wrong name and exited 0, and `--db a?b.db`
// created a file called `a`.
func TestDSNDoesNotReinterpretAPath(t *testing.T) {
	for _, name := range []string{"nodary?x.db", "a#b.db", "no%64ary.db", "plain.db"} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, name)
			db, err := Open(context.Background(), path)
			if err != nil {
				t.Fatal(err)
			}
			if err := db.Migrate(context.Background()); err != nil {
				t.Fatal(err)
			}
			if err := db.Close(); err != nil {
				t.Fatal(err)
			}

			var opened string
			rows, err := openRO(t, path).Read().Query(`PRAGMA database_list`)
			if err != nil {
				t.Fatal(err)
			}
			for rows.Next() {
				var seq int
				var schema string
				if err := rows.Scan(&seq, &schema, &opened); err != nil {
					t.Fatal(err)
				}
			}
			rows.Close()
			if opened != path {
				t.Errorf("opened %q, want %q", opened, path)
			}

			ents, err := os.ReadDir(dir)
			if err != nil {
				t.Fatal(err)
			}
			for _, e := range ents {
				switch e.Name() {
				case name, name + "-wal", name + "-shm":
				default:
					t.Errorf("invented a file: %q", e.Name())
				}
			}
		})
	}
}
