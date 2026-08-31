package store

import (
	"context"
	"database/sql"
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
