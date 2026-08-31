package store

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"testing/fstest"
	"time"
)

func set(files map[string]string) fs.FS {
	m := fstest.MapFS{}
	for name, body := range files {
		m["migrations/"+name] = &fstest.MapFile{Data: []byte(body)}
	}
	return m
}

func migrateWith(t *testing.T, db *DB, files map[string]string) error {
	t.Helper()
	return db.MigrateFS(context.Background(), set(files), "migrations")
}

func appliedVersions(t *testing.T, db *DB) []int {
	t.Helper()
	rows, err := db.Read().Query(`SELECT version FROM schema_migration ORDER BY version`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []int
	for rows.Next() {
		var v int
		if err := rows.Scan(&v); err != nil {
			t.Fatal(err)
		}
		out = append(out, v)
	}
	return out
}

// embeddedVersions is what a fully migrated database should contain. Derived
// rather than written out, so adding a migration does not silently turn these
// tests into assertions about a stale number.
func embeddedVersions(t *testing.T) []int {
	t.Helper()
	ms, err := loadMigrations(migrationsFS, "migrations")
	if err != nil {
		t.Fatal(err)
	}
	out := make([]int, 0, len(ms))
	for _, m := range ms {
		out = append(out, m.version)
	}
	if len(out) == 0 {
		t.Fatal("no migrations are embedded")
	}
	return out
}

// The bookkeeping table is created by a migration, not by bootstrap DDL in Go,
// so the very first run has to work against a database where the table the
// runner records into does not exist yet.
func TestFreshDatabaseBootstrapsItself(t *testing.T) {
	db := openTemp(t)
	if err := db.Migrate(context.Background()); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	if got, want := appliedVersions(t, db), embeddedVersions(t); !slices.Equal(got, want) {
		t.Errorf("applied = %v, want %v", got, want)
	}
}

func TestRerunIsANoOp(t *testing.T) {
	db := openTemp(t)
	ctx := context.Background()
	for i := range 3 {
		if err := db.Migrate(ctx); err != nil {
			t.Fatalf("Migrate #%d: %v", i+1, err)
		}
	}
	if got, want := appliedVersions(t, db), embeddedVersions(t); !slices.Equal(got, want) {
		t.Errorf("applied = %v after three runs, want %v", got, want)
	}
}

func TestAppliesInVersionOrder(t *testing.T) {
	db := openTemp(t)
	err := migrateWith(t, db, map[string]string{
		"0001_schema_migration.sql": schemaMigrationDDL,
		// 0003 depends on 0002 having run, so any non-ascending order fails
		// here — map iteration order most plausibly. It does not distinguish
		// numeric from lexical sorting: the filename pattern requires four
		// digits, and zero-padding makes the two agree up to 9999.
		"0003_third.sql":  `INSERT INTO second(x) VALUES (1)`,
		"0002_second.sql": `CREATE TABLE second(x INTEGER) STRICT`,
	})
	if err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	want := []int{1, 2, 3}
	got := appliedVersions(t, db)
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("applied = %v, want %v", got, want)
	}
}

// A changed file means the schema in the database is not the one this binary
// believes it wrote. 08 §5 requires aborting rather than proceeding.
func TestAlteredMigrationAborts(t *testing.T) {
	db := openTemp(t)
	original := map[string]string{
		"0001_schema_migration.sql": schemaMigrationDDL,
		"0002_second.sql":           `CREATE TABLE second(x INTEGER) STRICT`,
	}
	if err := migrateWith(t, db, original); err != nil {
		t.Fatal(err)
	}

	tampered := map[string]string{
		"0001_schema_migration.sql": schemaMigrationDDL,
		"0002_second.sql":           `CREATE TABLE second(x INTEGER, y INTEGER) STRICT`,
	}
	err := migrateWith(t, db, tampered)
	if !errors.Is(err, ErrChecksumMismatch) {
		t.Fatalf("error = %v, want ErrChecksumMismatch", err)
	}
	// Naming the migration is the point: "checksum mismatch" alone leaves an
	// operator diffing every file in the directory.
	if !strings.Contains(err.Error(), "0002_second") {
		t.Errorf("error %q does not name the migration", err)
	}
}

// Rolling a nodary version back is not supported; the recovery is restoring a
// backup taken before the upgrade (08 §5).
func TestDowngradeRefused(t *testing.T) {
	db := openTemp(t)
	newer := map[string]string{
		"0001_schema_migration.sql": schemaMigrationDDL,
		"0002_second.sql":           `CREATE TABLE second(x INTEGER) STRICT`,
	}
	if err := migrateWith(t, db, newer); err != nil {
		t.Fatal(err)
	}

	older := map[string]string{"0001_schema_migration.sql": schemaMigrationDDL}
	err := migrateWith(t, db, older)
	if !errors.Is(err, ErrDowngrade) {
		t.Fatalf("error = %v, want ErrDowngrade", err)
	}
}

// Two branches numbering independently is how this happens. Applying 0002 after
// 0003 has run would execute it against a schema it was never written for.
func TestOutOfOrderMigrationRefused(t *testing.T) {
	db := openTemp(t)
	if err := migrateWith(t, db, map[string]string{
		"0001_schema_migration.sql": schemaMigrationDDL,
		"0003_third.sql":            `CREATE TABLE third(x INTEGER) STRICT`,
	}); err != nil {
		t.Fatal(err)
	}

	err := migrateWith(t, db, map[string]string{
		"0001_schema_migration.sql": schemaMigrationDDL,
		"0002_second.sql":           `CREATE TABLE second(x INTEGER) STRICT`,
		"0003_third.sql":            `CREATE TABLE third(x INTEGER) STRICT`,
	})
	if !errors.Is(err, ErrMigrationGap) {
		t.Fatalf("error = %v, want ErrMigrationGap", err)
	}
}

// Either the database is fully migrated or it is untouched. A partial run would
// leave a schema no version of the binary has ever expected.
func TestFailingMigrationRollsBackWhole(t *testing.T) {
	db := openTemp(t)
	err := migrateWith(t, db, map[string]string{
		"0001_schema_migration.sql": schemaMigrationDDL,
		"0002_second.sql":           `CREATE TABLE second(x INTEGER) STRICT`,
		"0003_broken.sql":           `CREATE TABLE oops(`,
	})
	if err == nil {
		t.Fatal("want an error from the broken migration")
	}

	var tables int
	if err := db.Read().QueryRow(
		`SELECT count(*) FROM sqlite_master WHERE type='table'`).Scan(&tables); err != nil {
		t.Fatal(err)
	}
	if tables != 0 {
		t.Errorf("%d tables survived a failed run, want the whole run rolled back", tables)
	}
}

// PRAGMA is silently a no-op inside a transaction and VACUUM cannot run in one
// at all, so a migration using either would appear to succeed and do nothing.
func TestUnsafeStatementsRejected(t *testing.T) {
	for _, body := range []string{
		"PRAGMA foreign_keys = OFF;\nCREATE TABLE t(x INTEGER) STRICT;",
		"VACUUM;",
		"create table t(x integer) strict;\nvacuum;",
	} {
		db := openTemp(t)
		err := migrateWith(t, db, map[string]string{
			"0001_schema_migration.sql": schemaMigrationDDL,
			"0002_unsafe.sql":           body,
		})
		if !errors.Is(err, ErrUnsafeMigration) {
			t.Errorf("body %q: error = %v, want ErrUnsafeMigration", body, err)
		}
	}
}

// The check strips comments first, so a migration may explain in prose why it
// avoids a PRAGMA. A checker too dumb to allow that gets worked around.
func TestKeywordsInCommentsAreAllowed(t *testing.T) {
	db := openTemp(t)
	err := migrateWith(t, db, map[string]string{
		"0001_schema_migration.sql": schemaMigrationDDL,
		"0002_second.sql": "-- Deliberately no PRAGMA here; see 08 §5.\n" +
			"/* VACUUM would not run in a transaction either. */\n" +
			"CREATE TABLE second(x INTEGER) STRICT;",
	})
	if err != nil {
		t.Fatalf("keyword inside a comment was rejected: %v", err)
	}
}

func TestMalformedFilenamesRejected(t *testing.T) {
	for _, name := range []string{"1_first.sql", "0001-first.sql", "first.sql", "0001_First.sql"} {
		db := openTemp(t)
		err := migrateWith(t, db, map[string]string{name: schemaMigrationDDL})
		if err == nil {
			t.Errorf("%q was accepted, want a refusal", name)
		}
	}
}

func TestDuplicateVersionsRejected(t *testing.T) {
	db := openTemp(t)
	err := migrateWith(t, db, map[string]string{
		"0001_schema_migration.sql": schemaMigrationDDL,
		"0002_second.sql":           `CREATE TABLE second(x INTEGER) STRICT`,
		"0002_also_second.sql":      `CREATE TABLE other(x INTEGER) STRICT`,
	})
	if err == nil || !strings.Contains(err.Error(), "share version") {
		t.Fatalf("error = %v, want a duplicate-version refusal", err)
	}
}

// The CLI opens the database directly, so a CLI invocation can race a server
// start. Reading the applied set inside the write transaction is what makes the
// loser a no-op instead of a second application of the same migration.
func TestConcurrentMigratorsApplyOnce(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nodary.db")

	const procs = 4
	// Same barrier as the writer test: the migration itself takes microseconds,
	// so without a rendezvous the children never overlap and this passed 14
	// times in a row with the mechanism it exists to test deleted.
	startAt := startBarrier(2 * time.Second)
	var wg sync.WaitGroup
	fails := make(chan string, procs)
	for p := range procs {
		wg.Add(1)
		go func(p int) {
			defer wg.Done()
			cmd := exec.Command(os.Args[0], "-test.run=TestChildMigrator")
			cmd.Env = append(os.Environ(),
				"NODARY_STORE_CHILD=1",
				"NODARY_STORE_PATH="+path,
				"NODARY_STORE_WHO="+strconv.Itoa(p),
				"NODARY_STORE_START="+startAt,
			)
			if b, err := cmd.CombinedOutput(); err != nil {
				fails <- fmt.Sprintf("child %d: %v\n%s", p, err, b)
			}
		}(p)
	}
	wg.Wait()
	close(fails)
	for msg := range fails {
		t.Fatal(msg)
	}

	db, err := Open(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if got, want := appliedVersions(t, db), embeddedVersions(t); !slices.Equal(got, want) {
		t.Errorf("applied = %v after %d concurrent migrators, want exactly %v", got, procs, want)
	}
}

// TestChildMigrator is the other half of TestConcurrentMigratorsApplyOnce.
func TestChildMigrator(t *testing.T) {
	path := os.Getenv("NODARY_STORE_PATH")
	if os.Getenv("NODARY_STORE_CHILD") == "" || path == "" {
		t.Skip("not invoked as a child migrator")
	}
	db, err := Open(context.Background(), path)
	if err != nil {
		t.Fatalf("child Open: %v", err)
	}
	defer db.Close()
	waitForBarrier(t)
	if err := db.Migrate(context.Background()); err != nil {
		t.Fatalf("child Migrate: %v", err)
	}
}

// The embedded set has to satisfy the same rules the runner enforces, and a
// malformed one is a build defect rather than an operator's problem.
func TestEmbeddedMigrationsAreWellFormed(t *testing.T) {
	ms, err := loadMigrations(migrationsFS, "migrations")
	if err != nil {
		t.Fatalf("embedded migrations do not load: %v", err)
	}
	if len(ms) == 0 {
		t.Fatal("no embedded migrations")
	}
	if ms[0].version != 1 || ms[0].name != "schema_migration" {
		t.Errorf("first migration is %04d_%s, want 0001_schema_migration", ms[0].version, ms[0].name)
	}
	for i, m := range ms {
		if m.version != i+1 {
			t.Errorf("migration %d is version %d; versions must be contiguous from 1", i, m.version)
		}
	}
}

// A private copy of 0001's DDL for the synthetic sets above, so a test that
// changes it cannot alter the checksum of the shipped migration.
const schemaMigrationDDL = `CREATE TABLE schema_migration (
    version    INTEGER PRIMARY KEY,
    name       TEXT NOT NULL,
    checksum   TEXT NOT NULL,
    applied_at TEXT NOT NULL
) STRICT;`
