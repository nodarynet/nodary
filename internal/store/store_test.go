package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func openTemp(t *testing.T) *DB {
	t.Helper()
	db, err := Open(context.Background(), filepath.Join(t.TempDir(), "sub", "nodary.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

// The pragmas are the durability and concurrency posture of the whole system,
// and they are set through the DSN, where a typo is silent — an unknown pragma
// name is simply ignored rather than refused.
func TestPragmasAreActuallyApplied(t *testing.T) {
	db := openTemp(t)
	for _, tc := range []struct{ pragma, want string }{
		{"journal_mode", "wal"},
		{"foreign_keys", "1"},
		{"busy_timeout", "5000"},
		{"synchronous", "2"}, // 2 is FULL
	} {
		for name, pool := range map[string]*sql.DB{"writer": db.write, "reader": db.read} {
			var got string
			if err := pool.QueryRow("PRAGMA " + tc.pragma).Scan(&got); err != nil {
				t.Fatalf("%s PRAGMA %s: %v", name, tc.pragma, err)
			}
			if !strings.EqualFold(got, tc.want) {
				t.Errorf("%s PRAGMA %s = %s, want %s", name, tc.pragma, got, tc.want)
			}
		}
	}
}

// The -wal file holds committed-but-uncheckpointed audit records and encrypted
// secrets. SQLite creates the sidecars from the process umask, so a permissive
// umask would leave evidence world-readable without this.
func TestFileAndSidecarModes(t *testing.T) {
	old := syscallUmask(0o022) // a permissive umask is the case that matters
	defer syscallUmask(old)

	// Deliberately does NOT call restrictPermissions: Open must do it, and an
	// earlier version of this test called it here, so deleting the call in
	// Open would not have failed anything.
	db := openTemp(t)
	if err := db.WriteTx(context.Background(), func(tx *sql.Tx) error {
		_, err := tx.Exec(`CREATE TABLE t(a INTEGER)`)
		return err
	}); err != nil {
		t.Fatal(err)
	}

	for _, suffix := range []string{"", "-wal", "-shm"} {
		p := db.Path() + suffix
		fi, err := os.Stat(p)
		if err != nil {
			if suffix == "" {
				t.Fatalf("database missing: %v", err)
			}
			continue
		}
		if fi.Mode().Perm()&0o077 != 0 {
			t.Errorf("%s is %#o, readable beyond the owner", filepath.Base(p), fi.Mode().Perm())
		}
	}

	di, err := os.Stat(filepath.Dir(db.Path()))
	if err != nil {
		t.Fatal(err)
	}
	if di.Mode().Perm()&0o077 != 0 {
		t.Errorf("data directory is %#o, want owner-only", di.Mode().Perm())
	}
}

// Pointing --data-dir at an unrelated SQLite file must be an error, not a
// migration run against somebody else's data.
func TestRefusesAForeignDatabase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "other.db")
	other, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := other.Exec(`CREATE TABLE somebody_elses(x INTEGER)`); err != nil {
		t.Fatal(err)
	}
	other.Close()

	db, err := Open(context.Background(), path)
	if err == nil {
		db.Close()
		t.Fatal("opened a foreign database, want a refusal")
	}
	if !errors.Is(err, ErrNotNodaryDatabase) {
		t.Errorf("error = %v, want ErrNotNodaryDatabase", err)
	}
}

func TestStampsAndAcceptsItsOwnDatabase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nodary.db")
	db, err := Open(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	db.Close()

	// Reopening must recognise the stamp rather than re-deciding.
	db2, err := Open(context.Background(), path)
	if err != nil {
		t.Fatalf("reopening a stamped database: %v", err)
	}
	defer db2.Close()

	var id int64
	if err := db2.Read().QueryRow("PRAGMA application_id").Scan(&id); err != nil {
		t.Fatal(err)
	}
	if id != applicationID {
		t.Errorf("application_id = %#x, want %#x", id, applicationID)
	}
}

func TestWriteTxRollsBackOnError(t *testing.T) {
	db := openTemp(t)
	ctx := context.Background()
	if err := db.WriteTx(ctx, func(tx *sql.Tx) error {
		_, err := tx.Exec(`CREATE TABLE t(a INTEGER)`)
		return err
	}); err != nil {
		t.Fatal(err)
	}

	sentinel := errors.New("caller changed its mind")
	err := db.WriteTx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.Exec(`INSERT INTO t VALUES (1)`); err != nil {
			return err
		}
		return sentinel
	})
	if !errors.Is(err, sentinel) {
		t.Fatalf("WriteTx error = %v, want the caller's error unwrapped", err)
	}

	var n int
	if err := db.Read().QueryRow(`SELECT count(*) FROM t`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Errorf("%d rows survived a rolled-back transaction, want 0", n)
	}
}

// appendLink is the pattern R1-07 actually depends on, and it is deliberately
// two statements with Go in between.
//
// A single `INSERT ... SELECT MAX(seq)+1 FROM chain` would be atomic on its own,
// because SQLite takes the write lock before executing any statement that
// writes — testing with it would pass whether or not _txlock=immediate is set,
// which is a test that proves nothing. R1b cannot use that form anyway: it must
// read the predecessor's hash, compute this record's hash in Go, and only then
// insert. That read-then-write across statements is what needs the transaction
// to hold the write lock from BEGIN.
func appendLink(tx *sql.Tx, who string) error {
	var max int64
	if err := tx.QueryRow(`SELECT COALESCE(MAX(seq),0) FROM chain`).Scan(&max); err != nil {
		return err
	}
	// Stands in for hashing the previous record: any real work between the read
	// and the write widens the window a second writer can slip through.
	runtime.Gosched()
	_, err := tx.Exec(`INSERT INTO chain(seq, who) VALUES (?, ?)`, max+1, who)
	return err
}

func createChain(t *testing.T, db *DB) {
	t.Helper()
	if err := db.WriteTx(context.Background(), func(tx *sql.Tx) error {
		_, err := tx.Exec(`CREATE TABLE IF NOT EXISTS chain(seq INTEGER PRIMARY KEY, who TEXT)`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

func TestConcurrentGoroutinesCannotShareASeq(t *testing.T) {
	db := openTemp(t)
	createChain(t, db)

	const writers, each = 8, 25
	var wg sync.WaitGroup
	errCh := make(chan error, writers*each)
	for w := range writers {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for range each {
				err := db.WriteTx(context.Background(), func(tx *sql.Tx) error {
					return appendLink(tx, strconv.Itoa(w))
				})
				if err != nil {
					errCh <- err
				}
			}
		}(w)
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Fatalf("write failed: %v", err)
	}
	assertContiguous(t, db, writers*each)
}

// The guarantee has to hold across processes, not just goroutines: R1 states
// that "the CLI operates on a local database directly", so a CLI invocation and
// a server are two writers against one file. A pool cap cannot help there, which
// is the whole reason for _txlock=immediate.
func TestConcurrentProcessesCannotShareASeq(t *testing.T) {
	if os.Getenv("NODARY_STORE_CHILD") != "" {
		return // the child path runs in TestMain-less isolation below
	}
	path := filepath.Join(t.TempDir(), "nodary.db")
	db, err := Open(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	createChain(t, db)
	db.Close()

	const procs, each = 4, 25
	// Every child starts at the same instant. Without a barrier the spawn cost
	// dominates and the winner finishes all its writes before the next child is
	// even running, so the assertion below is satisfied trivially.
	startAt := startBarrier(2 * time.Second)
	var wg sync.WaitGroup
	out := make(chan string, procs)
	for p := range procs {
		wg.Add(1)
		go func(p int) {
			defer wg.Done()
			cmd := exec.Command(os.Args[0], "-test.run=TestChildWriter")
			cmd.Env = append(os.Environ(),
				"NODARY_STORE_CHILD=1",
				"NODARY_STORE_PATH="+path,
				"NODARY_STORE_WHO="+strconv.Itoa(p),
				"NODARY_STORE_COUNT="+strconv.Itoa(each),
				"NODARY_STORE_START="+startAt,
			)
			if b, err := cmd.CombinedOutput(); err != nil {
				out <- fmt.Sprintf("child %d: %v\n%s", p, err, b)
			}
		}(p)
	}
	wg.Wait()
	close(out)
	for msg := range out {
		t.Fatal(msg)
	}

	db2, err := Open(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	defer db2.Close()
	assertContiguous(t, db2, procs*each)
}

// TestChildWriter is the other half of TestConcurrentProcessesCannotShareASeq.
// It is a no-op unless the parent invoked it with the environment set.
func TestChildWriter(t *testing.T) {
	path := os.Getenv("NODARY_STORE_PATH")
	if os.Getenv("NODARY_STORE_CHILD") == "" || path == "" {
		t.Skip("not invoked as a child writer")
	}
	n, _ := strconv.Atoi(os.Getenv("NODARY_STORE_COUNT"))
	who := os.Getenv("NODARY_STORE_WHO")

	db, err := Open(context.Background(), path)
	if err != nil {
		t.Fatalf("child Open: %v", err)
	}
	defer db.Close()
	waitForBarrier(t)
	for range n {
		if err := db.WriteTx(context.Background(), func(tx *sql.Tx) error {
			return appendLink(tx, who)
		}); err != nil {
			t.Fatalf("child write: %v", err)
		}
	}
}

// A contiguous 1..want with no gaps and no duplicates is the observable form of
// "no two writers claimed the same sequence number". A duplicate would have been
// rejected by the primary key, so a short count is the tell.
func assertContiguous(t *testing.T, db *DB, want int) {
	t.Helper()
	var rows, distinct, min, max int
	err := db.Read().QueryRow(
		`SELECT count(*), count(DISTINCT seq), COALESCE(MIN(seq),0), COALESCE(MAX(seq),0) FROM chain`,
	).Scan(&rows, &distinct, &min, &max)
	if err != nil {
		t.Fatal(err)
	}
	if rows != want || distinct != want || min != 1 || max != want {
		t.Errorf("chain has %d rows (%d distinct seq) spanning %d..%d, want exactly %d contiguous from 1",
			rows, distinct, min, max, want)
	}
}

func TestCloseTruncatesTheWAL(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nodary.db")
	db, err := Open(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	createChain(t, db)
	for range 200 {
		if err := db.WriteTx(context.Background(), func(tx *sql.Tx) error {
			return appendLink(tx, "bulk")
		}); err != nil {
			t.Fatal(err)
		}
	}
	before, err := os.Stat(path + "-wal")
	if err != nil {
		t.Fatalf("no WAL after 200 writes, so this test would prove nothing: %v", err)
	}
	if before.Size() == 0 {
		t.Fatal("WAL is empty before Close; this test would pass without doing anything")
	}
	if err := db.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	switch fi, err := os.Stat(path + "-wal"); {
	case errors.Is(err, os.ErrNotExist):
		// Removed entirely, which is also a truncation.
	case err != nil:
		t.Fatalf("stat after Close: %v", err)
	case fi.Size() != 0:
		t.Errorf("WAL is %d bytes after Close (was %d), want truncated", fi.Size(), before.Size())
	}
}
