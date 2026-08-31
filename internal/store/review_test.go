package store

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// A panic inside the callback used to leave the transaction unfinished: the
// pool's one connection never returned, and BEGIN IMMEDIATE's write lock still
// held on the file. Every writer on the machine stopped — this process and any
// other, since the CLI writes to the same database — and Close blocked forever.
//
// One bad Scan in a chain writer would have ended the audit log without a word,
// so this asserts recovery rather than merely that the panic propagates.
func TestPanicInWriteTxDoesNotWedgeTheWriter(t *testing.T) {
	db := openTemp(t)
	ctx := context.Background()
	createChain(t, db)

	func() {
		defer func() {
			if recover() == nil {
				t.Error("the panic did not propagate to the caller")
			}
		}()
		_ = db.WriteTx(ctx, func(tx *sql.Tx) error {
			panic("a chain writer dereferenced something nil")
		})
	}()

	// The next write in this process must still work.
	done := make(chan error, 1)
	go func() {
		next, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		done <- db.WriteTx(next, func(tx *sql.Tx) error { return appendLink(tx, "after") })
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("writer wedged after a panic: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("writer wedged after a panic: WriteTx never returned")
	}

	// And the file lock must have been released, so another process can write.
	other, err := Open(ctx, db.Path())
	if err != nil {
		t.Fatalf("second handle could not open after a panic: %v", err)
	}
	defer other.Close()
	octx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := other.WriteTx(octx, func(tx *sql.Tx) error { return appendLink(tx, "other") }); err != nil {
		t.Fatalf("a second handle is still locked out after a panic: %v", err)
	}

	// Close must not hang either.
	closed := make(chan error, 1)
	go func() { closed <- db.Close() }()
	select {
	case <-closed:
	case <-time.After(10 * time.Second):
		t.Fatal("Close blocked after a panic")
	}
}

// "WriteTx is the only write path" is the sentence R1-07 rests on. It was
// enforced by nothing: Read() handed out a fully writable pool.
func TestReadPoolRefusesWrites(t *testing.T) {
	db := openTemp(t)
	createChain(t, db)

	if _, err := db.Read().Exec(`INSERT INTO chain(seq, who) VALUES (99, 'sneaked')`); err == nil {
		t.Fatal("the read pool accepted a write")
	}
	// Reads must still work.
	var n int
	if err := db.Read().QueryRow(`SELECT count(*) FROM chain`).Scan(&n); err != nil {
		t.Fatalf("the read pool cannot read: %v", err)
	}
}

// Refusing a foreign database must not damage it. Opening with
// journal_mode(WAL) converts the file before anything has checked whose it is,
// so the refusal used to arrive after the damage.
func TestRefusingAForeignDatabaseLeavesItUntouched(t *testing.T) {
	path := filepath.Join(t.TempDir(), "someone-elses.db")
	other, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := other.Exec(`CREATE TABLE theirs(x INTEGER)`); err != nil {
		t.Fatal(err)
	}
	other.Close()

	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	db, err := Open(context.Background(), path)
	if err == nil {
		db.Close()
		t.Fatal("opened a foreign database")
	}
	if !errors.Is(err, ErrNotNodaryDatabase) {
		t.Fatalf("error = %v, want ErrNotNodaryDatabase", err)
	}

	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Error("the foreign database was modified while being refused")
	}
	for _, suffix := range []string{"-wal", "-shm"} {
		if _, err := os.Stat(path + suffix); err == nil {
			t.Errorf("a %s sidecar was left beside a foreign database", suffix)
		}
	}
}

// wal_checkpoint reports failure in its result row, not as an error, so a Close
// that only checked the error silently did nothing and still reported success —
// which is how a backup taken after a "clean" shutdown loses its most recent
// records.
func TestCloseReportsABlockedCheckpoint(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nodary.db")
	db, err := Open(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	createChain(t, db)
	for range 50 {
		if err := db.WriteTx(context.Background(), func(tx *sql.Tx) error {
			return appendLink(tx, "bulk")
		}); err != nil {
			t.Fatal(err)
		}
	}

	// A second handle holding an open read transaction pins the WAL. Close
	// must say so rather than reporting success.
	blocker, err := Open(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	defer blocker.Close()
	tx, err := blocker.Read().BeginTx(context.Background(), &sql.TxOptions{ReadOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	var n int
	if err := tx.QueryRow(`SELECT count(*) FROM chain`).Scan(&n); err != nil {
		t.Fatal(err)
	}

	err = db.Close()
	_ = tx.Rollback()
	if err == nil {
		t.Fatal("Close reported success while the checkpoint was blocked")
	}
	if !strings.Contains(err.Error(), "checkpointing WAL") {
		t.Errorf("error = %v, want it to name the checkpoint", err)
	}
}

// MkdirAll does nothing to a directory that already exists, and in a real
// install this directory arrives from a package postinst or an earlier release.
func TestExistingDataDirectoryIsTightened(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "lib")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	db, err := Open(context.Background(), filepath.Join(dir, "nodary.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	fi, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm()&0o077 != 0 {
		t.Errorf("pre-existing data directory left at %#o", fi.Mode().Perm())
	}
}

// A cancelled write must be distinguishable from a bug. It used to surface as
// "sql: transaction has already been committed or rolled back".
func TestCancelledWriteReportsCancellation(t *testing.T) {
	db := openTemp(t)
	createChain(t, db)

	ctx, cancel := context.WithCancel(context.Background())
	err := db.WriteTx(ctx, func(tx *sql.Tx) error {
		cancel()
		return tx.QueryRow(`SELECT count(*) FROM chain`).Scan(new(int))
	})
	if err == nil {
		t.Fatal("want an error from a cancelled transaction")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("error = %v, want it to unwrap to context.Canceled", err)
	}
}

// IsBusy is exported so a caller holding a record it must not drop can tell
// "try again" from "give up".
func TestIsBusyClassifiesLockContention(t *testing.T) {
	if IsBusy(errors.New("something else")) {
		t.Error("IsBusy accepted an unrelated error")
	}
	if IsBusy(nil) {
		t.Error("IsBusy accepted nil")
	}
}

// startBarrier hands every child the same absolute start instant. Without it
// the parent's process-spawn cost dominates and the children never overlap at
// all, so an assertion about concurrent behaviour is satisfied by writers that
// never ran concurrently.
//
// It is an improvement, not a proof. Measured: with the barrier in place, the
// cross-process migrator test does catch the realistic mistake (reading the
// applied set off the reader pool, outside the write lock — 3 failures in 3
// runs), but still does not catch a build that reads it in its own separate
// write transaction (6 passes in 6 runs), because the file lock serialises the
// children whatever start time they share. See
// TestMigrateBlockedBehindAWriterAppliesOnce for the ordering forced directly.
func startBarrier(d time.Duration) string {
	return time.Now().Add(d).Format(time.RFC3339Nano)
}

func waitForBarrier(t *testing.T) {
	t.Helper()
	at := os.Getenv("NODARY_STORE_START")
	if at == "" {
		return
	}
	when, err := time.Parse(time.RFC3339Nano, at)
	if err != nil {
		t.Fatalf("bad start barrier %q: %v", at, err)
	}
	for time.Now().Before(when) {
		// Spin rather than sleep: the window being contended is microseconds
		// wide, and a sleep's granularity is wider than that.
	}
}

// Proof that the barrier is doing something: without it, children spawned
// sequentially finish before the next one starts.
func TestBarrierMakesChildrenOverlap(t *testing.T) {
	const n = 4
	at := startBarrier(300 * time.Millisecond)
	when, err := time.Parse(time.RFC3339Nano, at)
	if err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	starts := make([]time.Time, n)
	for i := range n {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for time.Now().Before(when) {
			}
			starts[i] = time.Now()
		}(i)
	}
	wg.Wait()

	spread := starts[0].Sub(starts[0])
	for _, s := range starts {
		if d := s.Sub(when); d > spread {
			spread = d
		}
	}
	if spread > 50*time.Millisecond {
		t.Errorf("barrier released over %v, too loose to create contention", spread)
	}
}

// A deterministic version of the concurrent-migrator property.
//
// TestConcurrentMigratorsApplyOnce spawns real processes and asserts the
// outcome. That catches the realistic mistake, but it cannot manufacture an
// arbitrary interleaving: the migration takes microseconds and the file write
// lock serialises the children whatever start barrier they share, so it passed
// six out of six against a build that read the applied set in a separate write
// transaction.
//
// This one forces the ordering instead of hoping for it. A holds the write lock
// with every migration applied but uncommitted; B calls Migrate and must block
// on BEGIN, observe the applied set once A commits, and do nothing. A build
// that read the applied set before taking the lock sees an empty set and tries
// to CREATE TABLE a second time — verified: 3 failures in 3 runs against that
// mutation, before and after 0002 joined the set.
func TestMigrateBlockedBehindAWriterAppliesOnce(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nodary.db")
	ctx := context.Background()

	a, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	b, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()

	first, err := loadMigrations(migrationsFS, "migrations")
	if err != nil {
		t.Fatal(err)
	}

	holding := make(chan struct{})
	release := make(chan struct{})
	aDone := make(chan error, 1)

	go func() {
		aDone <- a.WriteTx(ctx, func(tx *sql.Tx) error {
			for _, m := range first {
				if err := apply(tx, m); err != nil {
					return err
				}
			}
			close(holding)
			<-release // hold the write lock open
			return nil
		})
	}()

	<-holding

	bDone := make(chan error, 1)
	go func() { bDone <- b.Migrate(ctx) }()

	// B must not be able to finish while A holds the lock.
	select {
	case err := <-bDone:
		close(release)
		t.Fatalf("the second migrator completed while the write lock was held: %v", err)
	case <-time.After(250 * time.Millisecond):
	}

	close(release)
	if err := <-aDone; err != nil {
		t.Fatalf("first migrator: %v", err)
	}
	if err := <-bDone; err != nil {
		t.Fatalf("second migrator failed instead of finding the set already applied: %v", err)
	}

	var rows int
	if err := b.Read().QueryRow(`SELECT count(*) FROM schema_migration`).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if want := len(embeddedVersions(t)); rows != want {
		t.Errorf("schema_migration has %d rows, want exactly %d", rows, want)
	}
}
