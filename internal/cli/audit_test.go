package cli

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nodarynet/nodary/internal/audit"
	"github.com/nodarynet/nodary/internal/store"
)

// chain writes n records to a temporary database and mirrors them to a file,
// returning both paths.
func chain(t *testing.T, n int) (dbPath, mirror string) {
	t.Helper()
	dir := t.TempDir()
	dbPath = filepath.Join(dir, "nodary.db")
	mirror = filepath.Join(dir, "audit.jsonl")

	db, err := store.Open(context.Background(), dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}

	at := time.Date(2026, 8, 31, 9, 14, 2, 371_000_000, time.UTC)
	l := audit.New(db,
		audit.NewDelivery([]audit.Sink{audit.NewFileSink(mirror)}, audit.Warn, io.Discard),
		audit.WithClock(func() time.Time { return at }))
	for i := range n {
		req := audit.Request{
			Actor:  audit.Actor{ID: "root", Method: "local"},
			Source: audit.Source{Version: "0.0.1-rc1"},
			Action: fmt.Sprintf("thing.add.%d", i),
			Target: &audit.Target{Kind: "thing", ID: fmt.Sprintf("thg_%d", i)},
		}
		if _, err := l.Act(context.Background(), req, func(m audit.Mutation) error { return nil }); err != nil {
			t.Fatal(err)
		}
	}
	return dbPath, mirror
}

func TestAuditVerifyReportsAWholeChain(t *testing.T) {
	dbPath, _ := chain(t, 5)

	code, stdout, stderr := run(t, "audit", "verify", "--db", dbPath)
	if code != ExitOK {
		t.Fatalf("exit = %d, want 0 (stderr %q)", code, stderr)
	}
	if !strings.Contains(stdout, "verified") || !strings.Contains(stdout, "seq 1–5") {
		t.Errorf("stdout = %q", stdout)
	}
	if stderr != "" {
		t.Errorf("stderr = %q, want nothing", stderr)
	}
}

// R1-09: verify names the first bad sequence, and exits non-zero.
func TestAuditVerifyNamesTheFirstBreakAndExitsOne(t *testing.T) {
	dbPath, _ := chain(t, 9)

	db, err := store.Open(context.Background(), dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.WriteTx(context.Background(), func(tx *sql.Tx) error {
		_, err := tx.Exec(`UPDATE audit SET justification = 'inserted later' WHERE seq = 6`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	db.Close()

	code, stdout, _ := run(t, "audit", "verify", "--db", dbPath)
	if code != ExitFailure {
		t.Errorf("exit = %d, want 1", code)
	}
	if !strings.Contains(stdout, "seq 6") {
		t.Errorf("stdout should name seq 6, got %q", stdout)
	}
	if !strings.Contains(stdout, string(audit.KindAltered)) {
		t.Errorf("stdout should say what was wrong, got %q", stdout)
	}
}

func TestAuditVerifyJSONIsAStableDocumentOnStdout(t *testing.T) {
	dbPath, mirror := chain(t, 4)

	code, stdout, stderr := run(t, "audit", "verify", "--db", dbPath, "--mirror", mirror, "--format", "json")
	if code != ExitOK {
		t.Fatalf("exit = %d (stderr %q)", code, stderr)
	}
	var got struct {
		OK    bool `json:"ok"`
		Chain struct {
			OK       bool  `json:"ok"`
			Records  int64 `json:"records"`
			LastSeq  int64 `json:"last_seq"`
			Warnings []any `json:"warnings"`
		} `json:"chain"`
		Mirror struct {
			Path    string `json:"path"`
			Records int64  `json:"records"`
		} `json:"mirror"`
		Comparison struct {
			Behind int64 `json:"behind"`
			Ahead  int64 `json:"ahead"`
		} `json:"comparison"`
	}
	if err := json.Unmarshal([]byte(stdout), &got); err != nil {
		t.Fatalf("stdout is not valid JSON: %v\n%s", err, stdout)
	}
	if !got.OK || !got.Chain.OK || got.Chain.Records != 4 || got.Chain.LastSeq != 4 {
		t.Errorf("report = %+v", got)
	}
	if got.Mirror.Path != mirror || got.Mirror.Records != 4 {
		t.Errorf("mirror report = %+v", got.Mirror)
	}
	if got.Comparison.Behind != 0 || got.Comparison.Ahead != 0 {
		t.Errorf("comparison = %+v", got.Comparison)
	}
	if got.Chain.Warnings == nil {
		t.Error("warnings should be an empty array, not null, so a consumer can iterate it")
	}
}

// The case an auditor is in: a copy pulled from a SIEM, on a machine that has
// never seen the database it came from.
func TestAuditVerifyChecksAMirrorWithNoDatabase(t *testing.T) {
	dbPath, mirror := chain(t, 5)
	for _, suffix := range []string{"", "-wal", "-shm"} {
		os.Remove(dbPath + suffix)
	}

	elsewhere := filepath.Join(t.TempDir(), "retrieved.jsonl")
	b, err := os.ReadFile(mirror)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(elsewhere, b, 0o600); err != nil {
		t.Fatal(err)
	}

	code, stdout, stderr := run(t, "audit", "verify", "--mirror", elsewhere)
	if code != ExitOK {
		t.Fatalf("exit = %d, want 0 (stderr %q, stdout %q)", code, stderr, stdout)
	}
	if !strings.Contains(stdout, "verified") {
		t.Errorf("stdout = %q", stdout)
	}
	if strings.Contains(stdout, "chain:") {
		t.Errorf("no database was present, so nothing should be reported about one: %q", stdout)
	}
}

// A database the operator named and that is not there is a mistake, not the
// no-database case.
func TestAuditVerifyRefusesANamedDatabaseThatIsAbsent(t *testing.T) {
	_, mirror := chain(t, 3)
	missing := filepath.Join(t.TempDir(), "nope.db")

	code, _, stderr := run(t, "audit", "verify", "--db", missing, "--mirror", mirror)
	if code != ExitFailure {
		t.Errorf("exit = %d, want 1", code)
	}
	if !strings.Contains(stderr, missing) {
		t.Errorf("stderr should name the database, got %q", stderr)
	}
}

// A read-only command must not migrate the database it was asked to inspect.
func TestAuditVerifyRefusesAnUnmigratedDatabaseRatherThanMigratingIt(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nodary.db")
	db, err := store.Open(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	db.Close() // stamped, never migrated

	code, _, stderr := run(t, "audit", "verify", "--db", path)
	if code != ExitFailure {
		t.Errorf("exit = %d, want 1", code)
	}
	if !strings.Contains(stderr, "schema") {
		t.Errorf("stderr = %q, want it to say the schema is behind", stderr)
	}

	check, err := store.Open(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	defer check.Close()
	var present int
	if err := check.Read().QueryRow(
		`SELECT count(*) FROM sqlite_master WHERE type='table' AND name='audit'`).Scan(&present); err != nil {
		t.Fatal(err)
	}
	if present != 0 {
		t.Error("a read-only verify migrated the database")
	}
}

func TestAuditVerifyReportsAMirrorThatIsMerelyBehind(t *testing.T) {
	dbPath, mirror := chain(t, 6)
	b, err := os.ReadFile(mirror)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSuffix(string(b), "\n"), "\n")
	if err := os.WriteFile(mirror, []byte(strings.Join(lines[:4], "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	code, stdout, _ := run(t, "audit", "verify", "--db", dbPath, "--mirror", mirror)
	if code != ExitOK {
		t.Errorf("exit = %d; a mirror behind the database is ordinary, not a failure", code)
	}
	if !strings.Contains(stdout, "2 records behind") {
		t.Errorf("stdout = %q", stdout)
	}
}

func TestAuditUsage(t *testing.T) {
	code, _, stderr := run(t, "audit")
	if code != ExitUsage {
		t.Errorf("exit = %d, want 2", code)
	}
	if !strings.Contains(stderr, "verify") {
		t.Errorf("stderr = %q", stderr)
	}

	code, _, stderr = run(t, "audit", "frobnicate")
	if code != ExitUsage {
		t.Errorf("exit = %d, want 2", code)
	}
	if !strings.Contains(stderr, "frobnicate") {
		t.Errorf("stderr should name the bad subcommand, got %q", stderr)
	}
}
