package cli

import (
	"context"
	"database/sql"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/nodarynet/nodary/internal/audit"
	"github.com/nodarynet/nodary/internal/paths"
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
	// This case is defined by the absence of a database at the default
	// location, and internal/paths is deliberately not configurable — so the
	// test can only assert it on a machine where nodary is not installed.
	// Without this it opened the operator's real chain and compared the fixture
	// against it, and the failure read as a defect in the code rather than in
	// the machine.
	if _, err := os.Stat(paths.Database()); err == nil {
		t.Skipf("%s exists on this machine, so there is no no-database case to test",
			paths.Database())
	}
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

func TestAuditListIsNewestFirstWithAHeader(t *testing.T) {
	dbPath, _ := chain(t, 4)

	code, stdout, stderr := run(t, "audit", "list", "--db", dbPath)
	if code != ExitOK {
		t.Fatalf("exit = %d (stderr %q)", code, stderr)
	}
	lines := strings.Split(strings.TrimSuffix(stdout, "\n"), "\n")
	if len(lines) != 5 {
		t.Fatalf("got %d lines, want a header and 4 records:\n%s", len(lines), stdout)
	}
	if !strings.HasPrefix(lines[0], "SEQ") {
		t.Errorf("first line = %q, want a header", lines[0])
	}
	if !strings.HasPrefix(lines[1], "4") || !strings.HasPrefix(lines[4], "1") {
		t.Errorf("listing is not newest first:\n%s", stdout)
	}
	if !strings.Contains(stdout, "thing/thg_3") {
		t.Errorf("the target should be rendered: %q", stdout)
	}
}

func TestAuditListFilters(t *testing.T) {
	dbPath, _ := chain(t, 6)

	code, stdout, _ := run(t, "audit", "list", "--db", dbPath, "--action", "thing.add.2")
	if code != ExitOK {
		t.Fatalf("exit = %d", code)
	}
	if strings.Count(stdout, "\n") != 2 {
		t.Errorf("want a header and one record, got:\n%s", stdout)
	}

	code, stdout, _ = run(t, "audit", "list", "--db", dbPath, "--limit", "2")
	if code != ExitOK || strings.Count(stdout, "\n") != 3 {
		t.Errorf("exit %d, --limit 2 gave:\n%s", code, stdout)
	}

	code, stdout, _ = run(t, "audit", "list", "--db", dbPath, "--actor", "nobody")
	if code != ExitOK {
		t.Errorf("exit = %d; no matches is not a failure", code)
	}
	if !strings.Contains(stdout, "no audit records match") {
		t.Errorf("stdout = %q", stdout)
	}
}

// A filter the operator got wrong is a usage error, not a general failure:
// exit 2 says "fix your command line", exit 1 says "something went wrong".
func TestAuditListRejectsABadFilterAsUsage(t *testing.T) {
	dbPath, _ := chain(t, 2)

	for _, args := range [][]string{
		{"audit", "list", "--db", dbPath, "--from", "last tuesday"},
		{"audit", "list", "--db", dbPath, "--to", "31/08/2026"},
		{"audit", "list", "--db", dbPath, "--limit", "5000"},
	} {
		code, stdout, stderr := run(t, args...)
		if code != ExitUsage {
			t.Errorf("%v: exit = %d, want 2 (stderr %q)", args, code, stderr)
		}
		if stdout != "" {
			t.Errorf("%v: errors belong on stderr, stdout had %q", args, stdout)
		}
	}
}

// The listing's records are the same objects the mirror holds. They are not the
// same bytes — the envelope is indented for reading — so this compares the
// decoded objects. Byte-identity is `audit export --format jsonl`'s job.
func TestAuditListJSONRecordsAreTheMirrorRecords(t *testing.T) {
	dbPath, mirror := chain(t, 3)

	code, stdout, stderr := run(t, "audit", "list", "--db", dbPath, "--format", "json")
	if code != ExitOK {
		t.Fatalf("exit = %d (stderr %q)", code, stderr)
	}
	var got struct {
		Count   int               `json:"count"`
		Records []json.RawMessage `json:"records"`
	}
	if err := json.Unmarshal([]byte(stdout), &got); err != nil {
		t.Fatalf("stdout is not valid JSON: %v\n%s", err, stdout)
	}
	if got.Count != 3 || len(got.Records) != 3 {
		t.Fatalf("count = %d, records = %d", got.Count, len(got.Records))
	}

	b, err := os.ReadFile(mirror)
	if err != nil {
		t.Fatal(err)
	}
	fileLines := strings.Split(strings.TrimSuffix(string(b), "\n"), "\n")
	// The listing is newest first; the file is oldest first.
	for i, raw := range got.Records {
		want := fileLines[len(fileLines)-1-i]
		var fromList, fromFile map[string]any
		if err := json.Unmarshal(raw, &fromList); err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal([]byte(want), &fromFile); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(fromList, fromFile) {
			t.Errorf("record %d differs\n  list %s\n  file %s", i, raw, want)
		}
	}
}

// docs/specs/10-cli.md §2 advertises --format text|json|yaml globally. This is
// the one verb where those are not the values, so the refusal has to name what
// it does accept rather than leaving the operator to guess.
func TestAuditExportRejectsTheGlobalFormatValues(t *testing.T) {
	dbPath, _ := chain(t, 2)

	for _, bad := range []string{"text", "json", "yaml"} {
		code, stdout, stderr := run(t, "audit", "export", "--db", dbPath, "--format", bad)
		if code != ExitUsage {
			t.Errorf("--format %s: exit = %d, want 2", bad, code)
		}
		if !strings.Contains(stderr, "jsonl") || !strings.Contains(stderr, "csv") {
			t.Errorf("--format %s: stderr should name the accepted values, got %q", bad, stderr)
		}
		if stdout != "" {
			t.Errorf("--format %s: stdout had %q", bad, stdout)
		}
	}
}

func TestAuditExportDefaultsToJSONLAndMatchesTheMirror(t *testing.T) {
	dbPath, mirror := chain(t, 5)

	code, stdout, stderr := run(t, "audit", "export", "--db", dbPath)
	if code != ExitOK {
		t.Fatalf("exit = %d (stderr %q)", code, stderr)
	}
	want, err := os.ReadFile(mirror)
	if err != nil {
		t.Fatal(err)
	}
	if stdout != string(want) {
		t.Errorf("export and mirror differ\n export %q\n mirror %q", stdout, want)
	}
	if stderr != "" {
		t.Errorf("stderr = %q, want nothing", stderr)
	}
}

func TestAuditExportCSV(t *testing.T) {
	dbPath, _ := chain(t, 3)

	code, stdout, stderr := run(t, "audit", "export", "--db", dbPath, "--format", "csv")
	if code != ExitOK {
		t.Fatalf("exit = %d (stderr %q)", code, stderr)
	}
	rows, err := csv.NewReader(strings.NewReader(stdout)).ReadAll()
	if err != nil {
		t.Fatalf("not valid CSV: %v\n%s", err, stdout)
	}
	if len(rows) != 4 {
		t.Errorf("%d rows, want a header and 3 records", len(rows))
	}
	if rows[0][0] != "seq" {
		t.Errorf("first column = %q, want seq", rows[0][0])
	}
}

func TestAuditExportResumes(t *testing.T) {
	dbPath, _ := chain(t, 6)

	code, stdout, _ := run(t, "audit", "export", "--db", dbPath, "--from-seq", "5")
	if code != ExitOK {
		t.Fatalf("exit = %d", code)
	}
	if got := strings.Count(strings.TrimSuffix(stdout, "\n"), "\n") + 1; got != 2 {
		t.Errorf("%d records, want 2:\n%s", got, stdout)
	}
}

// A comparison between a sound chain and a broken one says nothing. Printing
// "the mirror matches the database" underneath "record altered at seq 3" reads
// as a contradiction — what matched was the hash each side recorded at that
// sequence, not the record the mirror actually holds.
func TestAuditVerifySuppressesAMeaninglessComparison(t *testing.T) {
	dbPath, mirror := chain(t, 4)

	b, err := os.ReadFile(mirror)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSuffix(string(b), "\n"), "\n")
	lines[2] = strings.Replace(lines[2], `"thing.add.2"`, `"thing.add.X"`, 1)
	if err := os.WriteFile(mirror, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	code, stdout, _ := run(t, "audit", "verify", "--db", dbPath, "--mirror", mirror)
	if code != ExitFailure {
		t.Errorf("exit = %d, want 1", code)
	}
	if !strings.Contains(stdout, "seq 3") {
		t.Errorf("stdout should name the altered record: %q", stdout)
	}
	if strings.Contains(stdout, "comparison:") {
		t.Errorf("a comparison was reported against a broken chain:\n%s", stdout)
	}
}

// The message an operator reads has to be a sentence. Prefixing the sentinel's
// own text onto one that already says what is wrong is not.
func TestAuditListFilterErrorReadsAsASentence(t *testing.T) {
	dbPath, _ := chain(t, 1)

	_, _, stderr := run(t, "audit", "list", "--db", dbPath, "--from", "last tuesday")
	want := `nodary audit list: --from: "last tuesday" is neither a date (2006-01-02) nor an RFC3339 instant` + "\n"
	if stderr != want {
		t.Errorf("stderr = %q\n   want %q", stderr, want)
	}
}

// A damaged mirror is what this verb exists to report, and comparing before
// verifying made it the one input that produced no report: a bare stderr line,
// exit 1, and nothing on stdout at all under --format json.
func TestAuditVerifyReportsADamagedMirrorRatherThanAborting(t *testing.T) {
	dbPath, mirror := chain(t, 4)
	lines := strings.Split(strings.TrimSuffix(readFile(t, mirror), "\n"), "\n")
	lines[2] = lines[2][:len(lines[2])/2]
	writeFile(t, mirror, strings.Join(lines, "\n")+"\n")

	code, stdout, stderr := run(t, "audit", "verify", "--db", dbPath, "--mirror", mirror, "--format", "json")
	if code != ExitFailure {
		t.Fatalf("exit = %d, want 1 (stderr %q)", code, stderr)
	}
	var report struct {
		OK     bool               `json:"ok"`
		Chain  *struct{ OK bool } `json:"chain"`
		Mirror *struct {
			OK    bool `json:"ok"`
			Break *struct {
				Seq    int64  `json:"seq"`
				Detail string `json:"detail"`
			} `json:"break"`
		} `json:"mirror"`
	}
	if err := json.Unmarshal([]byte(stdout), &report); err != nil {
		t.Fatalf("--format json wrote nothing parseable: %q (stderr %q)", stdout, stderr)
	}
	if report.OK {
		t.Error("a damaged mirror was reported as sound")
	}
	if report.Chain == nil || !report.Chain.OK {
		t.Error("the database report was discarded, though it had already been computed")
	}
	if report.Mirror == nil || report.Mirror.Break == nil {
		t.Fatalf("the mirror's break was not named: %q", stdout)
	}
	if report.Mirror.Break.Seq != 3 || !strings.Contains(report.Mirror.Break.Detail, "line 3") {
		t.Errorf("the break does not name the damaged line: %+v", report.Mirror.Break)
	}
}

// audit.Unlimited is -1, and Filter tests for it before its range guard — so
// -1 was the one negative value that returned the whole chain, at exit 0, past
// the cap this flag's own help advertises.
func TestAuditListRefusesALimitOutsideItsAdvertisedRange(t *testing.T) {
	dbPath, _ := chain(t, 3)
	for _, limit := range []string{"-1", "0", "-2", "501"} {
		code, stdout, _ := run(t, "audit", "list", "--db", dbPath, "--limit", limit)
		if code != ExitUsage {
			t.Errorf("--limit %s: exit = %d, want 2 (stdout %q)", limit, code, stdout)
		}
	}
}

// `audit list --format json` is the same record `audit export --format jsonl`
// writes. encoding/json escapes <, > and & by default, so the two commands
// printed different bytes for one record.
func TestAuditListJSONDoesNotEscapeTheCanonicalBytes(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "nodary.db")
	db, err := store.Open(context.Background(), dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	l := audit.New(db, audit.NewDelivery(nil, audit.Warn, io.Discard))
	if _, err := l.Act(context.Background(), audit.Request{
		Actor:         audit.Actor{ID: "root", Method: "local"},
		Action:        "thing.add",
		Justification: "rollback of <prod> & staging",
	}, func(m audit.Mutation) error { return nil }); err != nil {
		t.Fatal(err)
	}
	db.Close()

	_, listed, _ := run(t, "audit", "list", "--db", dbPath, "--format", "json")
	_, exported, _ := run(t, "audit", "export", "--db", dbPath)
	const want = `rollback of <prod> & staging`
	if !strings.Contains(exported, want) {
		t.Fatalf("export did not carry the literal characters: %q", exported)
	}
	if !strings.Contains(listed, want) {
		t.Errorf("list --format json escaped the canonical bytes: %q", listed)
	}
}

// -h is a request, not a usage error: docs/specs/10-cli.md §4 puts human output
// on stdout and §5's code 2 is "bad flags, missing arguments".
func TestHelpGoesToStdoutAndSucceeds(t *testing.T) {
	for _, verb := range [][]string{
		{"audit", "list"}, {"audit", "verify"}, {"audit", "export"},
		{"components", "list"}, {"version"},
	} {
		name := strings.Join(verb, " ")
		code, stdout, stderr := run(t, append(verb, "-h")...)
		switch {
		case code != ExitOK:
			t.Errorf("%s -h: exit = %d, want 0", name, code)
		case stdout == "":
			t.Errorf("%s -h: nothing on stdout", name)
		case stderr != "":
			t.Errorf("%s -h: wrote a diagnostic too: %q", name, stderr)
		}
	}

	// A genuinely bad flag is still a usage error, on stderr.
	code, stdout, stderr := run(t, "audit", "list", "--nope")
	if code != ExitUsage || stdout != "" || stderr == "" {
		t.Errorf("bad flag: exit = %d, stdout = %q, stderr = %q", code, stdout, stderr)
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}
