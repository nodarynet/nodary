package audit

import (
	"context"
	"database/sql"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nodarynet/nodary/internal/store"
)

// chainOf writes n records and returns the database and the file they were
// mirrored to, so a test can tamper with either.
func chainOf(t *testing.T, n int) (*store.DB, string) {
	t.Helper()
	db := openDB(t)
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l := New(db, NewDelivery([]Sink{NewFileSink(path)}, Warn, io.Discard), WithClock(fixedClock))

	for i := range n {
		req := request(fmt.Sprintf("thing.add.%d", i))
		// Every optional is populated, so a test that tampers with one is
		// tampering with a field that was actually set.
		req.Target = &Target{Kind: "thing", ID: fmt.Sprintf("thg_%d", i)}
		req.Justification = "because"
		req.IntentHash = strings.Repeat("b", 64)
		req.Actor.Session = "ses_1"
		req.Source.IP = "10.0.0.7"
		_, err := l.Act(context.Background(), req, func(m Mutation) error {
			m.Detail("i", i)
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	return db, path
}

func TestVerifyAcceptsAWholeChain(t *testing.T) {
	db, path := chainOf(t, 12)

	res, err := VerifyDB(context.Background(), db)
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK() {
		t.Fatalf("a chain this package wrote did not verify: %v", res.Break)
	}
	if res.Records != 12 || res.FirstSeq != 1 || res.LastSeq != 12 {
		t.Errorf("result = %+v", res)
	}
	if len(res.Warnings) != 0 {
		t.Errorf("warnings = %v", res.Warnings)
	}

	// The same records, read from the file alone.
	fileRes, err := VerifyFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !fileRes.OK() || fileRes.Records != 12 {
		t.Errorf("the mirror did not verify: %+v", fileRes)
	}
}

// R1-09: mutating record k in a chain of N makes verify name k, not "chain
// invalid". Every field is tampered with in turn, because a field outside the
// preimage would leave verification silent.
func TestVerifyNamesTheAlteredRecord(t *testing.T) {
	for column, value := range map[string]any{
		"ts":             "2020-01-01T00:00:00.000Z",
		"actor_id":       "someone_else",
		"actor_method":   "token",
		"actor_session":  "ses_forged",
		"source_ip":      "10.9.9.9",
		"source_version": "9.9.9",
		"action":         "thing.remove",
		"target_kind":    "node",
		"target_id":      "nod_other",
		"intent_hash":    strings.Repeat("f", 64),
		"justification":  "backdated",
		"outcome":        "failure",
		"detail_json":    `{"i":999}`,
		"v":              2,
		"install":        "ins_elsewhere",
	} {
		t.Run(column, func(t *testing.T) {
			db, _ := chainOf(t, 9)
			const victim = 5

			if err := db.WriteTx(context.Background(), func(tx *sql.Tx) error {
				_, err := tx.Exec(
					fmt.Sprintf(`UPDATE audit SET %s = ? WHERE seq = ?`, column), value, victim)
				return err
			}); err != nil {
				t.Skipf("the schema refused the tampering, which is also a defence: %v", err)
			}

			res, err := VerifyDB(context.Background(), db)
			if err != nil {
				t.Fatal(err)
			}
			if res.OK() {
				t.Fatalf("altering %s went undetected", column)
			}
			if res.Break.Seq != victim {
				t.Errorf("break named seq %d, want %d (%v)", res.Break.Seq, victim, res.Break)
			}
		})
	}
}

// Rewriting a record *and* its hash moves the break to the next record, which
// is the strongest thing a chain gives you: fixing one record is not enough.
func TestVerifyDetectsAConsistentlyRewrittenRecord(t *testing.T) {
	db, _ := chainOf(t, 9)
	const victim = 5

	row := db.Read().QueryRow(`SELECT `+columns+` FROM audit WHERE seq = ?`, victim)
	r, err := scanRecord(row)
	if err != nil {
		t.Fatal(err)
	}
	r.Justification = "authorised, honestly"
	rehashed, err := r.Compute()
	if err != nil {
		t.Fatal(err)
	}
	if err := db.WriteTx(context.Background(), func(tx *sql.Tx) error {
		_, err := tx.Exec(`UPDATE audit SET justification = ?, hash = ? WHERE seq = ?`,
			r.Justification, rehashed, victim)
		return err
	}); err != nil {
		t.Fatal(err)
	}

	res, err := VerifyDB(context.Background(), db)
	if err != nil {
		t.Fatal(err)
	}
	if res.OK() {
		t.Fatal("a rewritten record and hash went undetected")
	}
	if res.Break.Kind != KindBroken || res.Break.Seq != victim+1 {
		t.Errorf("break = %v, want a broken chain at seq %d", res.Break, victim+1)
	}
}

func TestVerifyNamesADeletedRecord(t *testing.T) {
	db, _ := chainOf(t, 9)
	if err := db.WriteTx(context.Background(), func(tx *sql.Tx) error {
		_, err := tx.Exec(`DELETE FROM audit WHERE seq = 4`)
		return err
	}); err != nil {
		t.Fatal(err)
	}

	res, err := VerifyDB(context.Background(), db)
	if err != nil {
		t.Fatal(err)
	}
	if res.OK() {
		t.Fatal("a deleted record went undetected")
	}
	if res.Break.Kind != KindGap || res.Break.Seq != 4 {
		t.Errorf("break = %v, want a gap at seq 4", res.Break)
	}
}

func TestVerifyRequiresAGenesisStart(t *testing.T) {
	db, _ := chainOf(t, 5)
	if err := db.WriteTx(context.Background(), func(tx *sql.Tx) error {
		_, err := tx.Exec(`DELETE FROM audit WHERE seq = 1`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	res, err := VerifyDB(context.Background(), db)
	if err != nil {
		t.Fatal(err)
	}
	if res.OK() || res.Break.Kind != KindNotGenesis {
		t.Errorf("break = %v, want a genesis refusal", res.Break)
	}
}

// A clock that moved backwards is a warning, not a break: the cause is a clock.
func TestVerifyWarnsAboutABackwardClock(t *testing.T) {
	db := openDB(t)
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	at := time.Date(2026, 8, 31, 9, 0, 0, 0, time.UTC)
	l := New(db, NewDelivery(nil, Warn, io.Discard), WithClock(func() time.Time { return at }))
	_ = path

	for _, offset := range []time.Duration{0, time.Second, -time.Minute, time.Second} {
		at = at.Add(offset)
		if _, err := l.Act(context.Background(), request("thing.add"), func(m Mutation) error {
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}

	res, err := VerifyDB(context.Background(), db)
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK() {
		t.Fatalf("a backward clock broke the chain: %v", res.Break)
	}
	if len(res.Warnings) != 1 || res.Warnings[0].Kind != KindClockWentBack {
		t.Errorf("warnings = %v, want one backward-clock warning", res.Warnings)
	}
}

// The file must verify with no database anywhere near it: that is what makes a
// copy retrieved from a SIEM months later evidence rather than a backup.
func TestMirrorVerifiesWithoutItsDatabase(t *testing.T) {
	db, path := chainOf(t, 6)
	dbPath := db.Path()
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	for _, suffix := range []string{"", "-wal", "-shm"} {
		os.Remove(dbPath + suffix)
	}

	res, err := VerifyFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK() || res.Records != 6 {
		t.Errorf("result = %+v, break = %v", res, res.Break)
	}
}

func TestMirrorTamperingIsNamed(t *testing.T) {
	_, path := chainOf(t, 6)
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSuffix(string(b), "\n"), "\n")
	lines[3] = strings.Replace(lines[3], `"thing.add.3"`, `"thing.add.X"`, 1)
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	res, err := VerifyFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if res.OK() {
		t.Fatal("an edited mirror line went undetected")
	}
	if res.Break.Seq != 4 {
		t.Errorf("break = %v, want seq 4", res.Break)
	}
}

// A file holding two appliances' records is an aggregate, not a chain. Saying
// so beats reporting a chain break the operator cannot act on.
func TestMirrorFromTwoInstallationsIsNamedAsSuch(t *testing.T) {
	_, a := chainOf(t, 3)
	_, b := chainOf(t, 3)

	first, err := os.ReadFile(a)
	if err != nil {
		t.Fatal(err)
	}
	second, err := os.ReadFile(b)
	if err != nil {
		t.Fatal(err)
	}
	merged := filepath.Join(t.TempDir(), "merged.jsonl")
	if err := os.WriteFile(merged, append(first, second...), 0o600); err != nil {
		t.Fatal(err)
	}

	res, err := VerifyFile(merged)
	if err != nil {
		t.Fatal(err)
	}
	if res.OK() || res.Break.Kind != KindMixedInstalls {
		t.Errorf("break = %v, want a mixed-installation refusal", res.Break)
	}
}

// ParseLine is self-checking: it re-encodes what it read and compares. A field
// it forgot shows up here rather than travelling unverified.
func TestParseLineRoundTripsEveryField(t *testing.T) {
	r := sample()
	hash, err := r.Compute()
	if err != nil {
		t.Fatal(err)
	}
	r.Hash = hash
	line, err := r.Line()
	if err != nil {
		t.Fatal(err)
	}

	got, err := ParseLine(line)
	if err != nil {
		t.Fatalf("ParseLine: %v", err)
	}
	back, err := got.Line()
	if err != nil {
		t.Fatal(err)
	}
	if string(back) != string(line) {
		t.Errorf("round trip changed the record:\n got %s\nwant %s", back, line)
	}
}

// The self-check is what lets the field names appear in ParseLine as well as in
// members without the two being able to drift: a field this parser does not
// read makes the record fail to round-trip rather than travel unverified.
func TestParseLineRefusesAFieldItDoesNotRead(t *testing.T) {
	r := sample()
	hash, err := r.Compute()
	if err != nil {
		t.Fatal(err)
	}
	r.Hash = hash
	line, err := r.Line()
	if err != nil {
		t.Fatal(err)
	}
	// Everything a current record has, plus one field from a hypothetical
	// later version. Nothing else about the line is wrong.
	withExtra := append([]byte(`{"node_seq":4,`), line[1:]...)

	if _, err := ParseLine(withExtra); err == nil {
		t.Error("a line carrying a field this version does not read was accepted")
	}
}

func TestParseLineRejections(t *testing.T) {
	for name, line := range map[string]string{
		"not an object":   `[1,2,3]`,
		"missing field":   `{"v":1,"seq":1}`,
		"null required":   `{"v":1,"install":null,"seq":1,"ts":"2026-08-31T09:14:02.371Z"}`,
		"an extra field":  `{"extra":1}`,
		"seq as a string": `{"v":1,"install":"i","seq":"1","ts":"2026-08-31T09:14:02.371Z"}`,
		"unparseable ts":  `{"v":1,"install":"i","seq":1,"ts":"yesterday"}`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseLine([]byte(line)); err == nil {
				t.Errorf("ParseLine(%s) was accepted", line)
			}
		})
	}
}

// Delivery happens after the commit, so a file behind the database is ordinary
// and must not be reported as damage.
// A mirror holding records the database does not means the two are not a pair —
// a file from another appliance, or a database that was restored from an older
// backup. Unlike being behind, that is not ordinary.
func TestCompareReportsAFileThatIsAhead(t *testing.T) {
	db, path := chainOf(t, 4)
	if err := db.WriteTx(context.Background(), func(tx *sql.Tx) error {
		_, err := tx.Exec(`DELETE FROM audit WHERE seq > 2`)
		return err
	}); err != nil {
		t.Fatal(err)
	}

	cmp, err := Compare(context.Background(), db, path)
	if err != nil {
		t.Fatal(err)
	}
	if cmp.Ahead != 2 {
		t.Errorf("comparison = %+v, want two ahead", cmp)
	}
}

func TestCompareReportsAFileThatIsMerelyBehind(t *testing.T) {
	db, path := chainOf(t, 6)

	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSuffix(string(b), "\n"), "\n")
	if err := os.WriteFile(path, []byte(strings.Join(lines[:4], "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	cmp, err := Compare(context.Background(), db, path)
	if err != nil {
		t.Fatal(err)
	}
	if cmp.Behind != 2 || cmp.Ahead != 0 || cmp.Diverged != 0 {
		t.Errorf("comparison = %+v, want two behind and nothing else", cmp)
	}
}

func TestCompareNamesTheFirstDivergence(t *testing.T) {
	db, path := chainOf(t, 6)
	// Distinct values: UNIQUE(hash) refuses two rows carrying the same one,
	// which is the schema doing its job and would leave this test vacuous.
	if err := db.WriteTx(context.Background(), func(tx *sql.Tx) error {
		for seq, hash := range map[int]string{3: strings.Repeat("c", 64), 5: strings.Repeat("d", 64)} {
			if _, err := tx.Exec(`UPDATE audit SET hash = ? WHERE seq = ?`, hash, seq); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("the tampering this test needs was refused: %v", err)
	}

	cmp, err := Compare(context.Background(), db, path)
	if err != nil {
		t.Fatal(err)
	}
	if cmp.Diverged != 3 {
		t.Errorf("diverged at %d, want 3", cmp.Diverged)
	}
}

// Deleting a prefix of the chain was caught as KindNotGenesis, so the cheapest
// move available to anyone holding the file — delete all of it — was the one
// move the verifier could not name. The installation row is minted by the first
// record's own transaction, so its presence proves records existed.
func TestVerifyNamesAWhollyDeletedChain(t *testing.T) {
	db, _ := chainOf(t, 5)
	ctx := context.Background()

	if err := db.WriteTx(ctx, func(tx *sql.Tx) error {
		_, err := tx.Exec(`DELETE FROM audit`)
		return err
	}); err != nil {
		t.Fatal(err)
	}

	res, err := VerifyDB(ctx, db)
	if err != nil {
		t.Fatal(err)
	}
	if res.OK() {
		t.Fatal("an emptied chain verified as sound")
	}
	if !strings.Contains(res.Break.Detail, "every record has been deleted") {
		t.Errorf("break = %v", res.Break)
	}
}

// A database that genuinely never held a record has no installation row either,
// and must still verify.
func TestVerifyAcceptsAChainThatNeverHeldARecord(t *testing.T) {
	res, err := VerifyDB(context.Background(), openDB(t))
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK() || res.Records != 0 {
		t.Errorf("a fresh database did not verify: %+v", res.Break)
	}
}

// A record the table's CHECK constraints could never have held must not verify
// in the mirror either. The round-trip check proves the line was read
// faithfully, not that what it says is well formed.
func TestMirrorRecordsAreHeldToTheSameShapeAsRows(t *testing.T) {
	_, path := chainOf(t, 1)
	sound, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct{ name, from, to string }{
		{"outcome", `"outcome":"success"`, `"outcome":"redacted"`},
		{"version", `"v":1`, `"v":0`},
		{"actor method", `"method":"local"`, `"method":null`},
		{"half-set target", `"id":"thg_0","kind":"thing"`, `"id":null,"kind":"thing"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			line := strings.Replace(string(sound), tc.from, tc.to, 1)
			if line == string(sound) {
				t.Fatalf("the fixture does not contain %q", tc.from)
			}
			forged := filepath.Join(t.TempDir(), "audit.jsonl")
			if err := os.WriteFile(forged, []byte(line), 0o600); err != nil {
				t.Fatal(err)
			}
			res, err := VerifyFile(forged)
			if err != nil {
				t.Fatal(err)
			}
			if res.OK() {
				t.Errorf("a record the table would refuse verified in the mirror")
			}
		})
	}
}

// A mirror from another installation is not a mirror of this database, and
// matching by sequence alone reported that as tampering — same wording, same
// exit code — for an ordinary reinstall or restore.
func TestCompareNamesADifferentInstallationRatherThanDivergence(t *testing.T) {
	_, theirs := chainOf(t, 3)
	ours, _ := chainOf(t, 3)

	cmp, err := Compare(context.Background(), ours, theirs)
	if err != nil {
		t.Fatal(err)
	}
	if cmp.Installs == nil {
		t.Fatalf("a foreign mirror was compared as if it were a pair: %+v", cmp)
	}
	if cmp.Diverged != 0 || cmp.Ahead != 0 || cmp.Behind != 0 {
		t.Errorf("counts were reported for chains that are not a pair: %+v", cmp)
	}
}
