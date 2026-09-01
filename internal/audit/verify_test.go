package audit

import (
	"bytes"
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
	fileRes, err := VerifyFile(path, nil)
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

	res, err := VerifyFile(path, nil)
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

	res, err := VerifyFile(path, nil)
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

	res, err := VerifyFile(merged, nil)
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
			res, err := VerifyFile(forged, nil)
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

// writeLines is the mirror rewritten in a given order.
func writeLines(t *testing.T, lines []string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "reordered.jsonl")
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func mirrorLines(t *testing.T, path string) []string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return strings.Split(strings.TrimSuffix(string(b), "\n"), "\n")
}

// Delivery happens after the commit and several processes append to one path,
// so a concurrently written mirror interleaves. Measured before this was
// handled: twelve processes writing 480 records produced an inversion in one
// run of six, and verification reported "records missing" on a file that had
// lost nothing — the worst false positive a tamper detector can have.
func TestAReorderedMirrorStillVerifies(t *testing.T) {
	_, mirror := chainOf(t, 12)
	lines := mirrorLines(t, mirror)

	for name, order := range map[string][]int{
		"one inversion":  {0, 1, 3, 2, 4, 5, 6, 7, 8, 9, 10, 11},
		"reversed":       {11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0},
		"late genesis":   {5, 3, 8, 0, 1, 2, 4, 6, 7, 9, 10, 11},
		"last one first": {11, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10},
	} {
		t.Run(name, func(t *testing.T) {
			shuffled := make([]string, 0, len(order))
			for _, i := range order {
				shuffled = append(shuffled, lines[i])
			}
			res, err := VerifyFile(writeLines(t, shuffled), nil)
			if err != nil {
				t.Fatal(err)
			}
			if !res.OK() {
				t.Fatalf("a reordered but complete mirror did not verify: %v", res.Break)
			}
			if res.Records != 12 || res.FirstSeq != 1 || res.LastSeq != 12 {
				t.Errorf("result = %+v", res)
			}
			if res.Fragment {
				t.Error("a complete chain was reported as a fragment")
			}
		})
	}
}

// Tolerating reordering must not tolerate deletion: the record simply never
// arrives, and the gap is still named.
func TestAReorderedMirrorStillDetectsADeletion(t *testing.T) {
	_, mirror := chainOf(t, 12)
	lines := mirrorLines(t, mirror)

	shuffled := []string{lines[3], lines[0], lines[2], lines[5], lines[4]}
	for i := 6; i < len(lines); i++ {
		shuffled = append(shuffled, lines[i])
	}
	// lines[1] — seq 2 — is never written.
	res, err := VerifyFile(writeLines(t, shuffled), nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.OK() {
		t.Fatal("a deletion hid behind the reordering")
	}
	if res.Break.Kind != KindGap || res.Break.Seq != 2 {
		t.Errorf("break = %v, want a gap at seq 2", res.Break)
	}
}

// Delivery is at-least-once, so the same record arriving twice is ordinary.
func TestADuplicatedRecordIsTolerated(t *testing.T) {
	_, mirror := chainOf(t, 6)
	lines := mirrorLines(t, mirror)
	doubled := append([]string{lines[0], lines[0], lines[1]}, lines[1:]...)

	res, err := VerifyFile(writeLines(t, doubled), nil)
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK() {
		t.Fatalf("a repeated record was treated as damage: %v", res.Break)
	}
	if res.Records != 6 {
		t.Errorf("records = %d, want each counted once", res.Records)
	}
}

// Two *different* records claiming one sequence is a fork, not a duplicate.
func TestTwoRecordsClaimingOneSequenceIsABreak(t *testing.T) {
	_, mirror := chainOf(t, 4)
	lines := mirrorLines(t, mirror)
	forged := strings.Replace(lines[2], `"thing.add.2"`, `"thing.add.Z"`, 1)
	if forged == lines[2] {
		t.Fatal("the fixture did not change")
	}

	res, err := VerifyFile(writeLines(t, append(append([]string{}, lines...), forged)), nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.OK() {
		t.Fatal("two records claiming one sequence verified")
	}
	if res.Break.Seq != 3 {
		t.Errorf("break = %v, want seq 3", res.Break)
	}
}

// `audit export --from-seq` is the documented way a destination that fell
// behind catches up, and a rotated sink file is what the FileSink is written to
// support. Both are fragments. A verifier that called its own recovery
// artefacts tampered would be worse than useless — measured before this was
// handled: "chain does not start at genesis", 0 records verified, exit 1.
func TestAFragmentVerifiesAsAFragment(t *testing.T) {
	db, mirror := chainOf(t, 6)

	var out bytes.Buffer
	if _, err := ExportJSONL(context.Background(), db, Filter{FromSeq: 4}, &out); err != nil {
		t.Fatal(err)
	}
	rotated := mirrorLines(t, mirror)[3:]

	for name, path := range map[string]string{
		"export --from-seq": writeLines(t, strings.Split(strings.TrimSuffix(out.String(), "\n"), "\n")),
		"rotated sink file": writeLines(t, rotated),
	} {
		t.Run(name, func(t *testing.T) {
			res, err := VerifyFile(path, nil)
			if err != nil {
				t.Fatal(err)
			}
			if !res.OK() {
				t.Fatalf("a fragment was reported as damage: %v", res.Break)
			}
			if !res.Fragment {
				t.Error("a fragment was reported as a whole chain, which claims more than it proves")
			}
			if res.Anchored {
				t.Error("nothing anchored it")
			}
			if res.Records != 3 || res.FirstSeq != 4 || res.LastSeq != 6 {
				t.Errorf("result = %+v", res)
			}
		})
	}
}

// With the database that produced it, a fragment is anchored automatically:
// the appliance can say whether the fragment joins its chain.
func TestAFragmentAnchorsToItsDatabase(t *testing.T) {
	db, mirror := chainOf(t, 6)
	frag := writeLines(t, mirrorLines(t, mirror)[3:])

	res, err := VerifyMirror(context.Background(), db, frag)
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK() || !res.Fragment || !res.Anchored {
		t.Errorf("result = %+v break=%v", res, res.Break)
	}
}

// A fragment that does not join is the thing anchoring exists to catch.
func TestAFragmentThatDoesNotJoinIsRefused(t *testing.T) {
	_, mirror := chainOf(t, 6)
	frag := writeLines(t, mirrorLines(t, mirror)[3:])

	// Someone else's chain, at the same sequence.
	other, _ := chainOf(t, 6)
	res, err := VerifyMirror(context.Background(), other, frag)
	if err != nil {
		t.Fatal(err)
	}
	if res.OK() {
		t.Fatal("a fragment from another chain was accepted")
	}
	if res.Break.Kind != KindNotAnchored || res.Break.Seq != 4 {
		t.Errorf("break = %v, want a refusal to join at seq 4", res.Break)
	}

	// And explicitly, with a hash the caller supplies.
	res, err = VerifyFile(frag, &Anchor{Seq: 3, Hash: strings.Repeat("a", 64)})
	if err != nil {
		t.Fatal(err)
	}
	if res.OK() || res.Break.Kind != KindNotAnchored {
		t.Errorf("break = %v, want KindNotAnchored", res.Break)
	}
}

func TestAnAnchoredFragmentIsAccepted(t *testing.T) {
	db, mirror := chainOf(t, 6)
	lines := mirrorLines(t, mirror)
	third, err := ParseLine([]byte(lines[2]))
	if err != nil {
		t.Fatal(err)
	}

	res, err := VerifyFile(writeLines(t, lines[3:]), &Anchor{Seq: 3, Hash: third.Hash})
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK() || !res.Fragment || !res.Anchored {
		t.Errorf("result = %+v break=%v", res, res.Break)
	}
	_ = db
}

// A whole chain is not a fragment, and a forged genesis is not one either: a
// record claiming seq 1 has to carry the genesis hash.
func TestSeqOneMustStillCarryGenesis(t *testing.T) {
	_, mirror := chainOf(t, 4)
	lines := mirrorLines(t, mirror)
	forged := strings.Replace(lines[0], GenesisPrevHash, strings.Repeat("b", 64), 1)
	if forged == lines[0] {
		t.Fatal("the fixture did not change")
	}

	res, err := VerifyFile(writeLines(t, append([]string{forged}, lines[1:]...)), nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.OK() {
		t.Fatal("a forged genesis was accepted as a fragment")
	}
	if res.Break.Kind != KindNotGenesis {
		t.Errorf("break = %v, want KindNotGenesis", res.Break)
	}
}

// A database holds the whole chain, so a partial one there means records were
// deleted — the fragment allowance is for files, not for the authority.
func TestADatabaseMayNotBeAFragment(t *testing.T) {
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
		t.Errorf("break = %v, want the database refused as incomplete", res.Break)
	}
	if res.Fragment {
		t.Error("a database was excused as a fragment")
	}
}

// Compare walks both sides in sequence order and holds neither in memory, so
// the reordering a concurrently written mirror carries must not disturb it
// either.
func TestCompareToleratesAReorderedMirror(t *testing.T) {
	db, mirror := chainOf(t, 12)
	lines := mirrorLines(t, mirror)
	shuffled := []string{lines[11], lines[0], lines[2], lines[1], lines[3], lines[6], lines[4], lines[5]}
	shuffled = append(shuffled, lines[7], lines[8], lines[10], lines[9])

	cmp, err := Compare(context.Background(), db, writeLines(t, shuffled))
	if err != nil {
		t.Fatal(err)
	}
	if cmp.Diverged != 0 || cmp.Behind != 0 || cmp.Ahead != 0 || cmp.Installs != nil {
		t.Errorf("comparison = %+v, want a clean match", cmp)
	}
}

func TestCompareCountsAndDivergence(t *testing.T) {
	t.Run("behind at the end", func(t *testing.T) {
		db, mirror := chainOf(t, 8)
		cmp := compareTo(t, db, writeLines(t, mirrorLines(t, mirror)[:5]))
		if cmp.Behind != 3 || cmp.Ahead != 0 || cmp.Diverged != 0 {
			t.Errorf("comparison = %+v, want three behind", cmp)
		}
	})

	// A hole in the middle exercises the merge itself rather than the drain
	// that runs once one side is exhausted — a different arm, and one the
	// end-of-file cases leave untouched.
	t.Run("behind in the middle", func(t *testing.T) {
		db, mirror := chainOf(t, 8)
		lines := mirrorLines(t, mirror)
		holed := append(append([]string{}, lines[:2]...), lines[3:]...) // seq 3 absent
		cmp := compareTo(t, db, writeLines(t, holed))
		if cmp.Behind != 1 || cmp.Ahead != 0 || cmp.Diverged != 0 {
			t.Errorf("comparison = %+v, want one behind", cmp)
		}
	})

	t.Run("ahead at the end", func(t *testing.T) {
		db, mirror := chainOf(t, 8)
		lines := mirrorLines(t, mirror)
		deleteSeq(t, db, "seq > 5")
		cmp := compareTo(t, db, writeLines(t, lines))
		if cmp.Ahead != 3 || cmp.Behind != 0 {
			t.Errorf("comparison = %+v, want three ahead", cmp)
		}
	})

	t.Run("ahead in the middle", func(t *testing.T) {
		db, mirror := chainOf(t, 8)
		lines := mirrorLines(t, mirror)
		deleteSeq(t, db, "seq = 4")
		cmp := compareTo(t, db, writeLines(t, lines))
		if cmp.Ahead != 1 || cmp.Behind != 0 {
			t.Errorf("comparison = %+v, want one ahead", cmp)
		}
	})

	t.Run("a repeat is not a difference", func(t *testing.T) {
		db, mirror := chainOf(t, 4)
		l := mirrorLines(t, mirror)
		doubled := []string{l[0], l[1], l[1], l[2], l[0], l[3]}
		cmp := compareTo(t, db, writeLines(t, doubled))
		if cmp.Behind != 0 || cmp.Ahead != 0 || cmp.Diverged != 0 {
			t.Errorf("comparison = %+v, want a clean match", cmp)
		}
	})
}

func compareTo(t *testing.T, db *store.DB, path string) Comparison {
	t.Helper()
	cmp, err := Compare(context.Background(), db, path)
	if err != nil {
		t.Fatal(err)
	}
	return cmp
}

func deleteSeq(t *testing.T, db *store.DB, where string) {
	t.Helper()
	if err := db.WriteTx(context.Background(), func(tx *sql.Tx) error {
		_, err := tx.Exec(`DELETE FROM audit WHERE ` + where)
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

// A mirror left over from a previous installation is an ordinary state after a
// reinstall or a restore, and saying "tampered" about it would be the same
// wording and the same exit code as the real thing.
func TestCompareNamesAnInstallMismatch(t *testing.T) {
	db, _ := chainOf(t, 4)
	_, otherMirror := chainOf(t, 4)

	cmp, err := Compare(context.Background(), db, otherMirror)
	if err != nil {
		t.Fatal(err)
	}
	if cmp.Installs == nil {
		t.Fatalf("comparison = %+v, want an install mismatch", cmp)
	}
	if cmp.Diverged != 0 || cmp.Behind != 0 || cmp.Ahead != 0 {
		t.Errorf("a mismatch should not also be reported as divergence: %+v", cmp)
	}
}

// The judgement belongs here rather than in whichever surface asked for it:
// docs/tasks/README.md requires the CLI and the HTTP API to reach the same
// answer by the same route.
func TestAssessment(t *testing.T) {
	ok := &Result{Records: 3, FirstSeq: 1, LastSeq: 3}
	broken := &Result{Break: &Problem{Seq: 2, Kind: KindAltered}}

	for name, tc := range map[string]struct {
		a          Assessment
		wantOK     bool
		wantCompar bool
	}{
		"nothing examined": {Assessment{}, true, false},
		"chain alone":      {Assessment{Chain: ok}, true, false},
		"mirror alone":     {Assessment{Mirror: ok}, true, false},
		"both sound":       {Assessment{Chain: ok, Mirror: ok}, true, true},
		"chain broken":     {Assessment{Chain: broken, Mirror: ok}, false, false},
		"mirror broken":    {Assessment{Chain: ok, Mirror: broken}, false, false},
		// Behind is the mirror's ordinary state: delivery happens after the
		// commit, so trailing the database is not a fault.
		"mirror behind": {Assessment{Chain: ok, Mirror: ok,
			Comparison: &Comparison{Behind: 4}}, true, true},
		"mirror ahead": {Assessment{Chain: ok, Mirror: ok,
			Comparison: &Comparison{Ahead: 1}}, false, true},
		"diverged": {Assessment{Chain: ok, Mirror: ok,
			Comparison: &Comparison{Diverged: 7}}, false, true},
		"another installation": {Assessment{Chain: ok, Mirror: ok,
			Comparison: &Comparison{Installs: &InstallMismatch{Database: "ins_a", File: "ins_b"}}}, false, true},
	} {
		t.Run(name, func(t *testing.T) {
			if got := tc.a.OK(); got != tc.wantOK {
				t.Errorf("OK() = %v, want %v", got, tc.wantOK)
			}
			if got := tc.a.Comparable(); got != tc.wantCompar {
				t.Errorf("Comparable() = %v, want %v", got, tc.wantCompar)
			}
		})
	}
}
