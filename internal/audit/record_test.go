package audit

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"
)

// sample is the record every test in this file starts from. Every optional is
// populated, so a test that clears one is testing the cleared case rather than
// a field that was never set.
func sample() Record {
	return Record{
		V:             Version,
		Install:       "ins_9c1d0f4a7b28e5364d0a1f77b3c2e590",
		Seq:           7,
		TS:            time.Date(2026, 8, 31, 9, 14, 2, 371_000_000, time.UTC),
		Actor:         Actor{ID: "usr_01j8z", Method: "password+totp", Session: "ses_4b1"},
		Source:        Source{IP: "10.0.0.7", Version: "0.0.1-rc1"},
		Action:        "model.enable",
		Target:        &Target{Kind: "model", ID: "mdl_llama3"},
		IntentHash:    "1e5a0d0b0c9f3a2b4d6e8f0a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e",
		Justification: "enabling chat for the pilot group",
		Outcome:       OutcomeSuccess,
		Detail:        map[string]any{"gpus": []any{0, 1}, "restarted": true},
		PrevHash:      "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
		Hash:          "",
	}
}

func keysOf(t *testing.T, m map[string]any) []string {
	t.Helper()
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// The field set is the contract. Adding a field to Record without adding it
// here changes nothing that is hashed, so it would travel unprotected.
func TestMembersIsExactlyTheDocumentedFieldSet(t *testing.T) {
	want := []string{
		"action", "actor", "detail", "hash", "install", "intent_hash",
		"justification", "outcome", "prev_hash", "seq", "source", "target",
		"ts", "v",
	}
	got := keysOf(t, sample().members())
	if !reflect.DeepEqual(got, want) {
		t.Errorf("members() keys =\n  %v\nwant\n  %v", got, want)
	}
	if len(want) != 14 {
		t.Fatalf("the field set should be 14 fields, this test lists %d", len(want))
	}
}

// The preimage is members minus hash and nothing else. In particular v and
// install are inside it: they exist to identify which schema and which
// appliance a record came from, and a field an attacker can change without
// invalidating the hash identifies nothing.
func TestPreimageIsMembersMinusHashOnly(t *testing.T) {
	r := sample()
	r.Hash = "ff" + strings.Repeat("0", 62)

	b, err := r.Preimage()
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	if strings.Contains(s, `"hash"`) {
		t.Errorf("preimage contains its own hash: %s", s)
	}
	for _, field := range []string{`"v"`, `"install"`, `"prev_hash"`, `"seq"`, `"ts"`} {
		if !strings.Contains(s, field) {
			t.Errorf("preimage is missing %s: %s", field, s)
		}
	}
}

// Changing the stored hash must not change what the record hashes to, or
// verification would be self-fulfilling.
func TestComputeIgnoresTheStoredHash(t *testing.T) {
	a, err := sample().Compute()
	if err != nil {
		t.Fatal(err)
	}
	r := sample()
	r.Hash = "deadbeef"
	b, err := r.Compute()
	if err != nil {
		t.Fatal(err)
	}
	if a != b {
		t.Errorf("the stored hash changed the computed hash: %s vs %s", a, b)
	}
}

// The test that matters most. A field present in Record but absent from the
// preimage can be altered in the database without breaking verification, and
// nothing else in the suite would notice. Every field is mutated in turn.
func TestEveryFieldChangesTheHash(t *testing.T) {
	base, err := sample().Compute()
	if err != nil {
		t.Fatal(err)
	}

	mutations := map[string]func(*Record){
		"v":                 func(r *Record) { r.V = 2 },
		"install":           func(r *Record) { r.Install = "ins_0000" },
		"seq":               func(r *Record) { r.Seq = 8 },
		"ts":                func(r *Record) { r.TS = r.TS.Add(time.Millisecond) },
		"actor.id":          func(r *Record) { r.Actor.ID = "usr_other" },
		"actor.method":      func(r *Record) { r.Actor.Method = "token" },
		"actor.session":     func(r *Record) { r.Actor.Session = "ses_other" },
		"source.ip":         func(r *Record) { r.Source.IP = "10.0.0.8" },
		"source.version":    func(r *Record) { r.Source.Version = "0.0.2" },
		"action":            func(r *Record) { r.Action = "model.disable" },
		"target.kind":       func(r *Record) { r.Target = &Target{Kind: "node", ID: r.Target.ID} },
		"target.id":         func(r *Record) { r.Target = &Target{Kind: r.Target.Kind, ID: "mdl_other"} },
		"target (to null)":  func(r *Record) { r.Target = nil },
		"intent_hash":       func(r *Record) { r.IntentHash = strings.Repeat("0", 64) },
		"justification":     func(r *Record) { r.Justification = "something else entirely" },
		"outcome":           func(r *Record) { r.Outcome = OutcomeFailure },
		"detail (value)":    func(r *Record) { r.Detail = map[string]any{"gpus": []any{0, 2}, "restarted": true} },
		"detail (key)":      func(r *Record) { r.Detail = map[string]any{"gpus": []any{0, 1}, "rebooted": true} },
		"detail (to empty)": func(r *Record) { r.Detail = nil },
		"prev_hash":         func(r *Record) { r.PrevHash = strings.Repeat("1", 64) },
	}

	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			r := sample()
			mutate(&r)
			got, err := r.Compute()
			if err != nil {
				t.Fatal(err)
			}
			if got == base {
				t.Errorf("mutating %s did not change the hash: the field is outside the preimage", name)
			}
		})
	}
}

// docs/plans/R1a-storage-foundation.md froze this: an unset optional is null,
// never absent and never "". Absent, null and empty are three different hashes.
func TestUnsetOptionalsEncodeAsNull(t *testing.T) {
	r := sample()
	r.Actor = Actor{Method: "local"}
	r.Source = Source{}
	r.Target = nil
	r.IntentHash = ""
	r.Justification = ""
	r.Detail = nil

	b, err := r.Preimage()
	if err != nil {
		t.Fatal(err)
	}
	got := string(b)
	for _, want := range []string{
		`"actor":{"id":null,"method":"local","session":null}`,
		`"source":{"ip":null,"version":null}`,
		`"target":null`,
		`"intent_hash":null`,
		`"justification":null`,
		`"detail":{}`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("preimage does not contain %s\n  got %s", want, got)
		}
	}
}

// A timestamp is formatted, not marshalled, so a non-UTC clock and a
// sub-millisecond reading must not produce a different record.
func TestTimestampIsNormalised(t *testing.T) {
	utc := sample()
	base, err := utc.Compute()
	if err != nil {
		t.Fatal(err)
	}

	zone := time.FixedZone("UTC+7", 7*3600)
	elsewhere := sample()
	elsewhere.TS = utc.TS.In(zone)
	got, err := elsewhere.Compute()
	if err != nil {
		t.Fatal(err)
	}
	if got != base {
		t.Errorf("the same instant in another zone hashed differently: %s vs %s", got, base)
	}

	finer := sample()
	finer.TS = utc.TS.Add(437 * time.Microsecond)
	got, err = finer.Compute()
	if err != nil {
		t.Fatal(err)
	}
	if got != base {
		t.Errorf("sub-millisecond precision changed the hash: %s vs %s", got, base)
	}
}

func TestLineRefusesAnUnchainedRecord(t *testing.T) {
	if _, err := sample().Line(); err == nil {
		t.Error("Line produced output for a record with no hash")
	}
}

func TestValidate(t *testing.T) {
	for name, mutate := range map[string]func(*Record){
		"zero version":    func(r *Record) { r.V = 0 },
		"no install":      func(r *Record) { r.Install = "" },
		"zero seq":        func(r *Record) { r.Seq = 0 },
		"unset ts":        func(r *Record) { r.TS = time.Time{} },
		"no actor method": func(r *Record) { r.Actor.Method = "" },
		"no action":       func(r *Record) { r.Action = "" },
		"unknown outcome": func(r *Record) { r.Outcome = "maybe" },
		"short prev_hash": func(r *Record) { r.PrevHash = "abc" },
		"upper prev_hash": func(r *Record) { r.PrevHash = strings.ToUpper(r.PrevHash) },
		"half-set target": func(r *Record) { r.Target = &Target{Kind: "model"} },
	} {
		t.Run(name, func(t *testing.T) {
			r := sample()
			mutate(&r)
			if err := r.Validate(); !errors.Is(err, ErrInvalidRecord) {
				t.Errorf("Validate() = %v, want ErrInvalidRecord", err)
			}
		})
	}

	r := sample()
	r.PrevHash = GenesisPrevHash
	if err := r.Validate(); err != nil {
		t.Errorf("a genesis record was rejected: %v", err)
	}
	r.Target = nil
	if err := r.Validate(); err != nil {
		t.Errorf("a record with no target was rejected: %v", err)
	}
}

// The frozen artefact. If this fails, either the canonical encoder or the
// record shape has changed, and every hash ever written is now unreproducible.
// It is a golden file rather than a literal so the bytes are reviewable as
// bytes, and it is checked in as the thing a future version must still produce.
const goldenPath = "testdata/golden_record.json"

func TestGoldenRecord(t *testing.T) {
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

	want, err := os.ReadFile(goldenPath)
	if os.IsNotExist(err) && os.Getenv("NODARY_WRITE_GOLDEN") != "" {
		if err := os.WriteFile(goldenPath, append(line, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
		t.Fatalf("wrote %s; re-run without NODARY_WRITE_GOLDEN", goldenPath)
	}
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(line)+"\n", string(want); got != want {
		t.Errorf("the canonical record has changed.\n got %s\nwant %s", got, want)
	}
}

func TestGoldenRecordFileIsThisRecordsHash(t *testing.T) {
	// The golden file carries its own hash, so the file alone proves which
	// bytes produce it — no second fixture to keep in step.
	b, err := os.ReadFile(filepath.Clean(goldenPath))
	if err != nil {
		t.Fatal(err)
	}
	r := sample()
	hash, err := r.Compute()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"hash":"`+hash+`"`) {
		t.Errorf("golden file does not carry hash %s:\n%s", hash, b)
	}
}
