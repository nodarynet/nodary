package canonical

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The official RFC 8785 vectors from cyberphone/json-canonicalization, which is
// the suite the RFC's own reference implementations are checked against. These
// are the closest thing to an external audit of this package: if nodary's bytes
// match here, an auditor recomputing a hash from the JSONL mirror with any
// conforming implementation gets the same answer.
func TestOfficialJCSVectors(t *testing.T) {
	names, err := filepath.Glob("testdata/input/*.json")
	if err != nil || len(names) == 0 {
		t.Fatalf("no vectors found: %v", err)
	}
	for _, in := range names {
		name := filepath.Base(in)
		t.Run(name, func(t *testing.T) {
			input, err := os.ReadFile(in)
			if err != nil {
				t.Fatal(err)
			}
			want, err := os.ReadFile(filepath.Join("testdata/output", name))
			if err != nil {
				t.Fatal(err)
			}
			got, err := EncodeJSON(input)
			if err != nil {
				t.Fatalf("EncodeJSON: %v", err)
			}
			if string(got) != string(want) {
				t.Errorf("canonical form differs\n got: %s\nwant: %s", got, want)
			}
		})
	}
}

// Keys sort by UTF-16 code unit (RFC 8785 §3.2.3), which is not Go's native
// string order. U+1F602 encodes as the surrogate pair D83D DE02, so it sorts
// below U+FB33; in UTF-8 byte order it sorts above. Sorting with `<` would
// therefore disagree with every conforming implementation on this input, and
// the disagreement only appears for objects mixing the two ranges.
func TestKeyOrderIsUTF16NotByteOrder(t *testing.T) {
	const smiley, dalet = "\U0001F602", "דּ"

	if !(smiley > dalet) {
		t.Fatalf("premise wrong: expected %q to sort after %q in Go byte order", smiley, dalet)
	}

	got, err := EncodeJSON([]byte(`{"` + dalet + `":1,"` + smiley + `":2}`))
	if err != nil {
		t.Fatal(err)
	}
	want := `{"` + smiley + `":2,"` + dalet + `":1}`
	if string(got) != want {
		t.Errorf("got  %s\nwant %s", got, want)
	}
}

// ECMAScript Number::toString, which RFC 8785 §3.2.2.3 requires. Go's own
// formatting switches between decimal and exponential on different thresholds,
// so these boundaries are the ones most likely to be silently wrong.
func TestES6NumberFormatting(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"0", "0"},
		{"-0", "0"}, // ECMAScript renders negative zero as "0"
		{"1", "1"},
		{"-1", "-1"},
		{"1.0", "1"},
		{"4.50", "4.5"},
		{"1e2", "100"},
		{"2e-3", "0.002"},
		{"0.1", "0.1"},
		{"1e-6", "0.000001"}, // last value before exponential form
		{"1e-7", "1e-7"},     // first value after
		{"1e20", "100000000000000000000"},
		{"1e21", "1e+21"}, // the decimal/exponential boundary
		{"1E30", "1e+30"},
		{"5e-324", "5e-324"}, // smallest subnormal
		{"1.7976931348623157e308", "1.7976931348623157e+308"},
		{"9007199254740992", "9007199254740992"}, // 2^53 exactly
		{"333333333.33333329", "333333333.3333333"},
		{"0.000000000000000000000000001", "1e-27"},
	} {
		t.Run(tc.in, func(t *testing.T) {
			got, err := EncodeJSON([]byte(tc.in))
			if err != nil {
				t.Fatalf("EncodeJSON(%s): %v", tc.in, err)
			}
			if string(got) != tc.want {
				t.Errorf("EncodeJSON(%s) = %s, want %s", tc.in, got, tc.want)
			}
		})
	}
}

// Each of these would otherwise produce bytes that differ from another
// implementation's, or that silently lose information. A tamper-detector that
// disagrees with its verifier is worse than none.
func TestRejections(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   string
		want error
	}{
		{"integer past 2^53", `9007199254740993`, ErrIntegerTooLarge},
		{"integer past int64", `123456789012345678901234567890`, ErrIntegerTooLarge},
		{"negative past 2^53", `-9007199254740993`, ErrIntegerTooLarge},
		{"lone high surrogate", `{"k":"\ud800"}`, ErrLoneSurrogate},
		{"lone low surrogate", `{"k":"\udc00"}`, ErrLoneSurrogate},
		{"high surrogate then text", `{"k":"\ud83dx"}`, ErrLoneSurrogate},
		{"duplicate key", `{"a":1,"a":2}`, ErrDuplicateKey},
		{"duplicate key nested", `{"o":{"a":1,"a":2}}`, ErrDuplicateKey},
		{"invalid utf-8", "{\"k\":\"\xff\"}", ErrInvalidUTF8},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := EncodeJSON([]byte(tc.in))
			if err == nil {
				t.Fatalf("EncodeJSON(%s) = %s, want error %v", tc.in, got, tc.want)
			}
			if !errors.Is(err, tc.want) {
				t.Errorf("EncodeJSON(%s) error = %v, want %v", tc.in, err, tc.want)
			}
		})
	}
}

// A valid surrogate pair is not a lone surrogate, and rejecting it would break
// every record containing an emoji.
func TestValidSurrogatePairAccepted(t *testing.T) {
	got, err := EncodeJSON([]byte(`{"k":"😂"}`))
	if err != nil {
		t.Fatalf("valid surrogate pair rejected: %v", err)
	}
	if want := "{\"k\":\"\U0001F602\"}"; string(got) != want {
		t.Errorf("got %s, want %s", got, want)
	}
}

// A rejection has to say which field is at fault. "record is unencodable" sends
// an operator reading the whole record; ".detail.ratio" sends them to the line.
func TestErrorNamesThePath(t *testing.T) {
	_, err := EncodeJSON([]byte(`{"detail":{"ratio":9007199254740993}}`))
	if err == nil {
		t.Fatal("want an error")
	}
	var pe *PathError
	if !errors.As(err, &pe) {
		t.Fatalf("error %v is not a *PathError", err)
	}
	if pe.Path != ".detail.ratio" {
		t.Errorf("path = %q, want %q", pe.Path, ".detail.ratio")
	}
}

// Encode and EncodeJSON are two doors into one encoder. The plan claims they
// cannot drift; this is what holds that claim up.
func TestEncodeAgreesWithEncodeJSON(t *testing.T) {
	type inner struct {
		Ratio float64 `json:"ratio"`
		Note  *string `json:"note"`
	}
	type record struct {
		Seq      int64          `json:"seq"`
		Ts       string         `json:"ts"`
		Action   string         `json:"action"`
		Detail   inner          `json:"detail"`
		Tags     []string       `json:"tags"`
		Extra    map[string]any `json:"extra"`
		PrevHash string         `json:"prev_hash"`
	}
	note := "why"
	for _, v := range []record{
		{Seq: 1, Ts: "2026-08-30T00:00:00.000Z", Action: "model.enable",
			Detail: inner{Ratio: 0.92}, Tags: []string{"a", "b"},
			Extra:    map[string]any{"k": "v", "n": json.Number("42")},
			PrevHash: strings.Repeat("0", 64)},
		{Seq: 9007199254740991, Action: "node.approve",
			Detail: inner{Ratio: 1e-7, Note: &note},
			Extra:  map[string]any{"\U0001F602": true, "דּ": false}},
	} {
		viaGo, err := Encode(v)
		if err != nil {
			t.Fatalf("Encode: %v", err)
		}
		raw, err := json.Marshal(v)
		if err != nil {
			t.Fatalf("json.Marshal: %v", err)
		}
		viaJSON, err := EncodeJSON(raw)
		if err != nil {
			t.Fatalf("EncodeJSON: %v", err)
		}
		if string(viaGo) != string(viaJSON) {
			t.Errorf("entry points disagree\n  Encode:     %s\n  EncodeJSON: %s", viaGo, viaJSON)
		}
	}
}

// The domain is closed so that an unencodable value is a refusal rather than a
// quietly different set of bytes. time.Time is the case that matters: encoded
// field-by-field it would produce something no other implementation agrees with.
func TestClosedDomainRejections(t *testing.T) {
	type withTime struct {
		T interface{ String() string } `json:"t"`
	}
	_ = withTime{}

	for _, tc := range []struct {
		name string
		in   any
	}{
		{"float32", float32(1.5)},
		{"byte slice", []byte("hi")},
		{"channel", make(chan int)},
		{"function", func() {}},
		{"complex", complex(1, 2)},
		{"non-string map key", map[int]string{1: "a"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got, err := Encode(tc.in); err == nil {
				t.Errorf("Encode(%s) = %s, want ErrUnsupportedType", tc.name, got)
			} else if !errors.Is(err, ErrUnsupportedType) {
				t.Errorf("Encode(%s) error = %v, want ErrUnsupportedType", tc.name, err)
			}
		})
	}
}

// omitempty makes a field's presence depend on its value, so absent, null and
// empty become three different hashes for what the caller thinks is one record.
// Its semantics also differ between encoding/json v1 and v2.
func TestOmitemptyRejected(t *testing.T) {
	v := struct {
		A string `json:"a,omitempty"`
	}{}
	if got, err := Encode(v); err == nil {
		t.Errorf("Encode = %s, want a refusal of omitempty", got)
	} else if !strings.Contains(err.Error(), "omitempty") {
		t.Errorf("error = %v, want it to name omitempty", err)
	}
}

// An unset optional is null and always present, so every record has the same
// shape. This is what R1b's chain depends on.
func TestNilPointerIsNullNotAbsent(t *testing.T) {
	v := struct {
		Justification *string `json:"justification"`
	}{}
	got, err := Encode(v)
	if err != nil {
		t.Fatal(err)
	}
	if want := `{"justification":null}`; string(got) != want {
		t.Errorf("got %s, want %s", got, want)
	}
}

// Canonicalising a canonical document must be a no-op, or the form is not
// canonical.
func TestIdempotent(t *testing.T) {
	names, _ := filepath.Glob("testdata/input/*.json")
	for _, in := range names {
		input, err := os.ReadFile(in)
		if err != nil {
			t.Fatal(err)
		}
		once, err := EncodeJSON(input)
		if err != nil {
			t.Fatal(err)
		}
		twice, err := EncodeJSON(once)
		if err != nil {
			t.Fatalf("re-encoding %s: %v", filepath.Base(in), err)
		}
		if string(once) != string(twice) {
			t.Errorf("%s: not idempotent\n once: %s\ntwice: %s", filepath.Base(in), once, twice)
		}
	}
}

func TestHashHexIsLowercaseSHA256(t *testing.T) {
	// Canonical form is {} — the SHA-256 of the two bytes "{}".
	got, err := HashHex(map[string]any{})
	if err != nil {
		t.Fatal(err)
	}
	const want = "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"
	if got != want {
		t.Errorf("HashHex({}) = %s, want %s", got, want)
	}
}

// The root-of-trust parser sees whatever a third party's error body contains,
// so it must not panic and must stay idempotent on anything that parses.
func FuzzEncodeJSON(f *testing.F) {
	for _, s := range []string{
		`{}`, `[]`, `null`, `0`, `-0`, `1e21`, `1e-7`,
		`{"a":1,"b":[true,false,null]}`,
		`{"😂":"x"}`,
		`{"k":"\u001f"}`,
		`[1.5,-2.25,1e308]`,
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		once, err := EncodeJSON(data)
		if err != nil {
			return // refusing malformed or out-of-domain input is correct
		}
		twice, err := EncodeJSON(once)
		if err != nil {
			t.Fatalf("canonical output was rejected on re-encode: %q -> %q: %v", data, once, err)
		}
		if string(once) != string(twice) {
			t.Fatalf("not idempotent: %q -> %q -> %q", data, once, twice)
		}
	})
}
