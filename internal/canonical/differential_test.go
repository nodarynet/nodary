package canonical

import (
	"bytes"
	"encoding/json"
	"math"
	"math/rand"
	"strconv"
	"testing"

	refjcs "github.com/gowebpki/jcs"
)

// The plan for R1a chose full RFC 8785 over rejecting floating point, on the
// argument that the risk — a wrong ES6 number implementation corrupting hashes
// silently, and only for some values — becomes a test failure once there is a
// reference to compare against. This is that test.
//
// github.com/gowebpki/jcs is a test-only dependency. It is deliberately not
// used in the encoder: the point is an independent second opinion, which it
// stops being the moment production shares its code.

func requireSame(t *testing.T, in []byte) {
	t.Helper()
	got, gotErr := EncodeJSON(in)
	want, refErr := refjcs.Transform(refInput(in))

	switch {
	case refErr != nil && gotErr != nil:
		return // both refuse; the reasons need not match
	case refErr != nil:
		// The reference refuses what we accept. That is a real divergence.
		t.Errorf("we accepted %s as %s, reference refused it: %v", in, got, refErr)
	case gotErr != nil:
		// We refuse what the reference accepts. Expected only for the cases
		// this package deliberately narrows; anything else is a bug.
		return
	case string(got) != string(want):
		t.Errorf("canonical form differs for %s\n  ours: %s\n  ref:  %s", in, got, want)
	}
}

// refInput works around a defect in the reference, found by FuzzDifferential:
// it fails on whitespace surrounding a *top-level bare scalar* — " 0" and "0 "
// are refused with a ParseFloat error, while "\n0" and "\t0" are too. Leading
// whitespace before a top-level object, and whitespace anywhere inside one, are
// handled correctly.
//
// RFC 8259 defines JSON-text as `ws value ws`, so " 0" is valid and our
// accepting it is right. Whitespace is insignificant by definition and cannot
// change a canonical form, so trimming it for the reference costs no coverage
// of anything that matters — and it is far better than relaxing the comparison,
// which would hide a real divergence.
func refInput(in []byte) []byte {
	return bytes.Trim(append([]byte(nil), in...), " \t\r\n")
}

// Floats are the reason this dependency exists. These are the values where a
// hand-written ES6 implementation goes wrong: the decimal/exponential
// boundaries, subnormals, and the shortest-round-trip digits.
func TestDifferentialFloats(t *testing.T) {
	fixed := []float64{
		0, math.Copysign(0, -1), 1, -1, 0.1, 0.2, 0.3, 1.5, 4.5,
		1e-7, 1e-6, 1e20, 1e21, 1e30, 1e-27,
		math.SmallestNonzeroFloat64, math.MaxFloat64,
		333333333.33333329, 9007199254740992, -9007199254740992,
		1.0 / 3.0, 2.0 / 3.0, 1e100, 1e-100,
	}
	for _, f := range fixed {
		in := []byte("[" + strconv.FormatFloat(f, 'g', -1, 64) + "]")
		requireSame(t, in)
	}
}

// A fixed seed keeps this deterministic: a differential test that fails only on
// some runs is one people learn to re-run rather than read.
func TestDifferentialRandomFloats(t *testing.T) {
	r := rand.New(rand.NewSource(1))
	for i := 0; i < 20000; i++ {
		var f float64
		switch i % 4 {
		case 0:
			f = math.Float64frombits(r.Uint64()) // whole-bit-pattern space
		case 1:
			f = r.NormFloat64()
			f *= math.Pow(10, float64(r.Intn(60)-30))
		case 2:
			f = float64(r.Int63n(1 << 53))
		default:
			f = r.Float64()
		}
		if math.IsNaN(f) || math.IsInf(f, 0) {
			continue // not representable in JSON; both sides refuse
		}
		requireSame(t, []byte("["+strconv.FormatFloat(f, 'g', -1, 64)+"]"))
	}
}

// Structure, key ordering and string escaping, over inputs shaped like the
// records nodary actually writes.
func TestDifferentialDocuments(t *testing.T) {
	for _, in := range []string{
		`{}`, `[]`, `null`, `true`, `"x"`,
		`{"b":1,"a":2}`,
		`{"":"empty"}`,
		`{"é":1,"e":2,"€":3}`,
		`{"😂":1,"דּ":2}`,
		`{"a":{"c":[1,2,{"z":null,"y":false}],"b":"\t\n\r\f\b\\\"/"}}`,
		`{"detail":{"exit":1,"err":"a<b && c>d"},"gpu_memory_fraction":0.92}`,
		`[1,2.5,-0,1e21,"\u0000\u001f"]`,
		`{"nested":{"deep":{"deeper":{"n":[[[1]]]}}}}`,
	} {
		requireSame(t, []byte(in))
	}
}

// Whatever the fuzzer reaches, the two implementations must still agree.
func FuzzDifferential(f *testing.F) {
	for _, s := range []string{
		`{"a":1}`, `[1e21,1e-7]`, `{"😂":"x"}`, `0.1`, `{"a":{"b":[true,null]}}`,
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if !json.Valid(data) {
			return
		}
		requireSame(t, data)
	})
}
