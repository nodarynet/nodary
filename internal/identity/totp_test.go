package identity

import (
	"net/url"
	"strings"
	"testing"
	"time"
)

// rfcSeed is the ASCII secret every vector in RFC 4226 and RFC 6238 uses.
var rfcSeed = []byte("12345678901234567890")

// TestHOTPMatchesRFC4226 checks the truncation against RFC 4226 Appendix D.
func TestHOTPMatchesRFC4226(t *testing.T) {
	want := []string{
		"755224", "287082", "359152", "969429", "338314",
		"254676", "287922", "162583", "399871", "520489",
	}
	for counter, w := range want {
		if got := codeAt(rfcSeed, int64(counter), 6); got != w {
			t.Errorf("codeAt(counter %d) = %s, want %s", counter, got, w)
		}
	}
}

// TestTOTPMatchesRFC6238 checks the time step against RFC 6238 Appendix B.
//
// The vectors are eight digits, which is why codeAt takes a digit count: the
// specification ships its own proof and this is how it gets used.
func TestTOTPMatchesRFC6238(t *testing.T) {
	for _, tc := range []struct {
		unix int64
		want string
	}{
		{59, "94287082"},
		{1111111109, "07081804"},
		{1111111111, "14050471"},
		{1234567890, "89005924"},
		{2000000000, "69279037"},
		{20000000000, "65353130"},
	} {
		at := time.Unix(tc.unix, 0).UTC()
		if got := codeAt(rfcSeed, stepAt(at), 8); got != tc.want {
			t.Errorf("codeAt(T=%d) = %s, want %s", tc.unix, got, tc.want)
		}
	}
}

func TestStepBoundaries(t *testing.T) {
	for _, tc := range []struct {
		unix int64
		step int64
	}{{0, 0}, {29, 0}, {30, 1}, {59, 1}, {60, 2}, {1111111109, 37037036}} {
		if got := stepAt(time.Unix(tc.unix, 0)); got != tc.step {
			t.Errorf("stepAt(%d) = %d, want %d", tc.unix, got, tc.step)
		}
	}
}

func TestNewSeedIsTheRightSizeAndNotConstant(t *testing.T) {
	a, err := NewSeed()
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewSeed()
	if err != nil {
		t.Fatal(err)
	}
	if len(a) != totpSeedBytes || len(b) != totpSeedBytes {
		t.Fatalf("seed lengths %d and %d, want %d", len(a), len(b), totpSeedBytes)
	}
	if string(a) == string(b) {
		t.Fatal("two seeds are identical")
	}
	// 160 bits, base32, unpadded: what an authenticator expects to be typed.
	if got := EncodeSeed(a); len(got) != 32 || strings.Contains(got, "=") {
		t.Errorf("EncodeSeed = %q, want 32 unpadded characters", got)
	}
}

func TestURIIsWhatAnAuthenticatorReads(t *testing.T) {
	seed := []byte("12345678901234567890")
	raw := URI("nodary", "alice", seed)
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parsing %q: %v", raw, err)
	}
	if u.Scheme != "otpauth" || u.Host != "totp" {
		t.Errorf("scheme/host = %s://%s, want otpauth://totp", u.Scheme, u.Host)
	}
	if got := strings.TrimPrefix(u.Path, "/"); got != "nodary:alice" {
		t.Errorf("label = %q, want nodary:alice", got)
	}
	q := u.Query()
	for k, want := range map[string]string{
		"secret":    EncodeSeed(seed),
		"issuer":    "nodary",
		"algorithm": "SHA1",
		"digits":    "6",
		"period":    "30",
	} {
		if got := q.Get(k); got != want {
			t.Errorf("%s = %q, want %q", k, got, want)
		}
	}
	// The code the URI describes has to be the code this package generates.
	// A mismatched digits or period parameter produces an authenticator that
	// shows the right-looking number and is refused every time.
	now := time.Unix(1111111111, 0)
	if got := codeAt(seed, stepAt(now), totpDigits); len(got) != 6 {
		t.Errorf("generated code %q does not match the advertised digits", got)
	}
}

func TestURIEscapesAName(t *testing.T) {
	raw := URI("nodary", "alice smith/ops", []byte("12345678901234567890"))
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parsing %q: %v", raw, err)
	}
	if got := strings.TrimPrefix(u.Path, "/"); got != "nodary:alice smith/ops" {
		t.Errorf("label = %q, want it to round-trip", got)
	}
}

func TestVerifyAcceptsTheWindowAndRefusesOutsideIt(t *testing.T) {
	now := time.Unix(1111111111, 0)
	step := stepAt(now)
	for _, delta := range []int64{-1, 0, 1} {
		code := codeAt(rfcSeed, step+delta, totpDigits)
		got, ok := verifyCode(rfcSeed, code, now, -1)
		if !ok || got != step+delta {
			t.Errorf("step %+d: verifyCode = %d, %v; want %d, true", delta, got, ok, step+delta)
		}
	}
	for _, delta := range []int64{-2, 2, 100, -100} {
		code := codeAt(rfcSeed, step+delta, totpDigits)
		if _, ok := verifyCode(rfcSeed, code, now, -1); ok {
			t.Errorf("step %+d was accepted, and is outside the skew window", delta)
		}
	}
}

// TestACodeIsSpentOnce is the replay rule. Everything else about TOTP is
// standard; this is the part that makes a re-entry prove presence.
func TestACodeIsSpentOnce(t *testing.T) {
	now := time.Unix(1111111111, 0)
	step := stepAt(now)
	code := codeAt(rfcSeed, step, totpDigits)

	got, ok := verifyCode(rfcSeed, code, now, -1)
	if !ok || got != step {
		t.Fatalf("first use: %d, %v", got, ok)
	}
	if _, ok := verifyCode(rfcSeed, code, now, got); ok {
		t.Fatal("a code verified twice")
	}
	// The step before it is spent too: accepting it would hand back the
	// replay the floor just removed.
	if _, ok := verifyCode(rfcSeed, codeAt(rfcSeed, step-1, totpDigits), now, got); ok {
		t.Fatal("an earlier code was accepted after a later one was spent")
	}
	// The next step still works, which is what keeps the floor from locking
	// an account out.
	next := now.Add(totpStepSeconds * time.Second)
	if _, ok := verifyCode(rfcSeed, codeAt(rfcSeed, step+1, totpDigits), next, got); !ok {
		t.Fatal("the following code was refused")
	}
}

func TestVerifyRejectsMalformedCodes(t *testing.T) {
	now := time.Unix(1111111111, 0)
	for _, code := range []string{"", "12345", "1234567", "abcdef", "12345a", "12 34 5"} {
		if _, ok := verifyCode(rfcSeed, code, now, -1); ok {
			t.Errorf("%q was accepted", code)
		}
	}
}

// TestVerifyAcceptsGroupedDigits covers what an authenticator actually shows.
func TestVerifyAcceptsGroupedDigits(t *testing.T) {
	now := time.Unix(1111111111, 0)
	code := codeAt(rfcSeed, stepAt(now), totpDigits)
	for _, typed := range []string{code, code[:3] + " " + code[3:], code[:3] + "-" + code[3:]} {
		if _, ok := verifyCode(rfcSeed, typed, now, -1); !ok {
			t.Errorf("%q was refused", typed)
		}
	}
}

func TestVerifyRejectsAnotherSeedsCode(t *testing.T) {
	now := time.Unix(1111111111, 0)
	other, err := NewSeed()
	if err != nil {
		t.Fatal(err)
	}
	code := codeAt(other, stepAt(now), totpDigits)
	if _, ok := verifyCode(rfcSeed, code, now, -1); ok {
		t.Fatal("a code from a different seed verified")
	}
}

func TestSeedRoundTripsThroughItsEncoding(t *testing.T) {
	seed, err := NewSeed()
	if err != nil {
		t.Fatal(err)
	}
	back, err := DecodeSeed(EncodeSeed(seed))
	if err != nil {
		t.Fatalf("DecodeSeed: %v", err)
	}
	if string(back) != string(seed) {
		t.Fatal("the seed did not survive its encoding")
	}
	// Whitespace and case are what an operator pastes.
	if _, err := DecodeSeed("  " + strings.ToLower(EncodeSeed(seed)) + "\n"); err != nil {
		t.Errorf("a pasted seed was refused: %v", err)
	}
	for _, bad := range []string{"", "not base32!", EncodeSeed(seed)[:16]} {
		if _, err := DecodeSeed(bad); err == nil {
			t.Errorf("DecodeSeed(%q) was accepted", bad)
		}
	}
}

// TestCodeAgreesWithVerification keeps the exported generator and the
// verification path from drifting: one standing in for an authenticator is only
// useful if the other accepts it.
func TestCodeAgreesWithVerification(t *testing.T) {
	seed, err := NewSeed()
	if err != nil {
		t.Fatal(err)
	}
	at := time.Unix(1767225600, 0)
	if _, ok := verifyCode(seed, Code(seed, at), at, -1); !ok {
		t.Fatal("Code produced something verifyCode refuses")
	}
}
