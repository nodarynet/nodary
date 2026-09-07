package identity

import (
	"errors"
	"strconv"
	"strings"
	"testing"
)

func TestAPasswordRoundTrips(t *testing.T) {
	hash, err := HashPassword("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	if ok, stale := checkPassword(hash, "correct horse battery staple"); !ok || stale {
		t.Errorf("ok = %v, stale = %v", ok, stale)
	}
	if ok, _ := checkPassword(hash, "correct horse battery stapl"); ok {
		t.Error("a wrong password verified")
	}
}

// The hash is self-describing so the cost can be raised without invalidating
// anything: everything needed to verify it, and to notice it is behind, is in
// the string.
func TestTheHashCarriesItsOwnParameters(t *testing.T) {
	hash, err := HashPassword("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(hash, "$")
	if len(parts) != 4 {
		t.Fatalf("hash has %d parts: %q", len(parts), hash)
	}
	if parts[0] != "pbkdf2-sha256" {
		t.Errorf("scheme = %q", parts[0])
	}
	if n, err := strconv.Atoi(parts[1]); err != nil || n != pbkdf2Iterations {
		t.Errorf("iterations = %q", parts[1])
	}
	// The plaintext must not be recoverable from it, which is the whole point.
	if strings.Contains(hash, "horse") {
		t.Error("the hash contains the password")
	}
}

// R2-42: a hash produced under older parameters is replaced on the next
// successful verification.
func TestAnOldHashIsReportedStaleAndStillVerifies(t *testing.T) {
	old, err := encodeHash("correct horse battery staple", make([]byte, pbkdf2SaltBytes), 1000)
	if err != nil {
		t.Fatal(err)
	}
	ok, stale := checkPassword(old, "correct horse battery staple")
	if !ok {
		t.Fatal("a hash under old parameters stopped verifying")
	}
	if !stale {
		t.Error("a hash at 1000 iterations was not reported stale")
	}
}

// The salt is at least 128 bits because Go's FIPS module refuses shorter. That
// makes it a correctness requirement, not a preference.
func TestTheSaltIsAtLeastOneHundredAndTwentyEightBits(t *testing.T) {
	if pbkdf2SaltBytes*8 < 128 {
		t.Fatalf("salt is %d bits; Go's FIPS module refuses anything under 128", pbkdf2SaltBytes*8)
	}
	// And a hash carrying a shorter salt is treated as stale, so an install
	// that predates this floor upgrades itself rather than staying below it.
	short, err := encodeHash("correct horse battery staple", make([]byte, 8), pbkdf2Iterations)
	if err != nil {
		t.Fatal(err)
	}
	if ok, stale := checkPassword(short, "correct horse battery staple"); !ok || !stale {
		t.Errorf("a short-salted hash: ok = %v, stale = %v", ok, stale)
	}
}

func TestAShortPasswordIsRefused(t *testing.T) {
	_, err := HashPassword("short")
	if !errors.Is(err, ErrWeakPassword) {
		t.Errorf("err = %v, want ErrWeakPassword", err)
	}
}

// Malformed stored hashes must be refused rather than panicking: the column is
// in a database an administrator can write.
func TestAMalformedHashIsRefused(t *testing.T) {
	for _, stored := range []string{
		"", "nonsense", "pbkdf2-sha256$", "pbkdf2-sha256$x$y$z",
		"pbkdf2-sha256$600000$!!!$!!!", "argon2id$1$2$3",
		"pbkdf2-sha256$0$AAAA$AAAA", "pbkdf2-sha256$-1$AAAA$AAAA",
	} {
		if ok, _ := checkPassword(stored, "correct horse battery staple"); ok {
			t.Errorf("%q verified", stored)
		}
	}
}
