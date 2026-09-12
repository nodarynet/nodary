package agent

import (
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// docs/specs/02-enrollment.md §3: two thirds of the way through, computed from
// the certificate rather than from a constant — so a control plane that starts
// issuing a different lifetime moves its agents' schedules with it.
func TestRenewalIsDueTwoThirdsThroughTheCertificatesLife(t *testing.T) {
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name string
		life time.Duration
		want time.Duration // after start
	}{
		{"the ninety-day default", 90 * 24 * time.Hour, 60 * 24 * time.Hour},
		{"a shorter lifetime moves with it", 30 * 24 * time.Hour, 20 * 24 * time.Hour},
		{"an hour, for a test fixture", time.Hour, 40 * time.Minute},
	} {
		got := renewalAt(&x509.Certificate{NotBefore: start, NotAfter: start.Add(tc.life)})
		if want := start.Add(tc.want); !got.Equal(want) {
			t.Errorf("%s: renewal at %v, want %v", tc.name, got, want)
		}
	}
}

// The margin is the point: renewal starts a third of a lifetime before expiry,
// so a control plane that is unreachable for a week costs nothing.
func TestRenewalLeavesAThirdOfTheLifetimeToRetryIn(t *testing.T) {
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	end := start.Add(90 * 24 * time.Hour)
	margin := end.Sub(renewalAt(&x509.Certificate{NotBefore: start, NotAfter: end}))
	if margin < 29*24*time.Hour {
		t.Errorf("only %v between the first attempt and expiry", margin)
	}
	// And at that cadence there are hundreds of attempts in the margin, not a
	// handful, without retrying on every poll.
	if attempts := margin / renewRetry; attempts < 100 {
		t.Errorf("only %d retries fit in the margin", attempts)
	}
}

func TestReplacePairLeavesNoPartialFileAndKeepsTheKeyPrivate(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := filepath.Join(dir, "node.crt"), filepath.Join(dir, "node.key")
	if err := os.WriteFile(certPath, []byte("old cert"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, []byte("old key"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := replacePair(certPath, keyPath, []byte("new cert"), []byte("new key")); err != nil {
		t.Fatal(err)
	}
	for path, want := range map[string]string{certPath: "new cert", keyPath: "new key"} {
		got, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != want {
			t.Errorf("%s holds %q, want %q", path, got, want)
		}
	}

	// A key readable by anything but the agent is the one mode that matters.
	info, err := os.Stat(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Errorf("the new key is mode %o, want 600", mode)
	}

	// Nothing is left behind. The temporary files are written in the same
	// directory so the rename is on one filesystem, which means a crash would
	// otherwise litter it.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		var names []string
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Errorf("temporary files were left behind: %v", names)
	}
}
