package agent

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nodarynet/nodary/internal/api"
)

// The pin is the whole of a node's trust decision, so both directions matter:
// the right certificate has to work, and the wrong one has to fail as a pin
// failure rather than as a generic transport error an operator would retry.
func TestThePinAcceptsOneCertificateAndRefusesEveryOther(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	right := Fingerprint(srv.Certificate().Raw)

	// One hex digit different. A second httptest server would not do: they all
	// serve the same built-in certificate, so its fingerprint would be this one.
	wrong := right[:len(right)-1] + map[bool]string{true: "0", false: "1"}[strings.HasSuffix(right, "1")]

	client, err := Client(right, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := client.Get(srv.URL)
	if err != nil {
		t.Fatalf("the pinned certificate was refused: %v", err)
	}
	resp.Body.Close()

	client, err = Client(wrong, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Get(srv.URL); err == nil {
		t.Fatal("a server whose certificate does not match the pin was accepted")
	} else if !errors.Is(err, ErrPin) {
		t.Errorf("error = %v, want ErrPin: a mismatched pin must not read as a network problem", err)
	}
}

func TestAFingerprintMustBeAFingerprint(t *testing.T) {
	for _, bad := range []string{
		"", "sha256:", "deadbeef",
		// A base64 pin, which is what curl --pinnedpubkey takes and is not this.
		"sha256//abcdef",
		// Truncated: 63 hex characters.
		"sha256:" + strings.Repeat("a", 63),
	} {
		if _, err := PinnedTLS(bad); !errors.Is(err, ErrBadConfig) {
			t.Errorf("PinnedTLS(%q): error = %v, want a refusal", bad, err)
		}
	}
	// Case and surrounding whitespace are an operator pasting from a terminal.
	if _, err := PinnedTLS("  SHA256:" + strings.Repeat("A", 64) + "\n"); err != nil {
		t.Errorf("a pasted fingerprint was refused: %v", err)
	}
}

func TestAgentConfigRoundTripsAndRefusesWhatItShould(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "agent.toml")
	want := Config{
		Server: "https://nodary.example.internal:8443", Name: "gpu-01",
		CAFingerprint: "sha256:" + strings.Repeat("a", 64),
		Certificate:   "/etc/nodary/pki/node.crt", Key: "/etc/nodary/pki/node.key",
		ModelsDir: "/var/lib/nodary/models",
	}
	if err := os.WriteFile(path, RenderConfig(want), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if got != want {
		t.Errorf("round trip = %+v, want %+v", got, want)
	}

	for _, tc := range []struct{ what, body string }{
		{"an unknown key", "server = \"https://x:8443\"\nnaem = \"gpu-01\"\n"},
		{"a plaintext server", "server = \"http://x:8443\"\nname = \"a\"\nca_fingerprint = \"sha256:" +
			strings.Repeat("a", 64) + "\"\ncertificate = \"c\"\nkey = \"k\"\n"},
		{"no fingerprint", "server = \"https://x:8443\"\nname = \"a\"\ncertificate = \"c\"\nkey = \"k\"\n"},
	} {
		if err := os.WriteFile(path, []byte(tc.body), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadConfig(path); !errors.Is(err, ErrBadConfig) {
			t.Errorf("%s: error = %v, want a refusal", tc.what, err)
		}
	}
}

// R4-11 on the agent's side: it compares itself against the range the control
// plane advertises, not against the single number that plane speaks.
//
// The difference is the whole of why §4 asks for a range. A control plane
// upgraded to protocol 2 that still accepts 1 is every control plane
// mid-rollout; an agent comparing against `doc.Protocol` would stop reconciling
// on all of them, which turns a routine upgrade into a fleet-wide outage of
// exactly the kind this check exists to avoid.
func TestAnAgentComparesItselfAgainstTheAdvertisedRange(t *testing.T) {
	for _, c := range []struct {
		what         string
		doc          api.Desired
		wantIncompat bool
	}{
		{"inside a wider range",
			api.Desired{Protocol: api.Protocol + 1, ProtocolMin: api.Protocol, ProtocolMax: api.Protocol + 1}, false},
		{"exactly at the floor",
			api.Desired{Protocol: api.Protocol, ProtocolMin: api.Protocol, ProtocolMax: api.Protocol}, false},
		{"below the range",
			api.Desired{Protocol: api.Protocol + 3, ProtocolMin: api.Protocol + 2, ProtocolMax: api.Protocol + 3}, true},
		// A control plane old enough to advertise no range is compared the only
		// way what it said permits.
		{"no range, same number", api.Desired{Protocol: api.Protocol}, false},
		{"no range, different number", api.Desired{Protocol: api.Protocol + 1}, true},
		{"nothing said at all", api.Desired{}, false},
	} {
		err := compatible(c.doc)
		if c.wantIncompat && err == nil {
			t.Errorf("%s: reconciled against a control plane it cannot talk to", c.what)
		}
		if !c.wantIncompat && err != nil {
			t.Errorf("%s: %v", c.what, err)
		}
	}
}

// The refusal has to say what to do. An agent that stops reconciling and says
// only "protocol mismatch" leaves an operator with a node that is up, an agent
// that is running, and nothing happening.
func TestTheProtocolRefusalNamesTheFixAndWhatKeepsRunning(t *testing.T) {
	err := compatible(api.Desired{
		Protocol: api.Protocol + 3, ProtocolMin: api.Protocol + 2, ProtocolMax: api.Protocol + 3})
	if err == nil {
		t.Fatal("expected a refusal")
	}
	for _, want := range []string{"nodary upgrade", "stays running"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not say %q: %v", want, err)
		}
	}
}
