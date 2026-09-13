package cli

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nodarynet/nodary/internal/audit"
)

// writeServerConfig places a server.toml beside this appliance's key, which is
// where openSession looks for the [audit] block.
func (a *appliance) writeServerConfig(t *testing.T, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(a.dir, "server.toml"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

// R2-41 end to end: a record committed by an ordinary verb reaches a network
// endpoint named in server.toml. The chain's off-box anchor is the thing a
// compromised control plane cannot rewrite, and until this it was a customer
// integration documented in prose.
func TestARecordReachesTheEndpointNamedInServerToml(t *testing.T) {
	var mu sync.Mutex
	var got []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := make([]byte, 1<<16)
		n, _ := r.Body.Read(body)
		mu.Lock()
		got = append(got, string(body[:n]))
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	a := newAppliance(t)
	// The harness sets this to "none" for every other test; here the file is
	// the thing under test, and the environment override would win.
	t.Setenv(audit.SinksEnv, "")
	a.writeServerConfig(t, "bind = \"0.0.0.0:8443\"\n\n[audit]\nsinks = \""+srv.URL+"\"\n")

	if code, _, stderr := a.run("user", "add", "alice", "--role", "operator",
		"--justify", "shipping this record off-box"); code != ExitOK {
		t.Fatalf("user add: %d %s", code, stderr)
	}

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		n := len(got)
		mu.Unlock()
		if n > 0 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(got) == 0 {
		t.Fatal("nothing reached the endpoint")
	}
	joined := strings.Join(got, "")
	for _, want := range []string{`"action":"user.add"`, `"seq":1`, `"hash"`, `"prev_hash"`} {
		if !strings.Contains(joined, want) {
			t.Errorf("the delivered record does not carry %s: %s", want, joined)
		}
	}
}

// A control believed to be in force and silently not is the failure
// docs/plans/pilot.md §1 exists about. A typo in the sink specification fails
// the command rather than quietly falling back to the local file.
func TestAnUnusableSinkConfigurationFailsTheCommand(t *testing.T) {
	a := newAppliance(t)
	t.Setenv(audit.SinksEnv, "")
	a.writeServerConfig(t, "[audit]\nsinks = \"http://siem.example.test/in\"\n")

	code, _, stderr := a.run("user", "add", "alice", "--role", "operator", "--justify", "x")
	if code == ExitOK {
		t.Fatalf("a plaintext remote sink was accepted: %s", stderr)
	}
	if !strings.Contains(stderr, "plaintext") {
		t.Errorf("the refusal does not say why: %s", stderr)
	}
}

// A malformed server.toml is not the same as an absent one. A GPU node has no
// server.toml at all and every verb must still work there.
func TestAnAbsentServerConfigIsNotAnError(t *testing.T) {
	a := newAppliance(t)
	t.Setenv(audit.SinksEnv, "")
	if code, _, stderr := a.run("user", "add", "alice", "--role", "operator",
		"--justify", "no server.toml anywhere"); code != ExitOK {
		t.Fatalf("exit %d without a server.toml: %s", code, stderr)
	}
}

// The environment is the escape hatch: one command run against a copy of a
// database must not post to the production SIEM while somebody looks around.
func TestTheEnvironmentOverridesTheConfiguredSink(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("a record reached the configured endpoint despite the override")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	a := newAppliance(t) // sets NODARY_AUDIT_SINKS=none
	a.writeServerConfig(t, "[audit]\nsinks = \""+srv.URL+"\"\n")

	if code, _, stderr := a.run("user", "add", "alice", "--role", "operator",
		"--justify", "overridden"); code != ExitOK {
		t.Fatalf("user add: %d %s", code, stderr)
	}
	time.Sleep(100 * time.Millisecond)
}
