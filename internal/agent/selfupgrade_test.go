package agent

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/nodarynet/nodary/internal/api"
	"github.com/nodarynet/nodary/internal/buildinfo"
	"github.com/nodarynet/nodary/internal/minisign"
	"github.com/nodarynet/nodary/internal/release"
)

// mirror serves one release the way a control plane's dist cache does.
type mirror struct {
	binary []byte
	sig    string
	// omitSig serves the binary and 404s the signature, which is what a
	// control plane that published before R5-16 looks like.
	omitSig bool
	asked   atomic.Int32
}

func (m *mirror) server(t *testing.T, target string) *httptest.Server {
	t.Helper()
	asset := fmt.Sprintf("nodary-%s-%s-%s", target, runtime.GOOS, runtime.GOARCH)
	base := api.Prefix + "/agent/dist/"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		m.asked.Add(1)
		switch r.URL.Path {
		case base + asset:
			w.Write(m.binary)
		case base + asset + ".minisig":
			if m.omitSig {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			w.Write([]byte(m.sig))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// trustRelease installs a throwaway release key and returns a signer.
func trustRelease(t *testing.T) func([]byte) string {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var id [8]byte
	copy(id[:], []byte("release "))
	prev := release.TrustedKey
	release.TrustedKey = minisign.EncodePublicKey(minisign.PublicKey{ID: id, Key: pub})
	t.Cleanup(func() { release.TrustedKey = prev })
	return func(b []byte) string { return minisign.Sign(priv, id, b, "nodary release") }
}

// upgradeDaemon points a daemon at a mirror and an install prefix under a
// temporary directory.
func upgradeDaemon(t *testing.T, srv *httptest.Server, h *imageHost) *Daemon {
	t.Helper()
	prev := optDir
	t.Cleanup(func() { optDir = prev })
	optDir = t.TempDir()

	d := &Daemon{Config: Config{Server: srv.URL}, Host: Host{Run: h.run}, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	d.client.Store(srv.Client())
	return d
}

// R5-15's property: a node with no egress becomes the version its control plane
// targets, and the only thing that makes that safe is the signature.
func TestANodeUpgradesItselfFromTheMirror(t *testing.T) {
	sign := trustRelease(t)
	body := []byte("a newer nodary")
	m := &mirror{binary: body, sig: sign(body)}
	srv := m.server(t, "9.9.9")
	h := &imageHost{loaded: map[string]bool{}}
	d := upgradeDaemon(t, srv, h)

	d.selfUpgrade(context.Background(), "9.9.9")

	placed := filepath.Join(optDir, "9.9.9", "nodary")
	got, err := os.ReadFile(placed)
	if err != nil {
		t.Fatalf("the new binary was not placed: %v", err)
	}
	if string(got) != string(body) {
		t.Error("what was placed is not what the mirror served")
	}
	if fi, err := os.Stat(placed); err == nil && fi.Mode().Perm()&0o111 == 0 {
		t.Error("the placed binary is not executable")
	}
	// The flip is the only moment anything changes, and it points at the
	// version rather than at a path, so `current/nodary` resolves.
	link, err := os.Readlink(filepath.Join(optDir, "current"))
	if err != nil {
		t.Fatalf("current was not flipped: %v", err)
	}
	if link != "9.9.9" {
		t.Errorf("current -> %q, want 9.9.9", link)
	}
	if !h.saw("systemctl restart " + AgentUnit) {
		t.Errorf("the agent did not restart into the version it placed: %v", h.calls)
	}
	if failure, tried := d.upgrades.result("9.9.9"); !tried || failure != "" {
		t.Errorf("recorded %q, want a success", failure)
	}
}

// **The whole point of verifying on the node.** A control plane can serve
// whatever it likes; what makes that harmless is that the node checks against a
// key it did not receive from the control plane.
func TestABinaryTheMirrorTamperedWithIsNotInstalled(t *testing.T) {
	sign := trustRelease(t)
	body := []byte("a newer nodary")
	m := &mirror{binary: append(append([]byte(nil), body...), 'x'), sig: sign(body)}
	srv := m.server(t, "9.9.9")
	h := &imageHost{loaded: map[string]bool{}}
	d := upgradeDaemon(t, srv, h)

	d.selfUpgrade(context.Background(), "9.9.9")

	if _, err := os.Stat(filepath.Join(optDir, "9.9.9", "nodary")); err == nil {
		t.Error("a binary that failed verification was placed")
	}
	if _, err := os.Readlink(filepath.Join(optDir, "current")); err == nil {
		t.Error("current was flipped to a version that never verified")
	}
	if h.saw("systemctl restart " + AgentUnit) {
		t.Error("the agent restarted into a binary it could not verify")
	}
	failure, tried := d.upgrades.result("9.9.9")
	if !tried || failure == "" {
		t.Fatal("the failure was not recorded, so nothing would be reported")
	}
	if !strings.Contains(failure, "does not verify") {
		t.Errorf("the recorded reason does not say what was wrong: %q", failure)
	}
}

// 01 §9: an agent that cannot upgrade keeps running what it has. Nothing here
// is torn down before the new binary is known good.
func TestAMirrorWithNoSignatureLeavesTheNodeAlone(t *testing.T) {
	sign := trustRelease(t)
	body := []byte("a newer nodary")
	m := &mirror{binary: body, sig: sign(body), omitSig: true}
	srv := m.server(t, "9.9.9")
	h := &imageHost{loaded: map[string]bool{}}
	d := upgradeDaemon(t, srv, h)

	d.selfUpgrade(context.Background(), "9.9.9")

	if h.saw("systemctl restart " + AgentUnit) {
		t.Error("the agent restarted without verifying anything")
	}
	failure, _ := d.upgrades.result("9.9.9")
	if !strings.Contains(failure, "no signature") {
		t.Errorf("the reason does not name what was missing: %q", failure)
	}
}

// R4-21's rule, applied here: an agent that retried a permanent failure every
// poll would grind against it forever and fill a fleet's logs with one problem.
func TestAFailedUpgradeIsAttemptedOnceNotEverySixtySeconds(t *testing.T) {
	trustRelease(t)
	m := &mirror{binary: []byte("unsigned"), sig: "not a signature"}
	srv := m.server(t, "9.9.9")
	d := upgradeDaemon(t, srv, &imageHost{loaded: map[string]bool{}})

	for i := 0; i < 5; i++ {
		d.selfUpgrade(context.Background(), "9.9.9")
	}
	if n := m.asked.Load(); n > 2 {
		t.Errorf("the mirror was asked %d times for a target that cannot work", n)
	}

	// A different target is a new attempt: the fleet moved, and whatever was
	// wrong with the last one may not be wrong with this one.
	m.asked.Store(0)
	d.selfUpgrade(context.Background(), "9.9.10")
	if m.asked.Load() == 0 {
		t.Error("a new target version was not attempted")
	}
}

// Nothing to do, and no reason to ask the mirror about it.
func TestANodeAlreadyOnTheTargetDoesNothing(t *testing.T) {
	trustRelease(t)
	m := &mirror{}
	srv := m.server(t, buildinfo.Version)
	d := upgradeDaemon(t, srv, &imageHost{loaded: map[string]bool{}})

	d.selfUpgrade(context.Background(), buildinfo.Version)
	d.selfUpgrade(context.Background(), "")
	if m.asked.Load() != 0 {
		t.Errorf("the mirror was asked %d times by a node with nothing to do", m.asked.Load())
	}
}

// A development build cannot verify anything, so it must not download tens of
// megabytes to reach a conclusion it already had.
func TestADevelopmentAgentRefusesBeforeDownloading(t *testing.T) {
	m := &mirror{binary: []byte("x"), sig: "y"}
	srv := m.server(t, "9.9.9")
	d := upgradeDaemon(t, srv, &imageHost{loaded: map[string]bool{}})

	d.selfUpgrade(context.Background(), "9.9.9")
	if m.asked.Load() != 0 {
		t.Error("an agent with no release key downloaded a binary it could never verify")
	}
	failure, _ := d.upgrades.result("9.9.9")
	if !strings.Contains(failure, "placeholder release key") {
		t.Errorf("the reason does not name the build's own problem: %q", failure)
	}
}

// The flip is the only moment anything changes, so a flip that did not happen
// must not be followed by a restart: systemd would bring the *old* binary back
// up while the node reported that it had upgraded.
func TestAFlipThatFailsDoesNotRestartTheAgent(t *testing.T) {
	sign := trustRelease(t)
	body := []byte("a newer nodary")
	m := &mirror{binary: body, sig: sign(body)}
	srv := m.server(t, "9.9.9")
	h := &imageHost{loaded: map[string]bool{}}
	d := upgradeDaemon(t, srv, h)

	// A non-empty directory where the symlink goes: renaming onto it fails,
	// which is the closest a test gets to a disk that will not cooperate.
	blocked := filepath.Join(optDir, "current")
	if err := os.MkdirAll(filepath.Join(blocked, "in-the-way"), 0o755); err != nil {
		t.Fatal(err)
	}

	d.selfUpgrade(context.Background(), "9.9.9")

	if h.saw("systemctl restart " + AgentUnit) {
		t.Error("the agent restarted after a flip that did not happen; systemd would " +
			"bring the old binary back up and the node would report success")
	}
	failure, tried := d.upgrades.result("9.9.9")
	if !tried || failure == "" {
		t.Error("a failed flip was not recorded, so nothing would be reported")
	}
}
