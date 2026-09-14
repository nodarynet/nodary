package agent

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"

	"github.com/nodarynet/nodary/internal/api"
	"github.com/nodarynet/nodary/internal/buildinfo"
	"github.com/nodarynet/nodary/internal/paths"
	"github.com/nodarynet/nodary/internal/release"
)

// AgentUnit is the service this agent runs as, and restarts to become the
// version it just placed.
const AgentUnit = "nodary-agent.service"

// optDir is the install prefix. A var rather than paths.OptDir directly so a
// test can place a binary somewhere it is allowed to write — the same seam
// internal/cli uses for paths.ConfigDir. paths.OptDir stays a constant, because
// the layout is not configurable on a real host.
var optDir = paths.OptDir

// upgrader tracks what this process has already tried, so a target that cannot
// be reached is attempted once rather than every sixty seconds.
//
// The same shape Host.Asserted uses and for R4-21's reason: an agent that
// retried a permanent failure on a poll loop would grind against it forever and
// fill a fleet's logs with one problem. A target that changes is a new attempt;
// so is a restart of this process.
type upgrader struct {
	mu     sync.Mutex
	tried  string
	failed string
	target string
}

func (u *upgrader) result(target string) (string, bool) {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.failed, u.tried == target
}

func (u *upgrader) record(target, failure string) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.tried, u.failed = target, failure
}

// selfUpgrade brings this node to the version its control plane targets.
//
// **A node has no egress** (docs/specs/03-agent.md §1), so the binary comes
// from the mirror it already fetches components from, and the only thing that
// makes that safe is the signature: it is verified against the release key
// compiled into *this* binary, which arrived through a channel the control
// plane does not control (R5-16).
//
// **Nothing is torn down on failure.** Every step happens beside the running
// install — a new versioned directory, then one symlink flip — so an upgrade
// that cannot complete leaves a node serving the version it already had. That
// is docs/specs/01-install.md §9's requirement and the reason the order is
// fetch, verify, place, flip, restart rather than anything shorter.
func (d *Daemon) selfUpgrade(ctx context.Context, target string) {
	if target == "" || target == buildinfo.Version {
		return
	}
	if _, done := d.upgrades.result(target); done {
		return
	}
	if err := d.upgradeTo(ctx, target); err != nil {
		d.upgrades.record(target, err.Error())
		// Reported, not fatal. The deployments this node is running are
		// unaffected by a version it could not fetch.
		d.Log.Error("agent", "detail", "self-upgrade to "+target+": "+err.Error())
		return
	}
	d.upgrades.record(target, "")
}

func (d *Daemon) upgradeTo(ctx context.Context, target string) error {
	// Refused before downloading tens of megabytes it could never use, and
	// with the reason an operator can act on.
	if !release.Trusted() {
		return fmt.Errorf("this agent carries a placeholder release key, so it cannot verify "+
			"any binary it is handed; reinstall it from a release build (%w)", release.ErrUnverified)
	}
	asset := fmt.Sprintf("nodary-%s-%s-%s", target, runtime.GOOS, runtime.GOARCH)

	binary, err := d.fetchDist(ctx, asset)
	if err != nil {
		return err
	}
	sig, err := d.fetchDist(ctx, asset+".minisig")
	if err != nil {
		return fmt.Errorf("the mirror has the binary but no signature for it: %w", err)
	}
	if err := release.Verify(binary, string(sig)); err != nil {
		return err
	}

	// Beside the running install, never over it. paths.BinaryFor names the
	// versioned path install.sh and `nodary upgrade` both use, so an agent that
	// placed one is indistinguishable from an operator who did.
	dest := filepath.Join(optDir, target, "nodary")
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(dest), ".nodary-upgrade-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(binary); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmp.Name(), 0o755); err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), dest); err != nil {
		return err
	}

	// The flip, which is the only moment anything changes. A symlink rename is
	// atomic, so there is no instant at which `current` points at nothing.
	link := filepath.Join(optDir, "current")
	staging := link + ".new"
	_ = os.Remove(staging)
	if err := os.Symlink(target, staging); err != nil {
		return err
	}
	if err := os.Rename(staging, link); err != nil {
		_ = os.Remove(staging)
		return err
	}

	// And become it. systemd starts the new binary from the same path; this
	// process is replaced rather than upgraded in place, which is why nothing
	// after this line can be relied upon to run.
	if out, err := d.Host.systemctl(ctx, "restart", AgentUnit); err != nil {
		return fmt.Errorf("placed %s but could not restart %s: %v: %s",
			target, AgentUnit, err, tail(out))
	}
	return nil
}

// fetchDist reads one artifact from the control plane's mirror.
func (d *Daemon) fetchDist(ctx context.Context, name string) ([]byte, error) {
	url := strings.TrimRight(d.Config.Server, "/") + api.Prefix + "/agent/dist/" + name
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := d.http().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("the mirror answered %s for %s — `nodary upgrade` on the "+
			"control plane publishes one", resp.Status, name)
	}
	return io.ReadAll(io.LimitReader(resp.Body, maxBinaryBytes))
}

// maxBinaryBytes bounds what a mirror can make this node hold in memory. The
// binary is tens of megabytes; this is loose enough not to matter and tight
// enough that a mirror answering with something else cannot exhaust a GPU host.
const maxBinaryBytes = 512 << 20

// setTarget and target carry the version the control plane last named, from the
// poll loop to the heartbeat goroutine.
//
// Guarded, unlike d.last beside it: this is written on every poll and read on
// every heartbeat, and the two run on different goroutines. d.last predates the
// race detector reaching this package and is a separate problem.
func (d *Daemon) setTarget(v string) {
	d.upgrades.mu.Lock()
	defer d.upgrades.mu.Unlock()
	d.upgrades.target = v
}

func (d *Daemon) target() string {
	d.upgrades.mu.Lock()
	defer d.upgrades.mu.Unlock()
	return d.upgrades.target
}
