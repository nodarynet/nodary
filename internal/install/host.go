package install

import (
	"context"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/nodarynet/nodary/internal/components"
	"github.com/nodarynet/nodary/internal/paths"
)

// Layout is docs/specs/01-install.md §12, as directories and their modes.
//
// The modes are the specification's, and they are not decorative:
// /var/lib/nodary at 0710 gives its group traverse only, so an operator added
// to it can reach `models/` — 0755 below, and meant to be operator-written —
// without being able to list the directory or reach the database or its
// write-ahead log, which are independently locked to owner-only regardless
// (internal/paths.ModeDataDir's comment has the reasoning), and
// /etc/nodary/pki at 0700 because it holds the agent CA's sealed key.
var Layout = []struct {
	Dir  string
	Mode os.FileMode
	// Owned says whether the service user should own it. The PKI and the
	// sealing key are root's.
	Owned bool
}{
	{paths.DataDir, paths.ModeDataDir, true},
	{filepath.Join(paths.DataDir, "dist"), 0o755, true},
	{filepath.Join(paths.DataDir, "models"), 0o755, true},
	{paths.ConfigDir, paths.ModeConfigDir, false},
	{filepath.Join(paths.ConfigDir, "pki"), 0o700, false},
	{filepath.Join(paths.ConfigDir, "deployments"), 0o755, false},
	{filepath.Join(paths.ConfigDir, "backends"), 0o755, false},
	{paths.LogDir, paths.ModeLogDir, true},
}

// EnsureLayout creates the directories of 01 §12 with their specified modes.
//
// Modes are set on every run, not only at creation. An install that created a
// directory correctly and then never checked it again would let a `chmod 777`
// stand forever — and /var/lib/nodary at 0755 is the audit chain readable by
// every user on the box.
func EnsureLayout(o Options) ([]Step, error) {
	o.setDefaults()
	uid, gid := -1, -1
	if o.User != "" {
		if u, err := user.Lookup(o.User); err == nil {
			fmt.Sscan(u.Uid, &uid)
			fmt.Sscan(u.Gid, &gid)
		}
	}

	var steps []Step
	for _, l := range Layout {
		path := o.path(l.Dir)
		step := Step{Name: "dir: " + l.Dir, Detail: fmt.Sprintf("%s %o", path, l.Mode)}

		info, err := os.Stat(path)
		switch {
		case os.IsNotExist(err):
			if err := os.MkdirAll(path, l.Mode); err != nil {
				return steps, err
			}
			step.Changed = true
		case err != nil:
			return steps, err
		case info.Mode().Perm() != l.Mode:
			step.Changed = true
		}
		// Set every time. See the note above.
		if err := os.Chmod(path, l.Mode); err != nil {
			return steps, fmt.Errorf("setting the mode of %s: %w", path, err)
		}
		if l.Owned && uid >= 0 && o.Root == "" {
			if err := os.Chown(path, uid, gid); err != nil {
				return steps, fmt.Errorf("setting the owner of %s: %w", path, err)
			}
		}
		steps = append(steps, step)
	}
	return steps, nil
}

// EnsureUser creates the service account 01 §4 step 4 asks for.
//
// A system account with no login shell and no home: it exists to own files and
// run two processes, and anything more is a way in. Idempotent — an existing
// account is used rather than recreated, because a site may have provisioned
// one with its own uid policy.
func EnsureUser(ctx context.Context, name string, o Options) (Step, error) {
	o.setDefaults()
	step := Step{Name: "user: " + name}
	if name == "" {
		step.Detail = "running as root; no service account"
		return step, nil
	}
	if _, err := user.Lookup(name); err == nil {
		step.Detail = "already exists"
		return step, nil
	}
	out, err := o.Run(ctx, "useradd", "--system", "--no-create-home",
		"--shell", "/usr/sbin/nologin", name)
	if err != nil {
		return step, fmt.Errorf("creating the %s user: %w: %s", name, err, strings.TrimSpace(string(out)))
	}
	step.Changed, step.Detail = true, "created as a system account with no shell"
	return step, nil
}

// PlaceComponents extracts the fetched archives and puts their binaries where
// the unit template expects them.
//
// It records ownership as it goes, distinguishing what it placed from what it
// found — R5-11, and the reason is that a host may already run containerd for
// something else. **A binary already present is left alone**, and recorded as
// found rather than placed, so an uninstall will not remove it.
func PlaceComponents(ctx context.Context, fetched []components.Fetched, o Options,
	recordPath, version string) ([]Step, error) {
	o.setDefaults()
	binDir := o.path(o.BinDir)
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		return nil, err
	}

	var steps []Step
	var owned []components.Owned
	for _, f := range fetched {
		want, ok := wantedBinaries[f.Component]
		if !ok {
			continue
		}
		staged := filepath.Join(filepath.Dir(f.Path), ".extract", f.Component)
		if strings.HasSuffix(f.Path, ".tar.gz") {
			if _, err := components.Extract(f.Path, staged); err != nil {
				return steps, err
			}
		}

		for _, b := range want {
			src := filepath.Join(staged, b.From)
			if !strings.HasSuffix(f.Path, ".tar.gz") {
				src = f.Path // a bare binary, e.g. runc
			}
			dst := filepath.Join(binDir, b.As)
			step := Step{Name: "bin: " + b.As, Detail: dst}

			if _, err := os.Stat(dst); err == nil {
				// Found, not placed. Left alone and recorded as such: removing
				// something the operator installed, because its name appears in
				// nodary's manifest, would take down whatever else uses it.
				step.Detail = dst + " (already present, left alone)"
				owned = append(owned, components.Owned{Component: f.Component,
					Version: f.Version, Path: dst, Placed: false})
				steps = append(steps, step)
				continue
			}
			if err := copyExecutable(src, dst); err != nil {
				return steps, fmt.Errorf("placing %s: %w", b.As, err)
			}
			step.Changed = true
			owned = append(owned, components.Owned{Component: f.Component,
				Version: f.Version, Path: dst, SHA256: f.SHA256, Placed: true})
			steps = append(steps, step)
		}
	}

	if recordPath != "" && len(owned) > 0 {
		if err := components.Record(recordPath, version, owned...); err != nil {
			return steps, err
		}
	}
	return steps, nil
}

// wantedBinaries names what comes out of each archive and what it is called on
// the host.
//
// An explicit list rather than "everything executable in the tarball":
// containerd's archive carries several binaries, only some of which nodary
// needs, and an install that placed all of them would own files it never uses
// and would remove them on uninstall.
var wantedBinaries = map[string][]struct{ From, As string }{
	"containerd": {
		{"bin/containerd", "containerd"},
		{"bin/containerd-shim-runc-v2", "containerd-shim-runc-v2"},
		{"bin/ctr", "ctr"},
	},
	"nerdctl": {{"nerdctl", "nerdctl"}},
	"runc":    {{"", "runc"}},
}

// CNIBinDir is where the CNI plugins live. Not /usr/local/bin: containerd looks
// for them in their own directory, and mixing them with host binaries makes
// both harder to reason about.
const CNIBinDir = "/opt/cni/bin"

// PlaceCNIPlugins extracts the CNI plugins into their own directory.
func PlaceCNIPlugins(fetched components.Fetched, o Options) (Step, error) {
	o.setDefaults()
	dir := o.path(CNIBinDir)
	step := Step{Name: "cni plugins", Detail: dir}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return step, err
	}
	// The plugins the isolated network's configuration names, and nothing else.
	before, _ := os.ReadDir(dir)
	if _, err := components.Extract(fetched.Path, dir); err != nil {
		return step, err
	}
	after, _ := os.ReadDir(dir)
	step.Changed = len(after) != len(before)
	step.Detail = fmt.Sprintf("%s (%d plugins)", dir, len(after))
	return step, nil
}

// copyExecutable places a binary at 0755, writing to a temporary file first so
// a killed install does not leave a truncated executable at a path something
// will try to run.
func copyExecutable(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	tmp, err := os.CreateTemp(filepath.Dir(dst), ".nodary-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := io.Copy(tmp, in); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmp.Name(), 0o755); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), dst)
}

// Start enables and starts a unit.
func Start(ctx context.Context, unit string, o Options) (Step, error) {
	o.setDefaults()
	step := Step{Name: "start: " + unit}
	if o.Root != "" {
		step.Detail = "not started: this is a staged install into " + o.Root
		return step, nil
	}
	out, err := o.Run(ctx, "systemctl", "enable", "--now", unit)
	if err != nil {
		return step, fmt.Errorf("starting %s: %w: %s", unit, err, strings.TrimSpace(string(out)))
	}
	step.Changed, step.Detail = true, "enabled and started"
	return step, nil
}

// Restart is for a unit that may already be running and needs to pick up a
// configuration written to disk after it started.
//
// `systemctl enable --now` — what Start runs — is a no-op on a unit that is
// already active: systemd does not compare what's on disk to what the running
// process loaded, it only asks whether *a* process is up. `gateway sync` used
// exactly that to make LiteLLM pick up its first real route and found the
// config on disk correct, the process still running the empty list it started
// with, and nothing said so. Safe to call on a stopped unit too — systemd
// starts it fresh, same as Start would.
func Restart(ctx context.Context, unit string, o Options) (Step, error) {
	o.setDefaults()
	step := Step{Name: "restart: " + unit}
	if o.Root != "" {
		step.Detail = "not restarted: this is a staged install into " + o.Root
		return step, nil
	}
	out, err := o.Run(ctx, "systemctl", "restart", unit)
	if err != nil {
		return step, fmt.Errorf("restarting %s: %w: %s", unit, err, strings.TrimSpace(string(out)))
	}
	step.Changed, step.Detail = true, "restarted"
	return step, nil
}

// EnsureBinary places this executable at docs/specs/01-install.md §12's
// location and points `current` at it.
//
// **The units must not invoke the binary wherever it happened to be at install
// time.** They carry `PrivateTmp=true` and `ProtectHome=true`, so a binary
// under /tmp or /home is invisible to the service — systemd reports
// `203/EXEC`, which says nothing about why. That is not hypothetical: it is
// what a privileged run of scripts/verify-privileged.sh reported, from a build
// in /tmp.
//
// 01 §2 step 4 has install.sh do this before it `exec`s the binary, and 01 §12
// fixes the paths. Doing it here as well means an install started any other way
// — a package manager, a copy, a `go build` — lands in the same place, and the
// unit's ExecStart is a path that exists for the service rather than for the
// person who ran the install.
func EnsureBinary(version string, o Options) ([]Step, string, error) {
	o.setDefaults()
	self, err := os.Executable()
	if err != nil {
		return nil, "", err
	}
	self, _ = filepath.EvalSymlinks(self)

	versioned := o.path(paths.VersionedBinary(version))
	stable := o.path(paths.Binary())
	step := Step{Name: "binary", Detail: versioned}

	if same, _ := sameFile(self, versioned); !same {
		if err := os.MkdirAll(filepath.Dir(versioned), 0o755); err != nil {
			return nil, "", err
		}
		if err := copyExecutable(self, versioned); err != nil {
			return nil, "", fmt.Errorf("placing the binary at %s: %w", versioned, err)
		}
		step.Changed, step.Detail = true, versioned+" (current → "+version+")"
	}
	// Both links every time, not only when the binary moved: that is how a run
	// which placed the binary and then failed heals on the next one.
	if err := linkCurrent(o, version); err != nil {
		return []Step{step}, stable, err
	}
	onPath, err := linkOnPath(o)
	if err != nil {
		return []Step{step}, stable, err
	}
	return []Step{step, onPath}, stable, nil
}

// linkOnPath puts `nodary` somewhere a shell will find it.
//
// **Every line this install prints tells the operator to run `nodary`** — the
// setup link, `nodary node approve`, `nodary token join`, `nodary doctor`. None
// of them worked: 01 §12 puts the binary at /opt/nodary/current/nodary, which
// is on nobody's PATH, and nothing linked it anywhere. The verification script
// never noticed because it runs its own build out of /tmp.
//
// /usr/local/bin because it is on a login PATH *and* in sudo's default
// `secure_path`, which matters more here than usual: almost every nodary verb
// worth typing needs root, and a link somewhere sudo strips would work for the
// operator and vanish under sudo — the same trap that hid nvidia-smi from
// preflight.
//
// The link points at `current`, not at a version, so an upgrade moves both by
// moving one.
func linkOnPath(o Options) (Step, error) {
	link := filepath.Join(o.path(o.BinDir), "nodary")
	target := o.path(paths.Binary())
	step := Step{Name: "PATH", Detail: link + " → " + target}

	switch info, err := os.Lstat(link); {
	case err == nil && info.Mode()&os.ModeSymlink == 0:
		// A real file, which somebody else put there — a pip or npm wrapper, or
		// an older copy. Left alone and reported, on the rule PlaceComponents
		// already follows: removing what an operator installed, because its
		// name matches ours, takes down whatever they were using it for.
		step.Detail = link + " is a file, not ours to replace; `nodary` may run an older build"
		return step, nil
	case err == nil:
		if existing, _ := os.Readlink(link); existing == target {
			return step, nil
		}
	case !os.IsNotExist(err):
		return step, err
	}

	if err := os.MkdirAll(filepath.Dir(link), 0o755); err != nil {
		return step, err
	}
	// Through a temporary name, for the reason linkCurrent does it: a link
	// removed and recreated has a window in which `nodary` is not a command.
	tmp := link + ".tmp"
	_ = os.Remove(tmp)
	if err := os.Symlink(target, tmp); err != nil {
		return step, err
	}
	if err := os.Rename(tmp, link); err != nil {
		return step, err
	}
	step.Changed = true
	return step, nil
}

// linkCurrent points /opt/nodary/current at one version.
//
// Replaced atomically through a temporary name: a symlink removed and recreated
// has a window in which every unit's ExecStart does not resolve, and an upgrade
// is exactly when something is likely to restart.
func linkCurrent(o Options, version string) error {
	dir := o.path(paths.OptDir)
	link := filepath.Join(dir, "current")
	tmp := filepath.Join(dir, ".current.tmp")
	_ = os.Remove(tmp)
	if err := os.Symlink(version, tmp); err != nil {
		return err
	}
	return os.Rename(tmp, link)
}

func sameFile(a, b string) (bool, error) {
	ai, err := os.Stat(a)
	if err != nil {
		return false, err
	}
	bi, err := os.Stat(b)
	if err != nil {
		return false, err
	}
	return os.SameFile(ai, bi), nil
}

// serviceOwned is what the control plane and the gateway open once they are
// running as the service account.
//
// **secret.key is deliberately absent.** 01 §12 keeps it 0400 root:root, and
// nodary-server.service passes it in with `LoadCredential=` instead. Adding it
// here would make the install quietly undo that.
var serviceOwned = []string{
	filepath.Join(paths.ConfigDir, "server.toml"),
	filepath.Join(paths.ConfigDir, "gateway.env"),
	filepath.Join(paths.ConfigDir, "pki"),
	paths.DataDir,
	paths.LogDir,
}

// EnsureOwnership hands those files to the account the units run as.
//
// `server install` runs as root and everything it creates is root:root; the
// units run as `nodary`. Every file the service opens has to be owned by that
// account or the install has produced a system that cannot start — and that is
// not hypothetical. A privileged run of scripts/verify-privileged.sh reported
//
//	nodary server start: open /etc/nodary/server.toml: permission denied
//
// from a control plane whose own installer had written the file seconds
// earlier. EnsureLayout already chowns the directories; nothing chowned what
// was written into them afterwards, which is everything that matters: the
// database, the PKI, and the two configuration files.
//
// Last step of the install, rather than at each write site, because that is
// where it can be true of everything at once: the certificates, the database
// and its write-ahead log are all created at different points and by different
// packages.
func EnsureOwnership(o Options) ([]Step, error) {
	o.setDefaults()
	if o.User == "" || o.Root != "" {
		// Running as root, or staged into a prefix that is nobody's to own.
		return nil, nil
	}
	u, err := user.Lookup(o.User)
	if err != nil {
		return nil, nil // EnsureUser has already said so
	}
	uid, gid := -1, -1
	fmt.Sscan(u.Uid, &uid)
	fmt.Sscan(u.Gid, &gid)
	if uid < 0 || gid < 0 {
		return nil, nil
	}

	var steps []Step
	for _, path := range serviceOwned {
		changed, err := chownTree(path, uid, gid)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return steps, fmt.Errorf("giving %s to %s: %w", path, o.User, err)
		}
		steps = append(steps, Step{Name: "own: " + filepath.Base(path), Changed: changed,
			Detail: path + " → " + o.User})
	}
	return steps, nil
}

// chownTree gives one path, and everything under it, to uid:gid.
//
// Lchown rather than Chown: a symlink planted in the tree would otherwise let
// whoever planted it redirect a root-run chown at a file outside it.
func chownTree(root string, uid, gid int) (bool, error) {
	var changed bool
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		if st, ok := info.Sys().(*syscall.Stat_t); ok && int(st.Uid) == uid && int(st.Gid) == gid {
			return nil
		}
		changed = true
		return os.Lchown(p, uid, gid)
	})
	return changed, err
}
