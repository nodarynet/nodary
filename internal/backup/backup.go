// Package backup writes and describes the archive dev/specs/08-data-model.md
// §4 requires.
//
// It is a package rather than a function in one front end because both of them
// take backups now: `nodary backup create` on the console, and `POST /backups`
// for an administrator who is not standing at one. The archive format is the
// one thing that absolutely must not exist twice — a writer and a reader that
// disagree are discovered at restore, by somebody already having a bad day.
package backup

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/nodarynet/nodary/internal/audit"
	"github.com/nodarynet/nodary/internal/buildinfo"
	"github.com/nodarynet/nodary/internal/paths"
	"github.com/nodarynet/nodary/internal/store"
)

// A backup of nodary.db alone is useless: the TOTP seeds and the agent CA
// private key inside it are sealed under /etc/nodary/secret.key, the LiteLLM
// master key is in the configuration and not in the database at all, and the
// agent CA's certificate lives beside the key rather than in either.
//
// The inverse is the one that actually happens. An operator who backs up only
// the database finds out at restore time — the worst possible moment — that
// every node must re-enroll and every TOTP enrollment must be redone. So this
// takes both, always, and there is no flag to take less.
const (
	Database = "nodary.db"
	Config   = "config"
	Manifest = "backup.json"
)

// Info travels inside the archive so a restore can tell what it is holding
// before it writes anything.
type Info struct {
	CreatedAt string `json:"created_at"`
	Version   string `json:"version"`
	Install   string `json:"install"`
	Database  string `json:"database"`
	ConfigDir string `json:"config_dir"`
}

// Report is what was written, for whichever front end asked.
//
// The digest is here because the archive now has somewhere to go that is not
// the machine that made it: an operator moving one off-box has something to
// check it against that does not require reading the file twice.
type Report struct {
	Path     string   `json:"path"`
	Bytes    int64    `json:"bytes"`
	SHA256   string   `json:"sha256"`
	Captured []string `json:"captured"`
}

// ErrExposedDestination is 08 §4's refusal. Its own error because both front
// ends have to answer it the same way — exit 5 and 403, not a generic failure.
var ErrExposedDestination = errors.New("a backup holds the sealing key and this destination is not private")

// ErrExists refuses to overwrite. Last night's backup is not overwritten by a
// mistyped path.
var ErrExists = errors.New("that file already exists")

// CheckDestination refuses a world-readable or world-writable directory.
//
// The directory rather than the file: the archive itself is created 0600, so
// what is left to get wrong is where it is put. A world-writable one lets
// somebody replace the backup with their own, and a world-readable one is the
// case the specification names.
//
// No override. The specification says refuses, and a file holding the sealing
// key is not the place to add a way to say "yes I know".
func CheckDestination(out string) error {
	dir := filepath.Dir(out)
	info, err := os.Stat(dir)
	if err != nil {
		return err
	}
	if mode := info.Mode().Perm(); mode&0o007 != 0 {
		return fmt.Errorf("%w: %s is mode %04o — every TOTP seed, the data plane's credential "+
			"and the agent CA private key are sealed under /etc/nodary/secret.key, which this "+
			"archive contains (dev/specs/08-data-model.md §4). Write somewhere only root can "+
			"reach: sudo install -d -m 0700 /var/backups/nodary", ErrExposedDestination, dir, mode)
	}
	if _, err := os.Stat(out); err == nil {
		return fmt.Errorf("%w: %s; last night's backup is not overwritten", ErrExists, out)
	}
	return nil
}

// Create assembles the archive and returns what it holds.
//
// The caller records the act first. That ordering is the point: the audit
// record of the backup is inside the backup, which it can only be if the
// transaction has committed before the snapshot is taken — and it has to have
// committed anyway, because VACUUM INTO cannot start while a write is open.
func Create(ctx context.Context, db *store.DB, now time.Time, out, configDir string) (Report, error) {
	tmp, err := os.MkdirTemp(filepath.Dir(out), ".nodary-backup-*")
	if err != nil {
		return Report{}, err
	}
	defer os.RemoveAll(tmp)

	// Snapshotted rather than copied: `cp nodary.db` on a live host silently
	// omits everything since the last checkpoint.
	snapshot := filepath.Join(tmp, Database)
	if err := db.Snapshot(ctx, snapshot); err != nil {
		return Report{}, err
	}

	install, _ := audit.InstallID(ctx, db.Read())
	info := Info{
		CreatedAt: now.UTC().Format(audit.TimeFormat),
		Version:   buildinfo.Version,
		Install:   install,
		Database:  db.Path(),
		ConfigDir: configDir,
	}

	f, err := os.OpenFile(out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, paths.ModeDatabase)
	if err != nil {
		return Report{}, err
	}
	defer f.Close()

	// The digest is taken as the bytes are written, so nothing reads this file
	// back — a second read would be a second answer if anything touched it in
	// between, which is exactly what a digest is supposed to rule out.
	sum := sha256.New()
	counted := &counter{w: io.MultiWriter(f, sum)}
	gz := gzip.NewWriter(counted)
	tw := tar.NewWriter(gz)

	manifest, err := json.MarshalIndent(info, "", "  ")
	if err != nil {
		return Report{}, err
	}
	if err := addFile(tw, Manifest, append(manifest, '\n'), 0o600); err != nil {
		return Report{}, err
	}

	var captured []string
	if err := addPath(tw, Database, snapshot, &captured); err != nil {
		return Report{}, err
	}
	if err := addTree(tw, Config, configDir, &captured); err != nil {
		return Report{}, err
	}
	if err := tw.Close(); err != nil {
		return Report{}, err
	}
	if err := gz.Close(); err != nil {
		return Report{}, err
	}
	if err := f.Sync(); err != nil {
		return Report{}, err
	}
	return Report{Path: out, Bytes: counted.n,
		SHA256: hex.EncodeToString(sum.Sum(nil)), Captured: captured}, nil
}

type counter struct {
	w io.Writer
	n int64
}

func (c *counter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	c.n += int64(n)
	return n, err
}

func addFile(tw *tar.Writer, name string, body []byte, mode os.FileMode) error {
	if err := tw.WriteHeader(&tar.Header{
		Name: name, Mode: int64(mode), Size: int64(len(body)), Typeflag: tar.TypeReg,
	}); err != nil {
		return err
	}
	_, err := tw.Write(body)
	return err
}

func addPath(tw *tar.Writer, name, path string, captured *[]string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	body, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if captured != nil {
		*captured = append(*captured, fmt.Sprintf("%-28s %s", name, HumanBytes(info.Size())))
	}
	return addFile(tw, name, body, info.Mode().Perm())
}

// addTree captures a whole directory.
//
// Everything under it, with no exclusions. The alternative is a list of what
// matters, which is a list somebody has to remember to extend — and the failure
// mode of forgetting is discovered at restore. /etc/nodary is small, and all of
// it is either configuration or a secret.
func addTree(tw *tar.Writer, prefix, root string, captured *[]string) error {
	return filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		name := filepath.ToSlash(filepath.Join(prefix, rel))
		info, err := d.Info()
		if err != nil {
			return err
		}
		if d.IsDir() {
			return tw.WriteHeader(&tar.Header{
				Name: name + "/", Mode: int64(info.Mode().Perm()), Typeflag: tar.TypeDir,
			})
		}
		// Symlinks are followed rather than recorded. A backup that restored a
		// dangling link in place of a key would look like it worked.
		if !info.Mode().IsRegular() {
			return nil
		}
		return addPath(tw, name, path, captured)
	})
}

func HumanBytes(n int64) string {
	switch {
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MiB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.1f KiB", float64(n)/(1<<10))
	}
	return fmt.Sprintf("%d B", n)
}
