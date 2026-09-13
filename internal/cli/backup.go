package cli

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/nodarynet/nodary/internal/audit"
	"github.com/nodarynet/nodary/internal/buildinfo"
	"github.com/nodarynet/nodary/internal/paths"
)

// docs/specs/08-data-model.md §4. A backup of nodary.db alone is useless: the
// TOTP seeds, the LiteLLM master key and the agent CA private key inside it are
// all sealed under /etc/nodary/secret.key, and the agent CA's own certificate
// lives beside it rather than in the database at all.
//
// The inverse is the one that actually happens. An operator who backs up only
// the database finds out at restore time — the worst possible moment — that
// every node must re-enroll and every TOTP enrollment must be redone. So this
// verb takes both, always, and there is no flag to take less.
const (
	backupDatabase = "nodary.db"
	backupConfig   = "config"
	backupManifest = "backup.json"
)

// backupInfo travels inside the archive so a restore can tell what it is
// holding before it writes anything.
type backupInfo struct {
	CreatedAt string `json:"created_at"`
	Version   string `json:"version"`
	Install   string `json:"install"`
	Database  string `json:"database"`
	ConfigDir string `json:"config_dir"`
}

func cmdBackup(e env, args []string) int {
	if len(args) == 0 {
		fmt.Fprintf(e.stderr, "nodary backup: expected a subcommand (create, restore)\n")
		return ExitUsage
	}
	switch args[0] {
	case "create":
		return cmdBackupCreate(e, args[1:])
	case "restore":
		return cmdBackupRestore(e, args[1:])
	}
	fmt.Fprintf(e.stderr, "nodary backup: unknown subcommand %q (want create or restore)\n", args[0])
	return ExitUsage
}

// cmdBackupCreate writes one file holding everything needed to stand this
// control plane back up.
func cmdBackupCreate(e env, args []string) int {
	fs := newFlagSet(e, "backup create")
	dbPath, keyPath, credsPath := stateFlags(fs)
	cer := attestFlags(fs)
	out := fs.String("out", "", "the archive to write")
	configDir := fs.String("config-dir", paths.ConfigDir, "the configuration directory to capture")
	if code := parseFlags(e, fs, args); code >= 0 {
		return code
	}
	if *out == "" {
		fmt.Fprintf(e.stderr, "nodary backup create: --out is required\n")
		return ExitUsage
	}
	if code := refuseExposedDestination(e, "backup create", *out); code >= 0 {
		return code
	}
	if _, err := os.Stat(*out); err == nil {
		fmt.Fprintf(e.stderr, "nodary backup create: %s already exists; last night's backup is not overwritten\n", *out)
		return ExitFailure
	}

	s, ok := openSession(e, "backup create", *dbPath, *keyPath, *credsPath)
	if !ok {
		return ExitFailure
	}
	defer s.Close()

	// Audited like `evidence export`, and for the same reason: it is a read
	// that leaves the machine carrying every secret the machine has.
	rec, applied, code := s.attested(e, "backup create", change{
		action: "backup.create",
		target: &audit.Target{Kind: "backup", ID: filepath.Base(*out)},
		render: func(ctx context.Context, tx *sql.Tx) (any, error) {
			return map[string]any{
				"out": *out, "database": s.db.Path(), "config_dir": *configDir,
				"includes_secret_key": true,
			}, nil
		},
		apply: func(m audit.Mutation, _ any) error {
			// Written before the snapshot rather than after, so the record of
			// the backup is inside the backup. The transaction commits before
			// VACUUM INTO runs — it has to, because a vacuum cannot start while
			// a write is open.
			m.Detail("out", *out)
			m.Detail("config_dir", *configDir)
			return nil
		},
	}, cer, "text")
	if !applied {
		return code
	}

	if err := writeBackup(e, s, *out, *configDir); err != nil {
		os.Remove(*out)
		fmt.Fprintf(e.stderr, "nodary backup create: %v\n", err)
		return ExitFailure
	}
	reportRecord(e, rec)
	return ExitOK
}

// writeBackup assembles the archive.
func writeBackup(e env, s *session, out, configDir string) error {
	tmp, err := os.MkdirTemp(filepath.Dir(out), ".nodary-backup-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)

	snapshot := filepath.Join(tmp, backupDatabase)
	if err := s.db.Snapshot(context.Background(), snapshot); err != nil {
		return err
	}

	install, _ := audit.InstallID(context.Background(), s.db.Read())
	info := backupInfo{
		CreatedAt: s.now.UTC().Format(audit.TimeFormat),
		Version:   buildinfo.Version,
		Install:   install,
		Database:  s.db.Path(),
		ConfigDir: configDir,
	}

	f, err := os.OpenFile(out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, paths.ModeDatabase)
	if err != nil {
		return err
	}
	defer f.Close()

	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)

	manifest, err := json.MarshalIndent(info, "", "  ")
	if err != nil {
		return err
	}
	if err := addFileTo(tw, backupManifest, append(manifest, '\n'), 0o600); err != nil {
		return err
	}

	var captured []string
	if err := addPathTo(tw, backupDatabase, snapshot, &captured); err != nil {
		return err
	}
	if err := addTreeTo(tw, backupConfig, configDir, &captured); err != nil {
		return err
	}
	if err := tw.Close(); err != nil {
		return err
	}
	if err := gz.Close(); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}

	reportBackup(e, out, captured)
	return nil
}

// reportBackup says the loud thing 08 §4 requires.
func reportBackup(e env, out string, captured []string) {
	fmt.Fprintln(e.stdout, out)
	fmt.Fprintf(e.stderr, "\nWrote %s (0600), holding:\n", out)
	for _, c := range captured {
		fmt.Fprintf(e.stderr, "  %s\n", c)
	}
	fmt.Fprintf(e.stderr,
		"\nThis file is as sensitive as /etc/nodary/secret.key, because it contains it.\n"+
			"Anyone holding it can read every TOTP seed, the LiteLLM master key and the\n"+
			"agent CA private key. Store it where you would store the key itself.\n")
}

// refuseExposedDestination implements 08 §4's refusal.
//
// The directory rather than the file: the archive itself is created 0600, so
// what is left to get wrong is where it is put. A world-writable directory lets
// somebody replace the backup with their own, and a world-readable one is the
// case the specification names.
//
// No override flag. The specification says refuses, and a backup holding the
// sealing key is not the place to add a way to say "yes I know".
func refuseExposedDestination(e env, verb, out string) int {
	dir := filepath.Dir(out)
	info, err := os.Stat(dir)
	if err != nil {
		fmt.Fprintf(e.stderr, "nodary %s: %v\n", verb, err)
		return ExitFailure
	}
	if mode := info.Mode().Perm(); mode&0o007 != 0 {
		fmt.Fprintf(e.stderr,
			"nodary %s: %s is mode %04o, and a backup holds /etc/nodary/secret.key —\n"+
				"  every TOTP seed, the LiteLLM master key and the agent CA private key are\n"+
				"  sealed under it (docs/specs/08-data-model.md §4).\n"+
				"  Write somewhere only root can reach:\n"+
				"    sudo install -d -m 0700 /var/backups/nodary\n", verb, dir, mode)
		return ExitPolicy
	}
	return -1
}

func addFileTo(tw *tar.Writer, name string, body []byte, mode os.FileMode) error {
	if err := tw.WriteHeader(&tar.Header{
		Name: name, Mode: int64(mode), Size: int64(len(body)), Typeflag: tar.TypeReg,
	}); err != nil {
		return err
	}
	_, err := tw.Write(body)
	return err
}

func addPathTo(tw *tar.Writer, name, path string, captured *[]string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	body, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if captured != nil {
		*captured = append(*captured, fmt.Sprintf("%-28s %s", name, humanBytes(info.Size())))
	}
	return addFileTo(tw, name, body, info.Mode().Perm())
}

// addTreeTo captures a whole directory.
//
// Everything under it, with no exclusions. The alternative is a list of what
// matters, which is a list somebody has to remember to extend — and the failure
// mode of forgetting is discovered at restore, by somebody having a bad day
// already. /etc/nodary is small, and all of it is either configuration or a
// secret.
func addTreeTo(tw *tar.Writer, prefix, root string, captured *[]string) error {
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
		return addPathTo(tw, name, path, captured)
	})
}

func humanBytes(n int64) string {
	switch {
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MiB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.1f KiB", float64(n)/(1<<10))
	}
	return fmt.Sprintf("%d B", n)
}

// cmdBackupRestore puts a backup back.
//
// It writes files and starts nothing. A control plane that came back up on its
// own, mid-restore, against a half-written database, is a worse outcome than an
// operator running one more command.
func cmdBackupRestore(e env, args []string) int {
	fs := newFlagSet(e, "backup restore")
	from := fs.String("from", "", "the archive to restore")
	dbPath := fs.String("db", paths.Database(), "where to write the database")
	configDir := fs.String("config-dir", paths.ConfigDir, "where to write the configuration")
	force := fs.Bool("force", false, "overwrite an existing database and configuration")
	if code := parseFlags(e, fs, args); code >= 0 {
		return code
	}
	if *from == "" && fs.NArg() == 1 {
		*from = fs.Arg(0)
	}
	if *from == "" {
		fmt.Fprintf(e.stderr, "nodary backup restore: --from is required\n")
		return ExitUsage
	}

	info, members, err := readBackup(*from)
	if err != nil {
		fmt.Fprintf(e.stderr, "nodary backup restore: %v\n", err)
		return ExitFailure
	}

	// Refused rather than merged. Restoring over a live installation would
	// leave a database from one moment beside a sealing key from another, and
	// a database whose secrets will not unseal is indistinguishable from a
	// corrupt one until somebody tries to use a TOTP code.
	if !*force {
		for _, path := range []string{*dbPath, filepath.Join(*configDir, "secret.key")} {
			if _, err := os.Stat(path); err == nil {
				fmt.Fprintf(e.stderr,
					"nodary backup restore: %s already exists.\n"+
						"  Restoring over a live installation mixes a database from one moment with a\n"+
						"  sealing key from another, and the result does not announce itself — it fails\n"+
						"  later, at a TOTP prompt or a node's next request.\n"+
						"  Stop the control plane and move the existing files aside, or pass --force.\n",
					path)
				return ExitFailure
			}
		}
	}

	fmt.Fprintf(e.stderr, "Restoring the backup taken at %s", info.CreatedAt)
	if info.Version != "" {
		fmt.Fprintf(e.stderr, " by nodary %s", info.Version)
	}
	if info.Install != "" {
		fmt.Fprintf(e.stderr, " (install %s)", info.Install)
	}
	fmt.Fprintln(e.stderr, ".")

	written, err := extractBackupTo(*from, members, *dbPath, *configDir)
	if err != nil {
		fmt.Fprintf(e.stderr, "nodary backup restore: %v\n", err)
		return ExitFailure
	}
	for _, w := range written {
		fmt.Fprintf(e.stderr, "  %s\n", w)
	}
	fmt.Fprintf(e.stderr,
		"\nNothing was started. Check the result before bringing the control plane up:\n"+
			"  nodary audit verify --db %s\n"+
			"  systemctl start nodary-server\n", *dbPath)
	return ExitOK
}

// readBackup reads the manifest and the member list without extracting.
func readBackup(path string) (backupInfo, []string, error) {
	var info backupInfo
	var members []string
	err := walkBackup(path, func(h *tar.Header, r io.Reader) error {
		if h.Typeflag == tar.TypeDir {
			return nil
		}
		members = append(members, h.Name)
		if h.Name == backupManifest {
			return json.NewDecoder(r).Decode(&info)
		}
		return nil
	})
	if err != nil {
		return backupInfo{}, nil, err
	}
	if !slices.Contains(members, backupDatabase) {
		return backupInfo{}, nil, fmt.Errorf("%s holds no %s; it is not a nodary backup", path, backupDatabase)
	}
	// The refusal 08 §4 exists to prevent, caught before anything is written
	// rather than at the TOTP prompt three weeks later.
	if !slices.Contains(members, backupConfig+"/secret.key") {
		return backupInfo{}, nil, fmt.Errorf(
			"%s holds a database but no config/secret.key.\n"+
				"  Every TOTP seed, the LiteLLM master key and the agent CA private key in that\n"+
				"  database are sealed under it, so restoring this would produce a control plane\n"+
				"  that starts and cannot read its own secrets", path)
	}
	return info, members, nil
}

// extractBackupTo writes the members out, recreating each file's recorded mode.
func extractBackupTo(path string, members []string, dbPath, configDir string) ([]string, error) {
	var written []string
	err := walkBackup(path, func(h *tar.Header, r io.Reader) error {
		var dest string
		switch {
		case h.Name == backupManifest:
			return nil
		case h.Name == backupDatabase:
			dest = dbPath
		case strings.HasPrefix(h.Name, backupConfig+"/"):
			rel := strings.TrimPrefix(h.Name, backupConfig+"/")
			// An archive is untrusted input even when we wrote it: a member
			// named ../../etc/shadow would otherwise escape the destination.
			if !filepath.IsLocal(rel) {
				return fmt.Errorf("%s names a path outside the destination", h.Name)
			}
			dest = filepath.Join(configDir, rel)
		default:
			return nil
		}

		mode := os.FileMode(h.Mode).Perm()
		if h.Typeflag == tar.TypeDir {
			return os.MkdirAll(dest, mode)
		}
		if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
			return err
		}
		f, err := os.OpenFile(dest, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
		if err != nil {
			return err
		}
		if _, err := io.Copy(f, r); err != nil {
			f.Close()
			return err
		}
		if err := f.Close(); err != nil {
			return err
		}
		// Set explicitly: O_CREATE applies the process umask, and a sealing key
		// restored at 0644 instead of 0400 is a silent total compromise.
		if err := os.Chmod(dest, mode); err != nil {
			return err
		}
		written = append(written, fmt.Sprintf("%-28s %04o", dest, mode))
		return nil
	})
	return written, err
}

func walkBackup(path string, fn func(*tar.Header, io.Reader) error) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return fmt.Errorf("%s is not a gzip archive: %w", path, err)
	}
	defer gz.Close()

	tr := tar.NewReader(gz)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		if err := fn(h, tr); err != nil {
			return err
		}
	}
}
