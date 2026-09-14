package cli

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/nodarynet/nodary/internal/audit"
	"github.com/nodarynet/nodary/internal/backup"
	"github.com/nodarynet/nodary/internal/paths"
)

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
	server := serverFlag(fs)
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
	rem, code := remoteFor(e, "backup create", *server, *credsPath, *dbPath, *keyPath)
	if code >= 0 {
		return code
	}

	// **The archive is written on the control plane and stays there**, and
	// --out names a path on that machine rather than on this one.
	//
	// Not a limitation worked around later: 08 §4 says the archive is as
	// sensitive as the sealing key because it contains it, along with the
	// agent CA private key and the LiteLLM master key. Streaming that to
	// whichever laptop ran the command would move the control plane's entire
	// secret material onto a machine with a different security posture as a
	// side effect of a flag. What --server buys is the attribution: the chain
	// says who took the backup, where a cron on the host says root.
	if rem != nil {
		var rep backup.Report
		out, applied, code := rem.attested(e, "backup create", remoteAct{method: "POST",
			path: "/backups", body: map[string]string{"out": *out, "config_dir": *configDir}},
			cer, "text")
		if !applied {
			return code
		}
		if raw, err := json.Marshal(out.Result); err == nil {
			_ = json.Unmarshal(raw, &rep)
		}
		reportBackup(e, rep, true)
		reportRecord(e, audit.Record{Seq: out.AuditSeq})
		return ExitOK
	}

	if err := backup.CheckDestination(*out); err != nil {
		fmt.Fprintf(e.stderr, "nodary backup create: %v\n", err)
		return exitFor(err)
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

	rep, err := backup.Create(context.Background(), s.db, s.now, *out, *configDir)
	if err != nil {
		os.Remove(*out)
		fmt.Fprintf(e.stderr, "nodary backup create: %v\n", err)
		return ExitFailure
	}
	reportBackup(e, rep, false)
	reportRecord(e, rec)
	return ExitOK
}

// reportBackup says the loud thing 08 §4 requires.
//
// `remote` changes one sentence and it is the one that matters: the file is on
// the control plane, so "store it where you would store the key itself" is
// advice about a machine the operator is not standing on.
func reportBackup(e env, rep backup.Report, remote bool) {
	fmt.Fprintln(e.stdout, rep.Path)
	where := ""
	if remote {
		where = " on the control plane"
	}
	fmt.Fprintf(e.stderr, "\nWrote %s%s (0600), %s, sha256:%s, holding:\n",
		rep.Path, where, backup.HumanBytes(rep.Bytes), rep.SHA256[:min(12, len(rep.SHA256))])
	for _, c := range rep.Captured {
		fmt.Fprintf(e.stderr, "  %s\n", c)
	}
	fmt.Fprintf(e.stderr,
		"\nThis file is as sensitive as /etc/nodary/secret.key, because it contains it.\n"+
			"Anyone holding it can read every TOTP seed, the LiteLLM master key and the\n"+
			"agent CA private key. Store it where you would store the key itself.\n")
	if remote {
		fmt.Fprintf(e.stderr,
			"It stays on that machine: nodary will not carry the sealing key to yours.\n"+
				"Move it with whatever already moves your backups off that host.\n")
	}
}

// cmdBackupRestore puts a backup back.
//
// It writes files and starts nothing. A control plane that came back up on its
// own, mid-restore, against a half-written database, is a worse outcome than an
// operator running one more command.
func cmdBackupRestore(e env, args []string) int {
	fs := newFlagSet(e, "backup restore")
	server := serverFlag(fs)
	from := fs.String("from", "", "the archive to restore")
	dbPath := fs.String("db", paths.Database(), "where to write the database")
	configDir := fs.String("config-dir", paths.ConfigDir, "where to write the configuration")
	force := fs.Bool("force", false, "overwrite an existing database and configuration")
	if code := parseFlags(e, fs, args); code >= 0 {
		return code
	}
	// **Declared so it can be refused with a reason**, rather than falling
	// through to "flag provided but not defined" — an administrator who can
	// create a backup over the network will reasonably try to restore one that
	// way, and the answer is a sentence, not a parser error.
	//
	// Restore replaces /etc/nodary and the database on the machine it runs on,
	// with the control plane stopped, and starts nothing afterwards. There is
	// no coherent thing for it to do against a control plane that is serving
	// requests — and a control plane that could be told to overwrite its own
	// sealing key over HTTP is one whose worst day is one request away.
	if strings.TrimSpace(*server) != "" {
		fmt.Fprintf(e.stderr,
			"nodary backup restore: this runs on the control-plane host, with it stopped.\n"+
				"  It replaces the database and /etc/nodary and starts nothing, so there is\n"+
				"  nothing for --server to act against:\n"+
				"    sudo systemctl stop nodary-server\n"+
				"    sudo nodary backup restore --from ARCHIVE\n"+
				"    sudo nodary audit verify && sudo systemctl start nodary-server\n")
		return ExitUsage
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
func readBackup(path string) (backup.Info, []string, error) {
	var info backup.Info
	var members []string
	err := walkBackup(path, func(h *tar.Header, r io.Reader) error {
		if h.Typeflag == tar.TypeDir {
			return nil
		}
		members = append(members, h.Name)
		if h.Name == backup.Manifest {
			return json.NewDecoder(r).Decode(&info)
		}
		return nil
	})
	if err != nil {
		return backup.Info{}, nil, err
	}
	if !slices.Contains(members, backup.Database) {
		return backup.Info{}, nil, fmt.Errorf("%s holds no %s; it is not a nodary backup", path, backup.Database)
	}
	// The refusal 08 §4 exists to prevent, caught before anything is written
	// rather than at the TOTP prompt three weeks later.
	if !slices.Contains(members, backup.Config+"/secret.key") {
		return backup.Info{}, nil, fmt.Errorf(
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
		case h.Name == backup.Manifest:
			return nil
		case h.Name == backup.Database:
			dest = dbPath
		case strings.HasPrefix(h.Name, backup.Config+"/"):
			rel := strings.TrimPrefix(h.Name, backup.Config+"/")
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
