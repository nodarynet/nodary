package cli

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/nodarynet/nodary/internal/audit"
	"github.com/nodarynet/nodary/internal/components"
	"github.com/nodarynet/nodary/internal/paths"
)

// cmdComponentsApply is R5-27: a signed manifest revision supersedes the
// binary's embedded copy.
//
// **Applying one is a mutation and lands in the chain** (ADR 0007), so *which*
// manifest a fleet is running is an attributable fact with a person against it,
// rather than something inferred from a version string. That is the whole
// difference between this and dropping a file into /etc: the file is what the
// resolution reads, and the record is what says who decided it should.
//
// It takes a path rather than a URL. The revision arrives however the site
// already receives things — a download on a connected machine, a file an
// operator carried, a member extracted from an offline bundle — and a
// downloader here would be a second place the verification could differ, which
// is the failure `bundle create` is written to avoid.
func cmdComponentsApply(e env, args []string) int {
	fs := newFlagSet(e, "components apply")
	dbPath, keyPath, credsPath := stateFlags(fs)
	cer := attestFlags(fs)
	format := formatFlag(fs)
	sigPath := fs.String("signature", "", "detached signature (default: the path plus .minisig)")
	dir := fs.String("config-dir", "", "where the revision is installed (default "+paths.ConfigDir+")")
	if code := parseFlags(e, fs, args); code >= 0 {
		return code
	}
	if !checkFormat(e, *format) {
		return ExitUsage
	}
	if fs.NArg() != 1 {
		fmt.Fprintf(e.stderr, "nodary components apply: expected one manifest path\n")
		return ExitUsage
	}
	path := fs.Arg(0)

	doc, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintf(e.stderr, "nodary components apply: %v\n", err)
		return ExitFailure
	}
	sig, err := os.ReadFile(orElse(*sigPath, path+".minisig"))
	if err != nil {
		fmt.Fprintf(e.stderr, "nodary components apply: %v\n", err)
		fmt.Fprintf(e.stderr,
			"  a revision decides what every node installs; there is no unsigned mode\n")
		return ExitFailure
	}

	// Verified before anything is recorded or written: a chain record for a
	// revision that was never applied would be a false statement about the
	// fleet, and a half-written file would be one the resolution then reads.
	candidate, err := components.VerifyRevision(doc, string(sig))
	if err != nil {
		fmt.Fprintf(e.stderr, "nodary components apply: %v\n", err)
		if errors.Is(err, components.ErrUnverified) {
			fmt.Fprintf(e.stderr,
				"  This is a hard stop, and the floor keeps running. If the signature was made\n"+
					"  with stock minisign, it needs `-S -l`: the default writes a prehashed\n"+
					"  signature this build refuses (ADR 0007).\n")
		}
		return ExitFailure
	}
	floor, err := components.Load()
	if err != nil {
		fmt.Fprintf(e.stderr, "nodary components apply: %v\n", err)
		return ExitFailure
	}
	if candidate.Revision <= floor.Revision {
		// Not an error. An offline site replaying a bundle it already opened is
		// not doing anything wrong, and failing closed would make the safest
		// delivery mechanism the most fragile.
		fmt.Fprintf(e.stderr, "nodary components apply: revision %d is not newer than this "+
			"build's %d; nothing applied\n", candidate.Revision, floor.Revision)
		return ExitOK
	}

	configDir := orElse(*dir, paths.ConfigDir)
	s, ok := openSession(e, "components apply", *dbPath, *keyPath, *credsPath)
	if !ok {
		return ExitFailure
	}
	defer s.Close()

	rec, applied, code := s.attested(e, "components apply", change{
		action: "components.apply",
		target: &audit.Target{Kind: "manifest", ID: fmt.Sprintf("revision %d", candidate.Revision)},
		render: func(context.Context, *sql.Tx) (any, error) {
			return applyPreview(floor, candidate), nil
		},
		apply: func(m audit.Mutation, _ any) error {
			if err := writeRevision(configDir, doc, sig); err != nil {
				// Outside the transaction's reach: the file is on disk or it is
				// not, and a rollback would leave the chain saying nothing
				// happened on a host where it did.
				return audit.Partial{Err: err}
			}
			m.Detail("manifest_revision", candidate.Revision)
			m.Detail("superseded", floor.Revision)
			return nil
		},
	}, cer, *format)
	if !applied {
		return code
	}

	fmt.Fprintf(e.stderr, "manifest revision %d applied, superseding this build's %d.\n",
		candidate.Revision, floor.Revision)
	reportRecord(e, rec)
	return ExitOK
}

// applyPreview is what the operator approves, so it is the *difference* rather
// than the document: a manifest is thousands of lines and a diff of digests is
// the part a person can actually check.
func applyPreview(floor, candidate *components.Manifest) map[string]any {
	was := map[string]string{}
	for _, c := range floor.Components {
		for plat, a := range c.Platforms {
			was[c.Name+" "+plat] = a.SHA256 + a.Image
		}
	}
	var changed []map[string]any
	for _, c := range candidate.Components {
		for plat, a := range c.Platforms {
			key := c.Name + " " + plat
			now := a.SHA256 + a.Image
			if old, had := was[key]; !had || old != now {
				changed = append(changed, map[string]any{
					"component": c.Name, "platform": plat,
					"version": c.Version, "was": orDash(old), "now": now,
				})
			}
		}
	}
	return map[string]any{
		"revision": candidate.Revision, "superseded": floor.Revision,
		"nodary_version": candidate.NodaryVersion, "changed": changed,
	}
}

// writeRevision installs the document and its signature together.
//
// The signature lands *first*. Resolution reads the document and then looks for
// a signature beside it, so a crash between the two leaves a document with no
// signature — which the resolution refuses and reports — rather than a stale
// signature that verifies nothing, which it would also refuse but after
// claiming the pair was a matched set.
func writeRevision(dir string, doc, sig []byte) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	if err := replaceFile(filepath.Join(dir, components.RevisionSig), sig); err != nil {
		return err
	}
	return replaceFile(filepath.Join(dir, components.RevisionName), doc)
}

func replaceFile(path string, body []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(body); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmp.Name(), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// cmdComponentsShow answers which manifest this install is actually running.
//
// The question ADR 0007 makes worth asking: with a floor and a revision there
// are two documents on the host, and "what does this fleet pin" stops being
// readable off the version string.
func cmdComponentsShow(e env, args []string) int {
	fs := newFlagSet(e, "components show")
	format := formatFlag(fs)
	dir := fs.String("config-dir", "", "where a revision would be (default "+paths.ConfigDir+")")
	if code := parseFlags(e, fs, args); code >= 0 {
		return code
	}
	if !checkFormat(e, *format) {
		return ExitUsage
	}
	m, src, err := components.Effective(orElse(*dir, paths.ConfigDir))
	if err != nil {
		fmt.Fprintf(e.stderr, "nodary components show: %v\n", err)
		return ExitFailure
	}
	if *format == "json" {
		return writeJSON(e, "components show", map[string]any{
			"source": src, "nodary_version": m.NodaryVersion,
			"components": len(m.Components),
		})
	}
	source := "embedded in this binary"
	if src.Applied {
		source = "an applied revision"
	}
	fmt.Fprintf(e.stdout, "revision %d (%s)\n", src.Revision, source)
	fmt.Fprintf(e.stdout, "floor    %d\n", src.Floor)
	fmt.Fprintf(e.stdout, "pins     %d component(s)\n", len(m.Components))
	if src.Why != "" {
		fmt.Fprintf(e.stderr, "\nA revision is present and not in force: %s\n", src.Why)
	}
	return ExitOK
}
