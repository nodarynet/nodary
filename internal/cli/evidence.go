package cli

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/nodarynet/nodary/ee/evidence"
	"github.com/nodarynet/nodary/ee/license"
	"github.com/nodarynet/nodary/internal/audit"
)

// members is what an unlicensed install prints instead of a bundle.
//
// docs/adr/0005: the commercial surface is discoverable, never hidden. A verb
// that is merely absent is discovered by a customer after they have chosen
// something else.
var members = []struct{ name, what string }{
	{evidence.MemberChain, "the audit segment for the period, anchored so it verifies standalone"},
	{evidence.MemberVerify, "what chain verification concluded, and how to repeat it without nodary"},
	{evidence.MemberControls, "practice to evidence index, machine-readable"},
	{evidence.MemberControlsMD, "the same index, for a human"},
	{evidence.MemberIdentity, "user and token lifecycle"},
	{evidence.MemberRevisions, "configuration revision history"},
	{evidence.MemberNodes, "node approvals with the inventory offered at approval"},
	{evidence.MemberRemediation, "what was known, decided, and applied"},
	{evidence.MemberManifest, "a digest of every member"},
	{evidence.MemberManifestSig, "that manifest, signed by this install"},
}

func cmdEvidence(e env, args []string) int {
	if len(args) == 0 {
		fmt.Fprintf(e.stderr, "nodary evidence: expected a subcommand (export)\n")
		return ExitUsage
	}
	if args[0] != "export" {
		fmt.Fprintf(e.stderr, "nodary evidence: unknown subcommand %q (want export)\n", args[0])
		return ExitUsage
	}
	return cmdEvidenceExport(e, args[1:])
}

func cmdEvidenceExport(e env, args []string) int {
	fs := newFlagSet(e, "evidence export")
	dbPath, keyPath, credsPath := stateFlags(fs)
	cer := attestFlags(fs)
	from := fs.String("from", "", "start of the reporting period (YYYY-MM-DD)")
	to := fs.String("to", "", "end of the reporting period (YYYY-MM-DD)")
	out := fs.String("out", "", "bundle to write")
	if code := parseFlags(e, fs, args); code >= 0 {
		return code
	}

	s, ok := openSession(e, "evidence export", *dbPath, *keyPath, *credsPath)
	if !ok {
		return ExitFailure
	}
	defer s.Close()

	// The license is checked before anything is rendered, so an unlicensed
	// install spends no time producing something it will not write.
	lic, err := license.Active(context.Background(), s.db.Read(), s.now)
	if err != nil {
		return reportUnlicensed(e, err)
	}
	if !lic.Covers(license.FeatureEvidence) {
		fmt.Fprintf(e.stderr, "nodary evidence export: this license does not cover evidence export.\n")
		return ExitPolicy
	}

	if *out == "" {
		fmt.Fprintf(e.stderr, "nodary evidence export: --out is required\n")
		return ExitUsage
	}
	start, end, ok := period(e, s.now, *from, *to)
	if !ok {
		return ExitUsage
	}

	var bundle *evidence.Bundle
	rec, applied, code := s.attested(e, "evidence export", change{
		action: "evidence.export",
		target: &audit.Target{Kind: "evidence", ID: filepath.Base(*out)},
		render: func(ctx context.Context, tx *sql.Tx) (any, error) {
			// What the bundle will cover, read from the chain rather than from
			// the flags: an export approved for a period that has since gained
			// records is a different document.
			var count int64
			var last int64
			if err := tx.QueryRowContext(ctx,
				`SELECT count(*), coalesce(max(seq), 0) FROM audit WHERE ts >= ? AND ts <= ?`,
				start.UTC().Format(audit.TimeFormat), end.UTC().Format(audit.TimeFormat),
			).Scan(&count, &last); err != nil {
				return nil, err
			}
			return map[string]any{
				"from": start.UTC().Format(time.DateOnly), "to": end.UTC().Format(time.DateOnly),
				"records": count, "last_seq": last, "customer": lic.Customer,
			}, nil
		},
		apply: func(m audit.Mutation, _ any) error {
			if err := s.touch(m); err != nil {
				return err
			}
			k, err := s.key()
			if err != nil {
				return err
			}
			install, err := audit.InstallID(context.Background(), s.db.Read())
			if err != nil {
				return err
			}
			bundle, err = evidence.Build(context.Background(), m, s.db, k, s.now,
				evidence.Options{From: start, To: end, Install: install})
			return err
		},
	}, cer, "text")
	if !applied {
		return code
	}

	// Written after the act commits: a bundle on disk that the chain does not
	// record is worse than a record with no bundle, because only one of the two
	// can be noticed.
	f, err := os.OpenFile(*out, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		fmt.Fprintf(e.stderr, "nodary evidence export: %v\n", err)
		return ExitFailure
	}
	if err := bundle.WriteTarGz(f, s.now); err != nil {
		f.Close()
		fmt.Fprintf(e.stderr, "nodary evidence export: %v\n", err)
		return ExitFailure
	}
	if err := f.Close(); err != nil {
		fmt.Fprintf(e.stderr, "nodary evidence export: %v\n", err)
		return ExitFailure
	}

	fmt.Fprintln(e.stdout, *out)
	fmt.Fprintf(e.stderr, "%d members, signed with evidence key %s.\n", len(bundle.Members), bundle.KeyID)
	fmt.Fprintf(e.stderr, "Verify it with: sha256sum -c manifest.sha256 && minisign -Vm manifest.json -p nodary-evidence.pub\n")
	reportRecord(e, rec)
	return ExitOK
}

// reportUnlicensed names every member the bundle would have held.
func reportUnlicensed(e env, err error) int {
	fmt.Fprintf(e.stderr, "nodary evidence export: %v\n\n", err)
	fmt.Fprintf(e.stderr, "A licensed install writes a signed tar.gz holding:\n")
	for _, m := range members {
		fmt.Fprintf(e.stderr, "  %-22s %s\n", m.name, m.what)
	}
	fmt.Fprintf(e.stderr, `
The bundle verifies with sha256sum and minisign alone, on a machine that has
never had nodary installed, and it keeps working after a license lapses.

The chain it is built from is not commercial: `+"`nodary audit export`"+` writes the
same records, unsigned and unindexed, and always will.
`)
	return ExitPolicy
}

// period resolves the reporting bounds, defaulting to the last 90 days.
func period(e env, now time.Time, from, to string) (time.Time, time.Time, bool) {
	start, end := now.AddDate(0, 0, -90), now
	var err error
	if from != "" {
		if start, err = time.Parse(time.DateOnly, from); err != nil {
			fmt.Fprintf(e.stderr, "nodary evidence export: --from %q is not YYYY-MM-DD\n", from)
			return time.Time{}, time.Time{}, false
		}
	}
	if to != "" {
		if end, err = time.Parse(time.DateOnly, to); err != nil {
			fmt.Fprintf(e.stderr, "nodary evidence export: --to %q is not YYYY-MM-DD\n", to)
			return time.Time{}, time.Time{}, false
		}
		end = end.Add(24*time.Hour - time.Nanosecond)
	}
	if end.Before(start) {
		fmt.Fprintf(e.stderr, "nodary evidence export: --to is before --from\n")
		return time.Time{}, time.Time{}, false
	}
	return start, end, true
}
