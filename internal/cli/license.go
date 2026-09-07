package cli

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/nodarynet/nodary/ee/license"
	"github.com/nodarynet/nodary/internal/audit"
)

func cmdLicense(e env, args []string) int {
	if len(args) == 0 {
		fmt.Fprintf(e.stderr, "nodary license: expected a subcommand (apply, show)\n")
		return ExitUsage
	}
	switch args[0] {
	case "apply":
		return cmdLicenseApply(e, args[1:])
	case "show":
		return cmdLicenseShow(e, args[1:])
	}
	fmt.Fprintf(e.stderr, "nodary license: unknown subcommand %q (want apply or show)\n", args[0])
	return ExitUsage
}

func cmdLicenseShow(e env, args []string) int {
	fs := newFlagSet(e, "license show")
	format := formatFlag(fs)
	dbPath := dbFlag(fs)
	if code := parseFlags(e, fs, args); code >= 0 {
		return code
	}
	if !checkFormat(e, *format) {
		return ExitUsage
	}

	path, _ := resolveDB(*dbPath)
	db, ok := openForReading(e, "license show", path)
	if !ok {
		return ExitFailure
	}
	defer db.Close()

	now := time.Now()
	lic, err := license.Active(context.Background(), db.Read(), now)
	if err != nil && !errors.Is(err, license.ErrExpired) {
		if *format == "json" {
			return writeJSON(e, "license show", map[string]any{"licensed": false, "detail": err.Error()})
		}
		// Not an error to report loudly: an unlicensed install is the normal
		// state of a community deployment, and everything it runs keeps running.
		fmt.Fprintf(e.stdout, "unlicensed\n")
		fmt.Fprintf(e.stderr, "%v\n", err)
		return ExitOK
	}

	expired := errors.Is(err, license.ErrExpired)
	if *format == "json" {
		return writeJSON(e, "license show", map[string]any{
			"licensed": !expired, "expired": expired, "customer": lic.Customer,
			"expires": lic.Expires, "features": lic.Features,
		})
	}
	state := "licensed"
	if expired {
		state = "expired"
	}
	fmt.Fprintf(e.stdout, "%s\t%s\t%s\n", state, lic.Customer, lic.Expires)
	if expired {
		fmt.Fprintf(e.stderr,
			"Evidence already exported stays readable and verifiable; see ee/LICENSE.\n")
	}
	return ExitOK
}

func cmdLicenseApply(e env, args []string) int {
	fs := newFlagSet(e, "license apply")
	dbPath, keyPath, credsPath := stateFlags(fs)
	cer := attestFlags(fs)
	sigPath := fs.String("signature", "", "detached signature (default: the licence path plus .minisig)")
	if code := parseFlags(e, fs, args); code >= 0 {
		return code
	}
	if fs.NArg() != 1 {
		fmt.Fprintf(e.stderr, "nodary license apply: expected one licence file\n")
		return ExitUsage
	}

	src, err := os.ReadFile(fs.Arg(0))
	if err != nil {
		fmt.Fprintf(e.stderr, "nodary license apply: %v\n", err)
		return ExitUsage
	}
	sp := *sigPath
	if sp == "" {
		sp = fs.Arg(0) + ".minisig"
	}
	sig, err := os.ReadFile(sp)
	if err != nil {
		fmt.Fprintf(e.stderr, "nodary license apply: %v\n", err)
		fmt.Fprintf(e.stderr, "  a licence is signed; pass --signature if it is not beside the file\n")
		return ExitUsage
	}

	s, ok := openSession(e, "license apply", *dbPath, *keyPath, *credsPath)
	if !ok {
		return ExitFailure
	}
	defer s.Close()

	var applied license.License
	rec, ok2, code := s.attested(e, "license apply", change{
		action: "license.apply",
		render: func(ctx context.Context, tx *sql.Tx) (any, error) {
			// Verified in the render, so an invalid licence is refused before
			// any ceremony is demanded rather than after it.
			l, err := license.Parse(string(src), string(sig), s.now)
			if err != nil {
				return nil, err
			}
			return map[string]any{
				"customer": l.Customer, "expires": l.Expires, "features": l.Features,
			}, nil
		},
		apply: func(m audit.Mutation, _ any) error {
			if err := s.touch(m); err != nil {
				return err
			}
			var err error
			applied, err = license.Apply(ctx(), m, s.who.Role, s.now, string(src), string(sig))
			return err
		},
	}, cer, "text")
	if !ok2 {
		return code
	}

	fmt.Fprintf(e.stdout, "%s\t%s\n", applied.Customer, applied.Expires)
	reportRecord(e, rec)
	return ExitOK
}

func ctx() context.Context { return context.Background() }
