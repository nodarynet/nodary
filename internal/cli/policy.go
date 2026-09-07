package cli

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"slices"
	"strings"

	"github.com/nodarynet/nodary/internal/audit"
	"github.com/nodarynet/nodary/internal/policy"
	"github.com/nodarynet/nodary/internal/store"
)

func cmdPolicy(e env, args []string) int {
	if len(args) == 0 {
		fmt.Fprintf(e.stderr, "nodary policy: expected a subcommand (show, apply, diff)\n")
		return ExitUsage
	}
	switch args[0] {
	case "show":
		return cmdPolicyShow(e, args[1:])
	case "apply":
		return cmdPolicyApply(e, args[1:])
	case "diff":
		return cmdPolicyDiff(e, args[1:])
	}
	fmt.Fprintf(e.stderr, "nodary policy: unknown subcommand %q (want show, apply or diff)\n", args[0])
	return ExitUsage
}

// loadCandidate resolves a profile argument, which is either the name of a
// built-in profile or a path to a TOML file.
//
// Names win over paths. A file called `regulated` in the working directory
// silently displacing the shipped profile is the kind of surprise a posture
// object must not have, and `./regulated` still reaches the file.
func loadCandidate(e env, verb, arg string) (policy.Profile, []byte, bool) {
	if slices.Contains(policy.BuiltinNames(), arg) {
		p, src, err := policy.Builtin(arg)
		if err != nil {
			fmt.Fprintf(e.stderr, "nodary %s: %v\n", verb, err)
			return policy.Profile{}, nil, false
		}
		return p, src, true
	}

	src, err := os.ReadFile(arg)
	if err != nil {
		fmt.Fprintf(e.stderr, "nodary %s: %v\n", verb, err)
		fmt.Fprintf(e.stderr, "  expected a built-in profile (%s) or a path to a TOML file\n",
			strings.Join(policy.BuiltinNames(), ", "))
		return policy.Profile{}, nil, false
	}
	p, err := policy.Parse(src)
	if err != nil {
		fmt.Fprintf(e.stderr, "nodary %s: %v\n", verb, err)
		return policy.Profile{}, nil, false
	}
	return p, src, true
}

// activeProfile reads the profile in force without opening the database for
// writing, so `show` and `diff` work against a read-only copy.
func activeProfile(e env, verb, dbPath string) (policy.Profile, bool) {
	db, err := store.OpenReadOnly(context.Background(), dbPath)
	if err != nil {
		fmt.Fprintf(e.stderr, "nodary %s: %v\n", verb, err)
		return policy.Profile{}, false
	}
	defer db.Close()

	p, _, err := policy.Active(context.Background(), db.Read())
	if err != nil {
		fmt.Fprintf(e.stderr, "nodary %s: %v\n", verb, err)
		return policy.Profile{}, false
	}
	return p, true
}

func cmdPolicyShow(e env, args []string) int {
	fs := newFlagSet(e, "policy show")
	format := formatFlag(fs)
	dbPath, _, _ := stateFlags(fs)
	if code := parseFlags(e, fs, args); code >= 0 {
		return code
	}
	if !checkFormat(e, *format) {
		return ExitUsage
	}

	p, ok := activeProfile(e, "policy show", *dbPath)
	if !ok {
		return ExitFailure
	}

	if *format == "json" {
		return writeJSON(e, "policy show", p)
	}
	fmt.Fprintf(e.stdout, "%s\n", p.Name)
	for _, l := range policy.Describe(p) {
		fmt.Fprintf(e.stdout, "  %s\n", l)
	}
	return ExitOK
}

func cmdPolicyDiff(e env, args []string) int {
	fs := newFlagSet(e, "policy diff")
	format := formatFlag(fs)
	dbPath, _, _ := stateFlags(fs)
	if code := parseFlags(e, fs, args); code >= 0 {
		return code
	}
	if !checkFormat(e, *format) {
		return ExitUsage
	}
	if fs.NArg() != 1 {
		fmt.Fprintf(e.stderr, "nodary policy diff: expected one profile (a built-in name or a TOML file)\n")
		return ExitUsage
	}

	active, ok := activeProfile(e, "policy diff", *dbPath)
	if !ok {
		return ExitFailure
	}
	candidate, _, ok := loadCandidate(e, "policy diff", fs.Arg(0))
	if !ok {
		return ExitUsage
	}

	changes := policy.Diff(active, candidate)
	if *format == "json" {
		return writeJSON(e, "policy diff", map[string]any{
			"active": active.Name, "candidate": candidate.Name,
			"changes": changes, "loosens": policy.Loosens(changes),
		})
	}
	if len(changes) == 0 {
		fmt.Fprintf(e.stdout, "no change: %s and %s are identical\n", active.Name, candidate.Name)
		return ExitOK
	}
	fmt.Fprintf(e.stdout, "%s -> %s\n", active.Name, candidate.Name)
	for _, c := range changes {
		fmt.Fprintf(e.stdout, "  %s\n", c)
	}
	if policy.Loosens(changes) {
		fmt.Fprintf(e.stderr, "\nthis profile loosens the posture; the lines marked (loosens) say where\n")
	}
	return ExitOK
}

func cmdPolicyApply(e env, args []string) int {
	fs := newFlagSet(e, "policy apply")
	format := formatFlag(fs)
	dbPath, keyPath, credsPath := stateFlags(fs)
	cer := attestFlags(fs)
	if code := parseFlags(e, fs, args); code >= 0 {
		return code
	}
	if !checkFormat(e, *format) {
		return ExitUsage
	}
	if fs.NArg() != 1 {
		fmt.Fprintf(e.stderr, "nodary policy apply: expected one profile (a built-in name or a TOML file)\n")
		return ExitUsage
	}

	candidate, source, ok := loadCandidate(e, "policy apply", fs.Arg(0))
	if !ok {
		return ExitUsage
	}

	s, ok := openSession(e, "policy apply", *dbPath, *keyPath, *credsPath)
	if !ok {
		return ExitFailure
	}
	defer s.Close()

	active, _, err := policy.Active(context.Background(), s.db.Read())
	if err != nil {
		fmt.Fprintf(e.stderr, "nodary policy apply: %v\n", err)
		return ExitFailure
	}

	// 07 §4: loosening is permitted; doing it silently is not. The report goes
	// to stderr before the change, so it is visible even when stdout is being
	// parsed as JSON.
	changes := policy.Diff(active, candidate)
	for _, c := range changes {
		if c.Loosens {
			fmt.Fprintf(e.stderr, "loosens: %s\n", c)
		}
	}

	rec, applied, code := s.attested(e, "policy apply", change{
		action: "policy.apply",
		target: &audit.Target{Kind: "policy", ID: candidate.Name},
		render: func(ctx context.Context, tx *sql.Tx) (any, error) {
			// The diff, not the candidate: the posture this replaces is what
			// moves if another administrator applies something in between, and
			// an operator who approved "regulated over default" did not approve
			// "regulated over whatever is there now".
			from, _, err := policy.Active(ctx, tx)
			if err != nil {
				return nil, err
			}
			d := policy.Diff(from, candidate)
			lines := make([]string, len(d))
			for i, c := range d {
				lines[i] = c.String()
			}
			return map[string]any{"from": from.Name, "to": candidate.Name, "changes": lines}, nil
		},
		apply: func(m audit.Mutation, _ any) error {
			if err := s.touch(m); err != nil {
				return err
			}
			return policy.Apply(context.Background(), m, s.who.Role, s.now, candidate, source)
		},
	}, cer, *format)
	if !applied {
		return code
	}

	if *format == "json" {
		return writeJSON(e, "policy apply", map[string]any{
			"profile": candidate.Name, "changes": changes,
			"loosens": policy.Loosens(changes), "record": rec.Seq,
		})
	}
	fmt.Fprintf(e.stdout, "applied %s (%d %s)\n", candidate.Name,
		len(changes), plural("change", len(changes)))
	fmt.Fprintf(e.stderr, "recorded as audit record %d\n", rec.Seq)
	return ExitOK
}

func plural(word string, n int) string {
	if n == 1 {
		return word
	}
	return word + "s"
}
