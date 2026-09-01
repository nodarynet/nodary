package cli

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/nodarynet/nodary/internal/audit"
	"github.com/nodarynet/nodary/internal/identity"
)

func cmdUser(e env, args []string) int {
	if len(args) == 0 {
		fmt.Fprintf(e.stderr,
			"nodary user: expected a subcommand (add, list, show, suspend, delete, totp)\n")
		return ExitUsage
	}
	switch args[0] {
	case "add":
		return cmdUserAdd(e, args[1:])
	case "list":
		return cmdUserList(e, args[1:])
	case "show":
		return cmdUserShow(e, args[1:])
	case "suspend":
		return cmdUserState(e, "suspend", args[1:])
	case "delete":
		return cmdUserState(e, "delete", args[1:])
	case "totp":
		return cmdUserTOTP(e, args[1:])
	case "passwd":
		// docs/specs/10-cli.md §1 lists it. Nothing in R1 reads a password
		// hash: the CLI authenticates with a personal token and the only
		// consumer is R2's login endpoint, so the hashing lands there rather
		// than being written here against no call site.
		fmt.Fprintf(e.stderr,
			"nodary user passwd: passwords are not in this release (%s).\n"+
				"  R1 authenticates with personal tokens: see `nodary token create`.\n",
			versionString())
		return ExitFailure
	default:
		fmt.Fprintf(e.stderr,
			"nodary user: unknown subcommand %q "+
				"(want add, list, show, suspend, delete or totp)\n", args[0])
		return ExitUsage
	}
}

// oneName reads the single positional argument these verbs take.
func oneName(e env, verb string, fs interface{ Args() []string }) (string, bool) {
	rest := fs.Args()
	switch {
	case len(rest) == 0:
		fmt.Fprintf(e.stderr, "nodary %s: expected a user name\n", verb)
		return "", false
	case len(rest) > 1:
		fmt.Fprintf(e.stderr, "nodary %s: expected one user name, got %d\n", verb, len(rest))
		return "", false
	}
	return rest[0], true
}

func cmdUserAdd(e env, args []string) int {
	fs := newFlagSet(e, "user add")
	format := formatFlag(fs)
	dbPath, keyPath, credsPath := stateFlags(fs)
	justify := justifyFlag(fs)
	role := fs.String("role", string(identity.RoleViewer), "role: "+identity.JoinRoles())
	email := fs.String("email", "", "email address, recorded and not validated")
	if code := parseFlags(e, fs, args); code >= 0 {
		return code
	}
	if !checkFormat(e, *format) {
		return ExitUsage
	}
	name, ok := oneName(e, "user add", fs)
	if !ok {
		return ExitUsage
	}
	wanted, err := identity.ParseRole(*role)
	if err != nil {
		fmt.Fprintf(e.stderr, "nodary user add: %v\n", err)
		return ExitUsage
	}

	s, ok := openSession(e, "user add", *dbPath, *keyPath, *credsPath)
	if !ok {
		return ExitFailure
	}
	defer s.Close()

	var created identity.User
	rec, err := s.log.Act(context.Background(),
		s.request("user.add", nil, *justify),
		func(m audit.Mutation) error {
			if err := s.touch(m); err != nil {
				return err
			}
			var err error
			created, err = identity.Add(context.Background(), m, s.who.Role, s.now,
				name, *email, wanted)
			return err
		})
	if err != nil {
		return reportActFailure(e, "user add", rec, err)
	}
	return writeUser(e, *format, created, rec)
}

func cmdUserState(e env, verb string, args []string) int {
	fs := newFlagSet(e, "user "+verb)
	format := formatFlag(fs)
	dbPath, keyPath, credsPath := stateFlags(fs)
	justify := justifyFlag(fs)
	if code := parseFlags(e, fs, args); code >= 0 {
		return code
	}
	if !checkFormat(e, *format) {
		return ExitUsage
	}
	name, ok := oneName(e, "user "+verb, fs)
	if !ok {
		return ExitUsage
	}

	s, ok := openSession(e, "user "+verb, *dbPath, *keyPath, *credsPath)
	if !ok {
		return ExitFailure
	}
	defer s.Close()

	change := identity.Suspend
	if verb == "delete" {
		change = identity.Delete
	}
	var after identity.User
	rec, err := s.log.Act(context.Background(),
		s.request("user."+verb, nil, *justify),
		func(m audit.Mutation) error {
			if err := s.touch(m); err != nil {
				return err
			}
			var err error
			after, err = change(context.Background(), m, s.who.Role, s.now, name)
			return err
		})
	if err != nil {
		return reportActFailure(e, "user "+verb, rec, err)
	}
	return writeUser(e, *format, after, rec)
}

func cmdUserList(e env, args []string) int {
	fs := newFlagSet(e, "user list")
	format := formatFlag(fs)
	dbPath := dbFlag(fs)
	all := fs.Bool("all", false, "include deleted users")
	if code := parseFlags(e, fs, args); code >= 0 {
		return code
	}
	if !checkFormat(e, *format) {
		return ExitUsage
	}

	path, _ := resolveDB(*dbPath)
	db, ok := openForReading(e, "user list", path)
	if !ok {
		return ExitFailure
	}
	defer db.Close()

	users, err := identity.List(context.Background(), db.Read(), *all)
	if err != nil {
		fmt.Fprintf(e.stderr, "nodary user list: %v\n", err)
		return ExitFailure
	}

	reports := make([]userReport, len(users))
	for i, u := range users {
		reports[i] = newUserReport(u)
	}
	if *format == "json" {
		return writeJSON(e, "user list", map[string]any{"users": reports})
	}

	tw := tabwriter.NewWriter(e.stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "NAME\tROLE\tSTATE\tTOTP\tCREATED")
	for _, u := range reports {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n",
			u.Name, u.Role, u.State, yesNo(u.TOTPEnrolled), u.CreatedAt)
	}
	return flush(e, "user list", tw)
}

func cmdUserShow(e env, args []string) int {
	fs := newFlagSet(e, "user show")
	format := formatFlag(fs)
	dbPath := dbFlag(fs)
	if code := parseFlags(e, fs, args); code >= 0 {
		return code
	}
	if !checkFormat(e, *format) {
		return ExitUsage
	}
	name, ok := oneName(e, "user show", fs)
	if !ok {
		return ExitUsage
	}

	path, _ := resolveDB(*dbPath)
	db, ok := openForReading(e, "user show", path)
	if !ok {
		return ExitFailure
	}
	defer db.Close()

	u, err := identity.Get(context.Background(), db.Read(), name)
	if err != nil {
		fmt.Fprintf(e.stderr, "nodary user show: %v\n", err)
		return exitFor(err)
	}
	tokens, err := identity.ListTokens(context.Background(), db.Read(), u.ID)
	if err != nil {
		fmt.Fprintf(e.stderr, "nodary user show: %v\n", err)
		return ExitFailure
	}

	report := newUserReport(u)
	if *format == "json" {
		return writeJSON(e, "user show", map[string]any{
			"user":   report,
			"tokens": tokenReports(tokens),
		})
	}

	tw := tabwriter.NewWriter(e.stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintf(tw, "id\t%s\n", report.ID)
	fmt.Fprintf(tw, "name\t%s\n", report.Name)
	fmt.Fprintf(tw, "email\t%s\n", orDash(report.Email))
	fmt.Fprintf(tw, "role\t%s\n", report.Role)
	fmt.Fprintf(tw, "state\t%s\n", report.State)
	fmt.Fprintf(tw, "totp\t%s\n", yesNo(report.TOTPEnrolled))
	fmt.Fprintf(tw, "created\t%s\n", report.CreatedAt)
	fmt.Fprintf(tw, "tokens\t%d\n", len(tokens))
	return flush(e, "user show", tw)
}

// cmdUserTOTP enrolls a user, in one command that confirms before it commits.
//
// The seed goes to stdout alone and everything else to stderr, so capturing
// stdout yields exactly the secret and nothing to strip
// (docs/specs/10-cli.md §4). The provisioning URI carries the same secret and
// is the human-facing form, which is why it is on the human-facing stream.
func cmdUserTOTP(e env, args []string) int {
	fs := newFlagSet(e, "user totp")
	dbPath, keyPath, credsPath := stateFlags(fs)
	justify := justifyFlag(fs)
	if code := parseFlags(e, fs, args); code >= 0 {
		return code
	}
	name, ok := oneName(e, "user totp", fs)
	if !ok {
		return ExitUsage
	}

	s, ok := openSession(e, "user totp", *dbPath, *keyPath, *credsPath)
	if !ok {
		return ExitFailure
	}
	defer s.Close()

	key, err := s.key()
	if err != nil {
		fmt.Fprintf(e.stderr, "nodary user totp: %v\n", err)
		return ExitFailure
	}
	seed, err := identity.NewSeed()
	if err != nil {
		fmt.Fprintf(e.stderr, "nodary user totp: %v\n", err)
		return ExitFailure
	}

	fmt.Fprintln(e.stdout, identity.EncodeSeed(seed))
	fmt.Fprintf(e.stderr, "\nScan or paste this into an authenticator:\n  %s\n\n",
		identity.URI(identity.Issuer, name, seed))
	fmt.Fprintf(e.stderr, "This seed is shown once and cannot be read back.\n")
	fmt.Fprintf(e.stderr, "Enter the code it now shows: ")

	code, err := bufio.NewReader(e.stdin).ReadString('\n')
	if err != nil && code == "" {
		fmt.Fprintf(e.stderr, "\nnodary user totp: no code was entered; nothing was changed\n")
		return ExitUsage
	}
	code = strings.TrimSpace(code)

	rec, err := s.log.Act(context.Background(),
		s.request("user.totp", nil, *justify),
		func(m audit.Mutation) error {
			if err := s.touch(m); err != nil {
				return err
			}
			_, err := identity.Enroll(context.Background(), m, s.who.Role, s.now, key,
				name, seed, code)
			return err
		})
	if err != nil {
		fmt.Fprintf(e.stderr, "\nnodary user totp: %v\n", err)
		if errors.Is(err, identity.ErrBadCode) {
			fmt.Fprintf(e.stderr,
				"  nothing was enrolled. Check the clock on both machines and try again.\n")
		}
		reportRecord(e, rec)
		return exitFor(err)
	}
	fmt.Fprintf(e.stderr, "\nEnrolled %s. Recorded as audit record %d.\n", name, rec.Seq)
	return ExitOK
}

// userReport is the stable shape of a user in --format json. It holds nothing
// sealed, which is the property worth stating: a display struct that gains a
// secret is how one reaches a log.
type userReport struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	Email        string `json:"email,omitempty"`
	Role         string `json:"role"`
	State        string `json:"state"`
	TOTPEnrolled bool   `json:"totp_enrolled"`
	CreatedAt    string `json:"created_at"`
}

func newUserReport(u identity.User) userReport {
	return userReport{
		ID:           u.ID,
		Name:         u.Name,
		Email:        u.Email,
		Role:         string(u.Role),
		State:        string(u.State),
		TOTPEnrolled: u.TOTPEnrolled,
		CreatedAt:    u.CreatedAt.Format(audit.TimeFormat),
	}
}

// writeUser reports one changed user and the record that change produced.
func writeUser(e env, format string, u identity.User, rec audit.Record) int {
	if format == "json" {
		return writeJSON(e, "user", map[string]any{
			"user": newUserReport(u),
			"seq":  rec.Seq,
		})
	}
	fmt.Fprintf(e.stdout, "%s\t%s\t%s\n", u.Name, u.Role, u.State)
	reportRecord(e, rec)
	return ExitOK
}

// reportRecord names the audit record an action produced, on stderr: it is
// progress information, not the output of the command.
func reportRecord(e env, rec audit.Record) {
	if rec.Seq == 0 {
		return
	}
	fmt.Fprintf(e.stderr, "audit record %d\n", rec.Seq)
}

// reportActFailure prints why a mutation failed and returns its exit code.
//
// The record is named even on failure, because a refusal is recorded too and an
// operator disputing one needs the sequence number to point at.
func reportActFailure(e env, verb string, rec audit.Record, err error) int {
	fmt.Fprintf(e.stderr, "nodary %s: %v\n", verb, err)
	reportRecord(e, rec)
	return exitFor(err)
}

// stateFlags registers the three "where does the state live" flags together, so
// no verb can offer one and forget another.
func stateFlags(fs *flag.FlagSet) (db, key, creds *string) {
	return dbFlag(fs), keyFlag(fs), credentialsFlag(fs)
}

func writeJSON(e env, verb string, doc any) int {
	enc := json.NewEncoder(e.stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(doc); err != nil {
		fmt.Fprintf(e.stderr, "nodary %s: %v\n", verb, err)
		return ExitFailure
	}
	return ExitOK
}

func flush(e env, verb string, tw *tabwriter.Writer) int {
	if err := tw.Flush(); err != nil {
		fmt.Fprintf(e.stderr, "nodary %s: %v\n", verb, err)
		return ExitFailure
	}
	return ExitOK
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

// formatTime renders a time for display, or "-" when unset.
func formatTime(t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	return t.Format(audit.TimeFormat)
}
