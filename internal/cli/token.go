package cli

import (
	"context"
	"database/sql"
	"fmt"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/nodarynet/nodary/internal/attest"
	"github.com/nodarynet/nodary/internal/audit"
	"github.com/nodarynet/nodary/internal/identity"
	"github.com/nodarynet/nodary/internal/paths"
	"github.com/nodarynet/nodary/internal/policy"
)

func cmdToken(e env, args []string) int {
	if len(args) == 0 {
		fmt.Fprintf(e.stderr, "nodary token: expected a subcommand (create, list, revoke, join)\n")
		return ExitUsage
	}
	switch args[0] {
	case "create":
		return cmdTokenCreate(e, args[1:])
	case "list":
		return cmdTokenList(e, args[1:])
	case "revoke":
		return cmdTokenRevoke(e, args[1:])
	case "join":
		return cmdTokenJoin(e, args[1:])
	default:
		fmt.Fprintf(e.stderr,
			"nodary token: unknown subcommand %q (want create, list, revoke or join)\n", args[0])
		return ExitUsage
	}
}

// defaultLifetime per kind, from docs/specs/02-enrollment.md §4: a service key
// defaults to a year, a personal token is session-scoped or explicit — ninety
// days is the explicit default — and a join token lives minutes to hours.
var defaultLifetime = map[identity.Kind]time.Duration{
	identity.KindPersonal: 90 * 24 * time.Hour,
	identity.KindService:  365 * 24 * time.Hour,
	identity.KindJoin:     time.Hour,
}

// parseLifetime reads a duration, accepting days and the word "never".
//
// Go's own parser stops at hours, and every lifetime an operator thinks in is
// longer than that. "never" is spelled out rather than given as 0, because a
// credential that never expires should be typed deliberately.
func parseLifetime(s string) (time.Duration, error) {
	switch s {
	case "":
		return 0, fmt.Errorf("an empty lifetime is not a duration")
	case "never":
		return 0, nil
	}
	if days, ok := strings.CutSuffix(s, "d"); ok {
		n, err := strconv.Atoi(days)
		if err != nil || n < 0 {
			return 0, fmt.Errorf("%q is not a number of days", s)
		}
		return time.Duration(n) * 24 * time.Hour, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("%q is not a duration (try 30d, 12h, or never)", s)
	}
	if d < 0 {
		return 0, fmt.Errorf("%q is a negative lifetime", s)
	}
	return d, nil
}

// cmdTokenCreate mints a credential.
//
// It takes no --format. The plaintext goes to stdout on a line of its own and
// everything else to stderr, so `TOKEN=$(nodary token create --user alice)`
// captures exactly the credential — which is what docs/specs/10-cli.md §4 means
// by printed once, with no surrounding decoration. A JSON document on the same
// stream would either hide the secret from a script or put it in a shape that
// gets logged.
func cmdTokenCreate(e env, args []string) int {
	fs := newFlagSet(e, "token create")
	dbPath, keyPath, credsPath := stateFlags(fs)
	cer := attestFlags(fs)
	userName := fs.String("user", "", "the user the credential belongs to")
	kindName := fs.String("kind", string(identity.KindPersonal), "pt (personal) or sk (service)")
	label := fs.String("name", "", "a label, so this credential is identifiable later")
	lifetime := fs.String("expires", "", "lifetime: 90d, 12h, or never (default per kind)")
	save := fs.Bool("save", false, "also write it to the credentials file")
	unattended := fs.Bool("allow-unattended", false,
		"let this credential mutate with nobody present to re-authenticate")
	if code := parseFlags(e, fs, args); code >= 0 {
		return code
	}
	if len(fs.Args()) > 0 {
		fmt.Fprintf(e.stderr, "nodary token create: unexpected argument %q; the user is --user\n",
			fs.Args()[0])
		return ExitUsage
	}
	if *userName == "" {
		fmt.Fprintf(e.stderr, "nodary token create: --user is required\n")
		return ExitUsage
	}
	kind, err := identity.ParseKind(*kindName)
	if err != nil {
		fmt.Fprintf(e.stderr, "nodary token create: %v\n", err)
		return ExitUsage
	}
	if kind == identity.KindJoin {
		fmt.Fprintf(e.stderr,
			"nodary token create: a join token belongs to no user; use `nodary token join`\n")
		return ExitUsage
	}
	if *save && kind != identity.KindPersonal {
		fmt.Fprintf(e.stderr,
			"nodary token create: --save writes a personal token, and this is a %s\n", kind)
		return ExitUsage
	}

	s, ok := openSession(e, "token create", *dbPath, *keyPath, *credsPath)
	if !ok {
		return ExitFailure
	}
	defer s.Close()

	expires, ok := expiryAt(e, "token create", s.now, *lifetime, defaultLifetime[kind])
	if !ok {
		return ExitUsage
	}

	// R1-17: the grant is refused at the mint rather than at every later use,
	// because it is the whole route around re-authentication and a profile that
	// closes it must close it once.
	if *unattended {
		active, _, err := policy.Active(context.Background(), s.db.Read())
		if err != nil {
			fmt.Fprintf(e.stderr, "nodary token create: %v\n", err)
			return ExitFailure
		}
		if err := attest.AllowUnattendedMint(active); err != nil {
			fmt.Fprintf(e.stderr, "nodary token create: %v\n", err)
			return ExitPolicy
		}
	}

	var (
		tok   identity.Token
		plain string
	)
	rec, applied, code := s.attested(e, "token create", change{
		action: "token.create",
		render: func(ctx context.Context, tx *sql.Tx) (any, error) {
			// The user's state is read, not echoed: minting against somebody
			// who was suspended between preview and apply is exactly the move
			// docs/specs/07-identity-audit.md §3 refuses.
			u, err := identity.Get(ctx, tx, *userName)
			if err != nil {
				return nil, err
			}
			return map[string]any{
				"user": u.Name, "user_state": string(u.State), "kind": string(kind),
				"name": *label, "expires": formatTime(expires), "unattended": *unattended,
			}, nil
		},
		apply: func(m audit.Mutation, _ any) error {
			if err := s.touch(m); err != nil {
				return err
			}
			var err error
			tok, plain, err = identity.MintToken(context.Background(), m, s.who.Role, s.now,
				*userName, kind, *label, expires, *unattended)
			return err
		},
	}, cer, "text")
	if !applied {
		return code
	}

	fmt.Fprintln(e.stdout, plain)
	fmt.Fprintf(e.stderr, "%s for %s, id %s, expires %s.\n",
		kind, *userName, tok.ID, formatTime(tok.ExpiresAt))
	fmt.Fprintf(e.stderr, "This is shown once and is stored only as a hash.\n")
	if tok.Unattended {
		fmt.Fprintf(e.stderr,
			"This credential may mutate unattended; the grant is audit record %d.\n", rec.Seq)
	}
	reportRecord(e, rec)

	if *save {
		path := *credsPath
		if path == "" {
			if path, err = paths.Credentials(); err != nil {
				fmt.Fprintf(e.stderr, "nodary token create: %v\n", err)
				return ExitFailure
			}
		}
		creds, err := identity.LoadCredentials(path)
		if err != nil {
			fmt.Fprintf(e.stderr, "nodary token create: %v\n", err)
			return ExitFailure
		}
		creds.Set(identity.LocalServer, identity.Credential{Token: plain, User: *userName})
		if err := creds.Save(path); err != nil {
			fmt.Fprintf(e.stderr, "nodary token create: %v\n", err)
			return ExitFailure
		}
		fmt.Fprintf(e.stderr, "Saved to %s.\n", path)
	}
	return ExitOK
}

func cmdTokenJoin(e env, args []string) int {
	fs := newFlagSet(e, "token join")
	dbPath, keyPath, credsPath := stateFlags(fs)
	cer := attestFlags(fs)
	format := formatFlag(fs)
	uses := fs.Int("uses", 1, "how many nodes may enroll with it")
	lifetime := fs.String("expires", "", "lifetime: 2h, 30m (default 1h)")
	if code := parseFlags(e, fs, args); code >= 0 {
		return code
	}
	if !checkFormat(e, *format) {
		return ExitUsage
	}

	s, ok := openSession(e, "token join", *dbPath, *keyPath, *credsPath)
	if !ok {
		return ExitFailure
	}
	defer s.Close()

	expires, ok := expiryAt(e, "token join", s.now, *lifetime, defaultLifetime[identity.KindJoin])
	if !ok {
		return ExitUsage
	}
	if expires.IsZero() {
		fmt.Fprintf(e.stderr,
			"nodary token join: a join token must expire; `never` enrolls anybody, forever\n")
		return ExitUsage
	}

	var (
		j     identity.JoinToken
		plain string
	)
	// Through core.Act like every other mutation, and not s.log.Act directly.
	//
	// This verb mints the credential that gets a machine onto the fleet, and it
	// was the one mutating verb in the CLI with no attestation at all: no
	// preview, no intent hash, no confirmation, and no way to supply a TOTP
	// code under a profile that requires one. The API's POST /tokens/join has
	// always gone through core.Act, so the two front ends disagreed about what
	// this costs — which is precisely the divergence
	// docs/plans/R2c-api-core.md exists to prevent, on the act where it matters
	// most.
	rec, applied, code := s.attested(e, "token join", change{
		action: "token.join",
		render: func(ctx context.Context, tx *sql.Tx) (any, error) {
			return map[string]any{"kind": string(identity.KindJoin), "uses": *uses,
				"expires": formatTime(expires)}, nil
		},
		apply: func(m audit.Mutation, _ any) error {
			if err := s.touch(m); err != nil {
				return err
			}
			var err error
			j, plain, err = identity.MintJoinToken(context.Background(), m, s.who.Role, s.now,
				s.who.Actor.ID, *uses, expires)
			return err
		},
	}, cer, *format)
	if !applied {
		return code
	}

	fmt.Fprintln(e.stdout, plain)
	fmt.Fprintf(e.stderr, "join token %s, %d use(s), expires %s.\n",
		j.ID, j.UsesLeft, formatTime(j.ExpiresAt))
	fmt.Fprintf(e.stderr, "This is shown once and is stored only as a hash.\n")
	reportRecord(e, rec)
	return ExitOK
}

func cmdTokenRevoke(e env, args []string) int {
	fs := newFlagSet(e, "token revoke")
	format := formatFlag(fs)
	dbPath, keyPath, credsPath := stateFlags(fs)
	cer := attestFlags(fs)
	if code := parseFlags(e, fs, args); code >= 0 {
		return code
	}
	if !checkFormat(e, *format) {
		return ExitUsage
	}
	rest := fs.Args()
	if len(rest) != 1 {
		fmt.Fprintf(e.stderr, "nodary token revoke: expected one token id\n")
		return ExitUsage
	}

	s, ok := openSession(e, "token revoke", *dbPath, *keyPath, *credsPath)
	if !ok {
		return ExitFailure
	}
	defer s.Close()

	var tok identity.Token
	rec, applied, code := s.attested(e, "token revoke", change{
		action: "token.revoke",
		render: func(ctx context.Context, tx *sql.Tx) (any, error) {
			// Whether it is already revoked is the moving part: revoking twice
			// should refuse rather than report a revocation that happened when
			// somebody else did it.
			before, err := identity.TokenByID(ctx, tx, rest[0])
			if err != nil {
				return nil, err
			}
			return map[string]any{
				"token": before.ID, "kind": string(before.Kind),
				"prefix": before.Prefix, "already_revoked": before.Revoked(),
			}, nil
		},
		apply: func(m audit.Mutation, _ any) error {
			if err := s.touch(m); err != nil {
				return err
			}
			var err error
			tok, err = identity.RevokeToken(context.Background(), m, s.who.Role, s.now, rest[0])
			return err
		},
	}, cer, *format)
	if !applied {
		return code
	}

	if *format == "json" {
		return writeJSON(e, "token revoke", map[string]any{
			"token": newTokenReport(tok),
			"seq":   rec.Seq,
		})
	}
	fmt.Fprintf(e.stdout, "%s\trevoked\t%s\n", tok.ID, formatTime(tok.RevokedAt))
	reportRecord(e, rec)
	return ExitOK
}

func cmdTokenList(e env, args []string) int {
	fs := newFlagSet(e, "token list")
	format := formatFlag(fs)
	dbPath := dbFlag(fs)
	userName := fs.String("user", "", "only this user's credentials")
	if code := parseFlags(e, fs, args); code >= 0 {
		return code
	}
	if !checkFormat(e, *format) {
		return ExitUsage
	}

	path, _ := resolveDB(*dbPath)
	db, ok := openForReading(e, "token list", path)
	if !ok {
		return ExitFailure
	}
	defer db.Close()

	ctx := context.Background()
	userID := ""
	if *userName != "" {
		u, err := identity.Get(ctx, db.Read(), *userName)
		if err != nil {
			fmt.Fprintf(e.stderr, "nodary token list: %v\n", err)
			return exitFor(err)
		}
		userID = u.ID
	}

	tokens, err := identity.ListTokens(ctx, db.Read(), userID)
	if err != nil {
		fmt.Fprintf(e.stderr, "nodary token list: %v\n", err)
		return ExitFailure
	}
	joins, err := identity.ListJoinTokens(ctx, db.Read())
	if err != nil {
		fmt.Fprintf(e.stderr, "nodary token list: %v\n", err)
		return ExitFailure
	}
	if userID != "" {
		// A join token belongs to nobody, so filtering by user excludes them
		// rather than showing every operator the whole enrollment set.
		joins = nil
	}

	if *format == "json" {
		return writeJSON(e, "token list", map[string]any{
			"tokens":      tokenReports(tokens),
			"join_tokens": joinReports(joins),
		})
	}

	tw := tabwriter.NewWriter(e.stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tKIND\tPREFIX\tNAME\tSTATE\tLAST USED\tEXPIRES")
	for _, t := range tokens {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			t.ID, t.Kind, t.Prefix, orDash(t.Name), tokenState(t, time.Now()),
			formatTime(t.LastUsedAt), formatTime(t.ExpiresAt))
	}
	for _, j := range joins {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%d use(s)\t%s\t%s\n",
			j.ID, identity.KindJoin, j.Prefix, "-", j.UsesLeft, "-", formatTime(j.ExpiresAt))
	}
	return flush(e, "token list", tw)
}

// expiryAt turns a lifetime into an instant, applying the per-kind default.
func expiryAt(e env, verb string, now time.Time, lifetime string,
	fallback time.Duration) (time.Time, bool) {
	d := fallback
	if lifetime != "" {
		var err error
		if d, err = parseLifetime(lifetime); err != nil {
			fmt.Fprintf(e.stderr, "nodary %s: --expires %v\n", verb, err)
			return time.Time{}, false
		}
	}
	if d == 0 {
		return time.Time{}, true
	}
	return now.Add(d), true
}

// tokenState says why a credential does or does not work, in one word.
func tokenState(t identity.Token, now time.Time) string {
	switch {
	case t.Revoked():
		return "revoked"
	case t.Expired(now):
		return "expired"
	}
	return "active"
}

// tokenReport is the stable shape of a credential in --format json. There is no
// field for the secret: docs/specs/10-cli.md §4 keeps one out of every list.
type tokenReport struct {
	ID         string `json:"id"`
	UserID     string `json:"user_id"`
	Kind       string `json:"kind"`
	Prefix     string `json:"prefix"`
	Name       string `json:"name,omitempty"`
	State      string `json:"state"`
	ExpiresAt  string `json:"expires_at,omitempty"`
	RevokedAt  string `json:"revoked_at,omitempty"`
	LastUsedAt string `json:"last_used_at,omitempty"`
	CreatedAt  string `json:"created_at"`
}

func newTokenReport(t identity.Token) tokenReport {
	r := tokenReport{
		ID:        t.ID,
		UserID:    t.UserID,
		Kind:      string(t.Kind),
		Prefix:    t.Prefix,
		Name:      t.Name,
		State:     tokenState(t, time.Now()),
		CreatedAt: t.CreatedAt.Format(audit.TimeFormat),
	}
	for _, f := range []struct {
		at  time.Time
		out *string
	}{{t.ExpiresAt, &r.ExpiresAt}, {t.RevokedAt, &r.RevokedAt}, {t.LastUsedAt, &r.LastUsedAt}} {
		if !f.at.IsZero() {
			*f.out = f.at.Format(audit.TimeFormat)
		}
	}
	return r
}

func tokenReports(ts []identity.Token) []tokenReport {
	out := make([]tokenReport, len(ts))
	for i, t := range ts {
		out[i] = newTokenReport(t)
	}
	return out
}

// joinReport is the stable shape of a join token in --format json.
type joinReport struct {
	ID        string `json:"id"`
	Prefix    string `json:"prefix"`
	UsesLeft  int    `json:"uses_left"`
	ExpiresAt string `json:"expires_at"`
	CreatedBy string `json:"created_by"`
	CreatedAt string `json:"created_at"`
}

func joinReports(js []identity.JoinToken) []joinReport {
	out := make([]joinReport, len(js))
	for i, j := range js {
		out[i] = joinReport{
			ID:        j.ID,
			Prefix:    j.Prefix,
			UsesLeft:  j.UsesLeft,
			ExpiresAt: j.ExpiresAt.Format(audit.TimeFormat),
			CreatedBy: j.CreatedBy,
			CreatedAt: j.CreatedAt.Format(audit.TimeFormat),
		}
	}
	return out
}
