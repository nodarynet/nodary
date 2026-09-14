package cli

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/nodarynet/nodary/internal/attest"
	"github.com/nodarynet/nodary/internal/audit"
	"github.com/nodarynet/nodary/internal/config"
	"github.com/nodarynet/nodary/internal/identity"
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
	server := serverFlag(fs)
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

	r, code := remoteFor(e, "token create", *server, *credsPath, *dbPath, *keyPath)
	if code >= 0 {
		return code
	}
	if r != nil {
		// The lifetime travels as the operator wrote it, not as an instant
		// this machine computed: the control plane holds the profile that caps
		// it, and it parses the string with the same parser this verb does.
		out, applied, code := r.attested(e, "token create",
			remoteAct{method: "POST", path: "/tokens", body: map[string]any{
				"user": *userName, "kind": string(kind), "name": *label,
				"lifetime": *lifetime, "unattended": *unattended}}, cer, "text")
		if !applied {
			return code
		}
		plain, _ := out.Result["token"].(string)
		var minted identity.TokenReport
		if raw, err := json.Marshal(out.Result["credential"]); err == nil {
			_ = json.Unmarshal(raw, &minted)
		}
		reportMinted(e, plain, minted, *userName, audit.Record{Seq: out.AuditSeq})
		if kind == identity.KindService {
			fmt.Fprintf(e.stderr,
				"\nA service key may call only the routes it is granted; `nodary limits show`\n"+
					"and the route grants are on the control plane.\n")
		}
		if *save {
			return saveCredential(e, "token create", *credsPath, r.base, *userName, plain)
		}
		return ExitOK
	}

	s, ok := openSession(e, "token create", *dbPath, *keyPath, *credsPath)
	if !ok {
		return ExitFailure
	}
	defer s.Close()

	expires, ok := expiryAt(e, "token create", s.now, kind, *lifetime)
	if !ok {
		return ExitUsage
	}

	// The profile bounds two things about a credential, and both are decided
	// here rather than at every later use: how long it may live, and whether it
	// may act with nobody present. R1-17 is the second; the first was specified
	// alongside it and went unread until an adoption review minted a ten-year
	// service key under a profile capping them at one.
	active, _, err := policy.Active(context.Background(), s.db.Read())
	if err != nil {
		fmt.Fprintf(e.stderr, "nodary token create: %v\n", err)
		return ExitFailure
	}
	if err := attest.AllowTokenLifetime(active, s.now, expires); err != nil {
		fmt.Fprintf(e.stderr, "nodary token create: %v\n", err)
		return ExitPolicy
	}
	if *unattended {
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

	reportMinted(e, plain, identity.NewTokenReport(tok, s.now), *userName, rec)
	if kind == identity.KindService {
		reportRouteAccess(e, s, *userName)
	}
	if *save {
		return saveCredential(e, "token create", *credsPath, identity.LocalServer, *userName, plain)
	}
	return ExitOK
}

// reportMinted prints the credential and then everything about it that will
// never be printable again.
//
// stdout carries the secret alone (docs/specs/10-cli.md §4) and stderr carries
// the description, so `nodary token create … > f` puts a usable credential in
// the file and tells the operator what it is on their terminal.
func reportMinted(e env, plain string, t identity.TokenReport, userName string, rec audit.Record) {
	fmt.Fprintln(e.stdout, plain)
	fmt.Fprintf(e.stderr, "%s for %s, id %s, expires %s.\n",
		t.Kind, userName, t.ID, orDash(t.ExpiresAt))
	fmt.Fprintf(e.stderr, "This is shown once and is stored only as a hash.\n")
	if t.Unattended {
		fmt.Fprintf(e.stderr,
			"This credential may mutate unattended; the grant is audit record %d.\n", rec.Seq)
	}
	reportRecord(e, rec)
}

// saveCredential writes a freshly minted personal token into the credentials
// file, under the appliance it belongs to.
//
// The target matters: a token minted over --server authenticates against *that*
// control plane, and filing it under "local" would leave it where a local
// invocation looks for one and nowhere a --server invocation does.
func saveCredential(e env, verb, credsPath, target, userName, plain string) int {
	path, err := credentialsPath(credsPath)
	if err != nil {
		fmt.Fprintf(e.stderr, "nodary %s: %v\n", verb, err)
		return ExitFailure
	}
	creds, err := identity.LoadCredentials(path)
	if err != nil {
		fmt.Fprintf(e.stderr, "nodary %s: %v\n", verb, err)
		return ExitFailure
	}
	cred := identity.Credential{Token: plain, User: userName}
	// The pin is the appliance's, not the credential's, so a token replacing an
	// older one keeps it rather than un-pinning the target.
	if old, err := creds.Token(target); err == nil {
		cred.CAFingerprint = old.CAFingerprint
	}
	creds.Set(target, cred)
	if err := creds.Save(path); err != nil {
		fmt.Fprintf(e.stderr, "nodary %s: %v\n", verb, err)
		return ExitFailure
	}
	fmt.Fprintf(e.stderr, "Saved to %s.\n", path)
	return ExitOK
}

// reportRouteAccess says what a service key may actually call.
//
// **docs/specs/06-gateway.md §2 is deny-by-default**: a user with no row in
// user_route may call nothing, which is what makes 07 §5's "least privilege by
// default" true rather than decorative — and it is invisible at the moment a
// credential is minted. The symptom otherwise is a 403 from a fleet where the
// node is approved, the model is loaded and the route is served, on a key that
// was just printed as though it were usable.
//
// Reported and not fixed here. Granting is a configuration change with an
// author and a revision like any other, and a mint that quietly widened access
// would be the one act in this product that changed what somebody may reach
// without recording that anybody decided it.
func reportRouteAccess(e env, s *session, user string) {
	snap, err := config.Read(context.Background(), s.db.Read())
	if err != nil || len(snap.Routes) == 0 {
		// No routes yet is an ordinary state on a fresh install, and there is
		// nothing useful to say about access to nothing.
		return
	}
	var granted []string
	for _, g := range snap.Grants {
		if g.User == user {
			granted = append(granted, g.Route)
		}
	}
	if len(granted) > 0 {
		fmt.Fprintf(e.stderr, "It may call: %s\n", strings.Join(granted, ", "))
		return
	}
	fmt.Fprintf(e.stderr,
		"\nIt may call nothing yet — a route is granted per user and denied by default.\n"+
			"  printf '[[grant]]\\nuser  = \"%s\"\\nroute = \"%s\"\\n' > grant.toml\n"+
			"  nodary config apply -f grant.toml --yes --justify \"grant %s the %s route\"\n",
		user, snap.Routes[0].Name, user, snap.Routes[0].Name)
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

	expires, ok := expiryAt(e, "token join", s.now, identity.KindJoin, *lifetime)
	if !ok {
		return ExitUsage
	}
	if expires.IsZero() {
		fmt.Fprintf(e.stderr,
			"nodary token join: a join token must expire; `never` enrolls anybody, forever\n")
		return ExitUsage
	}
	// The same ceiling, because --expires takes days here too. It is a loose
	// bound on a credential 02 §4 scopes to minutes and hours, but a loose
	// bound applied is worth more than a tight one nobody reads.
	active, _, err := policy.Active(context.Background(), s.db.Read())
	if err != nil {
		fmt.Fprintf(e.stderr, "nodary token join: %v\n", err)
		return ExitFailure
	}
	if err := attest.AllowTokenLifetime(active, s.now, expires); err != nil {
		fmt.Fprintf(e.stderr, "nodary token join: %v\n", err)
		return ExitPolicy
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
	server := serverFlag(fs)
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

	r, code := remoteFor(e, "token revoke", *server, *credsPath, *dbPath, *keyPath)
	if code >= 0 {
		return code
	}
	if r != nil {
		out, applied, code := r.attested(e, "token revoke",
			remoteAct{method: "DELETE", path: "/tokens/" + url.PathEscape(rest[0])}, cer, *format)
		if !applied {
			return code
		}
		var revoked identity.TokenReport
		if raw, err := json.Marshal(out.Result); err == nil {
			_ = json.Unmarshal(raw, &revoked)
		}
		return writeRevoked(e, *format, revoked, audit.Record{Seq: out.AuditSeq})
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

	return writeRevoked(e, *format, identity.NewTokenReport(tok, s.now), rec)
}

func writeRevoked(e env, format string, t identity.TokenReport, rec audit.Record) int {
	if format == "json" {
		return writeJSON(e, "token revoke", map[string]any{"token": t, "seq": rec.Seq})
	}
	fmt.Fprintf(e.stdout, "%s\trevoked\t%s\n", t.ID, orDash(t.RevokedAt))
	reportRecord(e, rec)
	return ExitOK
}

func cmdTokenList(e env, args []string) int {
	fs := newFlagSet(e, "token list")
	format := formatFlag(fs)
	dbPath := dbFlag(fs)
	server, credsPath := serverFlag(fs), credentialsFlag(fs)
	userName := fs.String("user", "", "only this user's credentials")
	if code := parseFlags(e, fs, args); code >= 0 {
		return code
	}
	if !checkFormat(e, *format) {
		return ExitUsage
	}
	r, code := remoteFor(e, "token list", *server, *credsPath, *dbPath)
	if code >= 0 {
		return code
	}

	var (
		tokens []identity.TokenReport
		joins  []identity.JoinReport
		err    error
	)
	if r != nil {
		q := url.Values{}
		if *userName != "" {
			q.Set("user", *userName)
		}
		tokens, err = remoteList[identity.TokenReport](r, "/tokens", "tokens", q)
		if err == nil && *userName == "" {
			joins, err = remoteList[identity.JoinReport](r, "/tokens", "join_tokens", nil)
		}
		if err != nil {
			fmt.Fprintf(e.stderr, "nodary token list: %v\n", err)
			return exitFor(err)
		}
	} else {
		ctx := context.Background()
		path, _ := resolveDB(*dbPath)
		db, ok := openForReading(e, "token list", path)
		if !ok {
			return ExitFailure
		}
		defer db.Close()

		userID := ""
		if *userName != "" {
			u, err := identity.Get(ctx, db.Read(), *userName)
			if err != nil {
				fmt.Fprintf(e.stderr, "nodary token list: %v\n", err)
				return exitFor(err)
			}
			userID = u.ID
		}
		live, err := identity.ListTokens(ctx, db.Read(), userID)
		if err != nil {
			fmt.Fprintf(e.stderr, "nodary token list: %v\n", err)
			return ExitFailure
		}
		tokens = identity.TokenReports(live, time.Now())
		if userID == "" {
			// A join token belongs to nobody, so filtering by user excludes
			// them rather than showing every operator the whole enrollment set.
			outstanding, err := identity.ListJoinTokens(ctx, db.Read())
			if err != nil {
				fmt.Fprintf(e.stderr, "nodary token list: %v\n", err)
				return ExitFailure
			}
			joins = identity.JoinReports(outstanding)
		}
	}

	if *format == "json" {
		return writeJSON(e, "token list", map[string]any{
			"tokens": tokens, "join_tokens": joins,
		})
	}

	tw := tabwriter.NewWriter(e.stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tKIND\tPREFIX\tNAME\tSTATE\tLAST USED\tEXPIRES")
	for _, t := range tokens {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			t.ID, t.Kind, t.Prefix, orDash(t.Name), t.State,
			orDash(t.LastUsedAt), orDash(t.ExpiresAt))
	}
	for _, j := range joins {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%d use(s)\t%s\t%s\n",
			j.ID, identity.KindJoin, j.Prefix, "-", j.UsesLeft, "-", orDash(j.ExpiresAt))
	}
	return flush(e, "token list", tw)
}

// expiryAt is identity.ExpiryFor with the CLI's way of reporting a bad flag.
func expiryAt(e env, verb string, now time.Time, kind identity.Kind,
	lifetime string) (time.Time, bool) {
	at, err := identity.ExpiryFor(kind, lifetime, now)
	if err != nil {
		fmt.Fprintf(e.stderr, "nodary %s: --expires %v\n", verb, err)
		return time.Time{}, false
	}
	return at, true
}
