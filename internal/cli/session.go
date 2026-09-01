package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/user"
	"strconv"
	"time"

	"github.com/nodarynet/nodary/internal/audit"
	"github.com/nodarynet/nodary/internal/identity"
	"github.com/nodarynet/nodary/internal/paths"
	"github.com/nodarynet/nodary/internal/secret"
	"github.com/nodarynet/nodary/internal/store"
)

// session is a database open for writing, with the audit log every mutation
// goes through and the principal performing it.
//
// The CLI and, in R2, the HTTP API produce the same identity.Principal and call
// the same core functions, which is the constraint docs/specs/10-cli.md opens
// with. Nothing here holds business logic.
type session struct {
	db       *store.DB
	log      *audit.Log
	delivery *audit.Delivery
	who      identity.Principal
	keyPath  string
	now      time.Time
}

// keyFlag registers --secret-key, the counterpart to --db.
//
// Not in docs/specs/10-cli.md §2's table, for the same reason --db is not: a
// spec describing an installed appliance names one location for each, and both
// flags exist so the binary can be pointed at another one. Without it the only
// way to exercise sealing is to write to /etc.
func keyFlag(fs *flag.FlagSet) *string {
	return fs.String("secret-key", "", "at-rest key path (default "+paths.SecretKey()+")")
}

func resolveKey(flagValue string) string {
	if flagValue != "" {
		return flagValue
	}
	return paths.SecretKey()
}

// credentialsFlag registers --credentials.
func credentialsFlag(fs *flag.FlagSet) *string {
	return fs.String("credentials", "", "personal-token file (default ~/.nodary/credentials)")
}

// justifyFlag registers the --justify of docs/specs/10-cli.md §2.
//
// R1c records it and does not enforce a minimum length: the minimum belongs to
// a policy profile (R1-15), and there are no profiles until R1d. Recording it
// now means the enforcement that arrives then has something to enforce against
// rather than a field to add.
func justifyFlag(fs *flag.FlagSet) *string {
	return fs.String("justify", "", "why this change is being made; required by policy")
}

// openSession opens the database for writing and works out who is acting.
func openSession(e env, verb, dbPath, keyPath, credsPath string) (*session, bool) {
	ctx := context.Background()
	path, _ := resolveDB(dbPath)

	db, err := store.Open(ctx, path)
	if err != nil {
		fmt.Fprintf(e.stderr, "nodary %s: %v\n", verb, err)
		return nil, false
	}
	// docs/specs/08-data-model.md §5: any process that opens the database for
	// writing applies migrations, because on a first install an operator's
	// first command reaches an unmigrated database.
	if err := db.Migrate(ctx); err != nil {
		fmt.Fprintf(e.stderr, "nodary %s: %v\n", verb, err)
		db.Close()
		return nil, false
	}

	s := &session{db: db, keyPath: resolveKey(keyPath), now: time.Now()}
	if !s.checkKeyBinding(e, verb) {
		db.Close()
		return nil, false
	}

	who, ok := resolvePrincipal(e, verb, db, credsPath, s.now)
	if !ok {
		db.Close()
		return nil, false
	}
	s.who = who

	delivery, err := audit.DeliveryFromEnv(e.stderr)
	if err != nil {
		fmt.Fprintf(e.stderr, "nodary %s: %v\n", verb, err)
		db.Close()
		return nil, false
	}
	s.delivery = delivery
	s.log = audit.New(db, delivery)
	return s, true
}

func (s *session) Close() {
	if s.delivery != nil {
		s.delivery.Close()
	}
	s.db.Close()
}

// checkKeyBinding is R1-36.
//
// It runs on every session rather than only where something is sealed, because
// the failure it exists to catch is a missing key, and a missing key is
// invisible until somebody tries to read a secret. Deleting
// /etc/nodary/secret.key and carrying on is the unrecoverable path: every TOTP
// seed, and later the CA key, becomes permanently unreadable, and nothing says
// so until the first person tries to log in.
//
// A session is what a mutating verb opens, so read-only commands are not
// blocked by a key problem. That is deliberate: a read-only command is how an
// operator diagnoses one, and refusing it would take away the tool at exactly
// the moment it is needed. Refusing the mutation is the half that matters —
// it stops a new secret being sealed under a key that cannot read the old
// ones.
func (s *session) checkKeyBinding(e env, verb string) bool {
	ctx := context.Background()
	bound, err := identity.BoundKeyID(ctx, s.db.Read())
	if err != nil {
		fmt.Fprintf(e.stderr, "nodary %s: %v\n", verb, err)
		return false
	}
	if bound == "" {
		// Nothing has been sealed, so there is nothing to lose and no key is
		// required to run.
		return true
	}

	k, err := secret.Load(s.keyPath)
	if errors.Is(err, os.ErrNotExist) {
		fmt.Fprintf(e.stderr,
			"nodary %s: this database was sealed under key %s and %s is missing.\n"+
				"  Restore it from a backup. Creating a new key does not recover anything:\n"+
				"  every sealed value stays unreadable, and nothing would report a problem.\n",
			verb, bound, s.keyPath)
		return false
	}
	if err != nil {
		fmt.Fprintf(e.stderr, "nodary %s: %v\n", verb, err)
		return false
	}
	if err := identity.CheckKey(ctx, s.db.Read(), k); err != nil {
		fmt.Fprintf(e.stderr, "nodary %s: %v\n", verb, err)
		return false
	}
	return true
}

// key loads the at-rest key, creating it if this is the first seal.
func (s *session) key() (*secret.Key, error) {
	return secret.Create(s.keyPath)
}

// resolvePrincipal works out who is acting.
//
// A personal token in the credentials file wins, and names a real account in
// every record it produces. Without one the invocation is local, and local is
// admin: docs/specs/07-identity-audit.md §1 requires that an appliance can
// still authenticate its own administrator when the network is degraded, and
// the authority is real rather than assumed — the database is mode 0600 and
// opening it for writing has already proved the access that grants. Demanding
// a credential the same access could mint would buy nothing.
func resolvePrincipal(e env, verb string, db *store.DB, credsPath string,
	now time.Time) (identity.Principal, bool) {
	path, explicit := credsPath, credsPath != ""
	if !explicit {
		var err error
		if path, err = paths.Credentials(); err != nil {
			// No home directory: there is nowhere for a credential to be, so
			// this is a local invocation and not a failure.
			return localPrincipal(), true
		}
	}

	creds, err := identity.LoadCredentials(path)
	if err != nil {
		// A credentials file that exists and cannot be used is reported, never
		// stepped over: falling back to local would silently act as an
		// administrator when the operator asked to act as themselves.
		fmt.Fprintf(e.stderr, "nodary %s: %v\n", verb, err)
		return identity.Principal{}, false
	}
	cred, err := creds.Token(identity.LocalServer)
	if err != nil {
		// Acting locally is right — an appliance with no credentials is the
		// ordinary case — but an operator who named a file and got nothing
		// from it should be told, because a typo in that path is otherwise
		// silent. It changes attribution rather than authority: the record
		// says method "local" either way, and opening the database for
		// writing already granted what local grants.
		if explicit {
			fmt.Fprintf(e.stderr, "nodary %s: no credential in %s; acting locally\n",
				verb, path)
		}
		return localPrincipal(), true
	}

	who, err := identity.ResolveToken(context.Background(), db.Read(), now, cred.Token)
	if err != nil {
		fmt.Fprintf(e.stderr, "nodary %s: %v\n", verb, err)
		fmt.Fprintf(e.stderr, "  the credential in %s did not authenticate.\n", path)
		return identity.Principal{}, false
	}
	return who, true
}

// localPrincipal names the operating-system account in the record, so a local
// action is attributable to somebody rather than to the machine.
func localPrincipal() identity.Principal {
	p := identity.LocalRoot()
	if u, err := user.Current(); err == nil && u.Username != "" {
		p.Actor.ID = u.Username
	} else {
		p.Actor.ID = "uid:" + strconv.Itoa(os.Getuid())
	}
	return p
}

// request builds the audit request for one action.
func (s *session) request(action string, target *audit.Target, justify string) audit.Request {
	return audit.Request{
		Actor:         s.who.Actor,
		Action:        action,
		Target:        target,
		Justification: justify,
		// Source is empty for a local invocation, which has neither a client
		// address nor a client version. R2 fills both from the request.
	}
}

// touch records the use of the credential that authorised an act, inside that
// act. Nothing outside internal/audit may write on its own.
func (s *session) touch(m audit.Mutation) error {
	if s.who.Local() {
		return nil
	}
	return identity.Touch(context.Background(), m, s.now, s.who.Token.ID)
}

// exitFor maps an error to the code docs/specs/10-cli.md §5 assigns it.
//
// One function, because the codes are a contract a script depends on and three
// verbs each deciding for themselves is how they stop agreeing.
func exitFor(err error) int {
	switch {
	case err == nil:
		return ExitOK
	case errors.Is(err, identity.ErrDenied),
		errors.Is(err, identity.ErrBadToken),
		errors.Is(err, identity.ErrTokenRevoked),
		errors.Is(err, identity.ErrTokenExpired),
		errors.Is(err, identity.ErrNotActive),
		errors.Is(err, identity.ErrNotEnrolled),
		errors.Is(err, identity.ErrBadCode):
		return ExitAuth
	case errors.Is(err, identity.ErrBadName),
		errors.Is(err, identity.ErrUnknownRole),
		errors.Is(err, identity.ErrUnknownKind):
		return ExitUsage
	case errors.Is(err, identity.ErrNameTaken),
		errors.Is(err, identity.ErrBadTransition):
		return ExitPrecondition
	case errors.Is(err, audit.ErrDeliveryBlocked):
		return ExitPolicy
	}
	return ExitFailure
}
