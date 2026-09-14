package cli

import (
	"fmt"
	"strings"

	"github.com/nodarynet/nodary/internal/agent"
	"github.com/nodarynet/nodary/internal/identity"
)

// cmdLogin stores the credential a --server invocation presents.
//
// It takes a personal token rather than a password, which is the identity
// model the CLI already has rather than a new one: `nodary token create --save`
// writes the same file for the local target, and docs/specs/01-install.md §4's
// one-time setup link exists so that a password is never typed into a terminal
// or left in a shell history. An administrator mints a token for a person with
// `nodary token create --user`; that person runs this once per appliance.
//
// The token is read from stdin and never taken as a flag. A credential on a
// command line is in the shell's history file and in every `ps` on the machine
// for as long as the command runs, and unlike a join token — single-use, and
// spent within the minute — a personal token is good for ninety days.
func cmdLogin(e env, args []string) int {
	fs := newFlagSet(e, "login")
	server := serverFlag(fs)
	fingerprint := fs.String("ca-fingerprint", "",
		"the control plane certificate to pin, sha256:… (printed by `server install`)")
	credsPath := credentialsFlag(fs)
	format := formatFlag(fs)
	if code := parseFlags(e, fs, args); code >= 0 {
		return code
	}
	if !checkFormat(e, *format) {
		return ExitUsage
	}
	if strings.TrimSpace(*server) == "" {
		fmt.Fprintf(e.stderr, "nodary login: --server is required, https://host:8443\n")
		return ExitUsage
	}
	base, err := normalizeServer(*server)
	if err != nil {
		fmt.Fprintf(e.stderr, "nodary login: %v\n", err)
		return ExitUsage
	}

	path, err := credentialsPath(*credsPath)
	if err != nil {
		fmt.Fprintf(e.stderr, "nodary login: %v\n", err)
		return ExitFailure
	}
	creds, err := identity.LoadCredentials(path)
	if err != nil {
		fmt.Fprintf(e.stderr, "nodary login: %v\n", err)
		return ExitFailure
	}

	// An existing pin is kept unless this run names one, so an ordinary
	// re-login after a token rotation does not ask for the fingerprint again.
	// Naming a different one is a decision, and it is reported rather than
	// applied quietly: a control plane presenting a new certificate is either
	// a reissue the operator performed or the thing pinning exists to catch.
	pin := strings.TrimSpace(*fingerprint)
	if old, err := creds.Token(base); err == nil {
		switch {
		case pin == "":
			pin = old.CAFingerprint
		case old.CAFingerprint != "" && !strings.EqualFold(pin, old.CAFingerprint):
			fmt.Fprintf(e.stderr, "nodary login: replacing the pin for %s.\n  was %s\n  now %s\n",
				base, old.CAFingerprint, pin)
		}
	}
	if pin == "" {
		fmt.Fprintf(e.stderr,
			"nodary login: --ca-fingerprint is required the first time you log in to %s.\n"+
				"  It is printed by `nodary server install` and by `nodary server status`\n"+
				"  on the control-plane host, and is the same value nodes pin.\n", base)
		return ExitUsage
	}
	if _, err := agent.PinnedTLS(pin); err != nil {
		fmt.Fprintf(e.stderr, "nodary login: %v\n", err)
		return ExitUsage
	}

	if e.interactive() {
		fmt.Fprintf(e.stderr, "Personal token for %s (from `nodary token create`): ", base)
	}
	// The read error is ignored where a line came back: stdin closing without a
	// trailing newline is how a pipe ends, and it is an ordinary success.
	line, _ := e.line()
	if e.interactive() {
		fmt.Fprintln(e.stderr)
	}
	token := strings.TrimSpace(line)
	if token == "" {
		fmt.Fprintf(e.stderr, "nodary login: no token on stdin.\n"+
			"  An administrator mints one with `nodary token create --user <you>`;\n"+
			"  pipe it in, or paste it at the prompt.\n")
		return ExitUsage
	}

	// Verified before it is written. A credential file that authenticates
	// nothing is worse than none at all: every later verb fails at the point
	// of use, naming the verb rather than the credential, and the operator has
	// no reason to suspect this step.
	r := &remote{base: base, cred: identity.Credential{Token: token, CAFingerprint: pin}}
	if r.c, err = agent.Client(pin, nil); err != nil {
		fmt.Fprintf(e.stderr, "nodary login: %v\n", err)
		return ExitFailure
	}
	var who struct {
		User, Role, Method string
		Unattended         bool
	}
	if err := r.do("GET", "/auth/whoami", nil, &who); err != nil {
		fmt.Fprintf(e.stderr, "nodary login: %v\n", err)
		return exitFor(err)
	}

	creds.Set(base, identity.Credential{Token: token, User: who.User, CAFingerprint: pin})
	if err := creds.Save(path); err != nil {
		fmt.Fprintf(e.stderr, "nodary login: %v\n", err)
		return ExitFailure
	}

	if *format == "json" {
		return writeJSON(e, "login", map[string]any{
			"server": base, "user": who.User, "role": who.Role,
			"ca_fingerprint": pin, "credentials": path})
	}
	fmt.Fprintf(e.stdout, "%s as %s (%s)\n", base, who.User, who.Role)
	fmt.Fprintf(e.stderr, "Saved to %s. Verbs that take --server will use it.\n", path)
	return ExitOK
}

// cmdLogout forgets one appliance's credential.
//
// Local only, and it says so. The token stays valid — it may be in use on
// another machine, and ending it for everybody is `nodary token revoke`, an
// audited act against the control plane rather than an edit to a file on this
// laptop.
func cmdLogout(e env, args []string) int {
	fs := newFlagSet(e, "logout")
	server := serverFlag(fs)
	credsPath := credentialsFlag(fs)
	if code := parseFlags(e, fs, args); code >= 0 {
		return code
	}
	if strings.TrimSpace(*server) == "" {
		fmt.Fprintf(e.stderr, "nodary logout: --server is required; it names which credential to forget\n")
		return ExitUsage
	}
	base, err := normalizeServer(*server)
	if err != nil {
		fmt.Fprintf(e.stderr, "nodary logout: %v\n", err)
		return ExitUsage
	}
	path, err := credentialsPath(*credsPath)
	if err != nil {
		fmt.Fprintf(e.stderr, "nodary logout: %v\n", err)
		return ExitFailure
	}
	creds, err := identity.LoadCredentials(path)
	if err != nil {
		fmt.Fprintf(e.stderr, "nodary logout: %v\n", err)
		return ExitFailure
	}
	if _, err := creds.Token(base); err != nil {
		fmt.Fprintf(e.stderr, "nodary logout: no credential for %s in %s\n", base, path)
		return ExitOK
	}
	creds.Forget(base)
	if err := creds.Save(path); err != nil {
		fmt.Fprintf(e.stderr, "nodary logout: %v\n", err)
		return ExitFailure
	}
	fmt.Fprintf(e.stdout, "forgot the credential for %s\n", base)
	fmt.Fprintf(e.stderr, "The token itself is still valid. `nodary token revoke` ends it for everyone.\n")
	return ExitOK
}
