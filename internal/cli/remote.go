package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/nodarynet/nodary/internal/agent"
	"github.com/nodarynet/nodary/internal/api"
	"github.com/nodarynet/nodary/internal/identity"
	"github.com/nodarynet/nodary/internal/paths"
)

// A control plane reached over the network rather than by opening its database.
//
// This is what makes an administrator a person. Without it the only way to run
// a privileged verb is a shell on the control-plane host, so every record the
// chain keeps names `root` and the method `local`
// (docs/specs/07-identity-audit.md §1) — an accountability product answering
// "who did this" with the name of an account three people share.
//
// The credential is a personal token presented as `Authorization: Bearer`,
// which is the identity model the CLI already has: `nodary token create --save`
// writes one, internal/cli/user.go records that "the CLI authenticates with a
// personal token", and internal/api's authenticate already prefers a bearer
// credential over a cookie because it is the one with a revocation record. A
// password is never typed at a terminal here, for the reason the wizard gives.

// errUnreachable is a control plane that did not answer. It is separate from
// every refusal the control plane itself produces, because
// docs/specs/10-cli.md §5 gives it its own exit code and a script retries it
// where it would not retry a 403.
var errUnreachable = errors.New("the control plane could not be reached")

// serverFlag registers docs/specs/10-cli.md §2's --server.
//
// Deliberately not defaulted from an environment variable. A verb that runs on
// this host and one that acts on another appliance are different acts, and an
// exported NODARY_SERVER would make which one happened depend on a shell
// setting nobody is looking at.
func serverFlag(fs *flag.FlagSet) *string {
	return fs.String("server", "",
		"act against this control plane over the network instead of this host's database")
}

// remote is one control plane and the credential for it.
type remote struct {
	base string
	cred identity.Credential
	c    *http.Client
}

// remoteFor builds the client for --server, or returns code -1 and a nil remote
// when the invocation is local.
//
// The exit code is returned rather than a bool because the two ways this fails
// are different answers to a script: no credential is ExitAuth, a malformed
// --server is ExitUsage.
func remoteFor(e env, verb, target, credsPath, dbPath string) (*remote, int) {
	if strings.TrimSpace(target) == "" {
		return nil, -1
	}
	// Both named is a contradiction, and the quiet resolution — remote wins,
	// --db ignored — is the failure this whole flag is careful about: an
	// operator who believed they were reading one database and read another.
	if strings.TrimSpace(dbPath) != "" {
		fmt.Fprintf(e.stderr, "nodary %s: --server and --db name different control planes; "+
			"pass one.\n", verb)
		return nil, ExitUsage
	}
	base, err := normalizeServer(target)
	if err != nil {
		fmt.Fprintf(e.stderr, "nodary %s: %v\n", verb, err)
		return nil, ExitUsage
	}
	path, err := credentialsPath(credsPath)
	if err != nil {
		fmt.Fprintf(e.stderr, "nodary %s: %v\n", verb, err)
		return nil, ExitFailure
	}
	creds, err := identity.LoadCredentials(path)
	if err != nil {
		fmt.Fprintf(e.stderr, "nodary %s: %v\n", verb, err)
		return nil, ExitAuth
	}
	cred, err := creds.Token(base)
	if err != nil {
		fmt.Fprintf(e.stderr, "nodary %s: no credential for %s in %s.\n"+
			"  Run `nodary login --server %s`.\n", verb, base, path, base)
		return nil, ExitAuth
	}
	c, err := agent.Client(cred.CAFingerprint, nil)
	if err != nil {
		fmt.Fprintf(e.stderr, "nodary %s: the pin stored for %s is unusable: %v\n"+
			"  Run `nodary login --server %s --ca-fingerprint sha256:…` to replace it.\n",
			verb, base, err, base)
		return nil, ExitFailure
	}
	return &remote{base: base, cred: cred, c: c}, -1
}

// normalizeServer is both the base URL and the key a credential is stored
// under, so the two cannot disagree: `host:8443`, `https://host:8443` and
// `https://host:8443/` are one appliance and must produce one key.
//
// The path is dropped rather than preserved. The API is always at
// internal/api.Prefix on the host root, so a path here is a paste that would
// otherwise be silently concatenated into a URL that 404s.
func normalizeServer(target string) (string, error) {
	t := strings.TrimSpace(target)
	if !strings.Contains(t, "://") {
		t = "https://" + t
	}
	u, err := url.Parse(t)
	if err != nil {
		return "", fmt.Errorf("--server %q: %v", target, err)
	}
	switch {
	case u.Scheme != "https":
		return "", fmt.Errorf("--server %q: the control plane is reached over https; "+
			"a credential is not sent over anything else", target)
	case u.Host == "":
		return "", fmt.Errorf("--server %q: no host; expected https://host:8443", target)
	}
	return "https://" + u.Host, nil
}

func credentialsPath(flagValue string) (string, error) {
	if flagValue != "" {
		return flagValue, nil
	}
	return paths.Credentials()
}

// do makes one API call and decodes the answer into out, which may be nil.
func (r *remote) do(method, path string, body, out any) error {
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, r.base+api.Prefix+path, rdr)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if r.cred.Token != "" {
		req.Header.Set("Authorization", "Bearer "+r.cred.Token)
	}
	resp, err := r.c.Do(req)
	if err != nil {
		// The pin failure is named rather than folded into "unreachable". A
		// certificate that does not match is a different problem from a host
		// that is down, and an operator told to check the network will not
		// find it.
		if errors.Is(err, agent.ErrPin) {
			return fmt.Errorf("%s does not present the certificate pinned for it: %w", r.base, err)
		}
		return fmt.Errorf("%w: %s: %v", errUnreachable, r.base, err)
	}
	defer resp.Body.Close()

	// Bounded. A control plane is trusted to be correct, not to be healthy:
	// something wedged serving an endless body should fail this command rather
	// than fill this machine's memory.
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		return fmt.Errorf("%w: reading the answer from %s: %v", errUnreachable, r.base, err)
	}
	if resp.StatusCode >= 400 {
		return remoteFailure(resp.StatusCode, raw)
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("%s answered with something this release cannot read: %v", r.base, err)
	}
	return nil
}

// remoteList reads a whole listing, following docs/specs/09-api.md §2's cursor
// to the end.
//
// The CLI's listings are not paged — `nodary node list` prints the fleet — so
// stopping at the first page would quietly print fifty nodes of sixty and say
// nothing, which is the same wrong-answer-without-a-symptom that readPage
// refuses a clamped limit over.
func remoteList[T any](r *remote, path, field string, q url.Values) ([]T, error) {
	if q == nil {
		q = url.Values{}
	}
	q.Set("limit", strconv.Itoa(api.MaxLimit))
	// Empty rather than nil. `--format json` is a stable schema a script reads
	// (docs/specs/10-cli.md §2), config.Read returns an empty slice for a
	// listing with nothing in it, and a `null` where that script expects `[]`
	// is a difference between the two routes with no reason behind it.
	all := []T{}
	for {
		var body map[string]json.RawMessage
		if err := r.do("GET", path+"?"+q.Encode(), nil, &body); err != nil {
			return nil, err
		}
		var items []T
		if raw, ok := body[field]; ok {
			if err := json.Unmarshal(raw, &items); err != nil {
				return nil, fmt.Errorf("%s answered with a %s listing this release cannot read: %v",
					r.base, field, err)
			}
		}
		all = append(all, items...)
		var next string
		if raw, ok := body["next_cursor"]; ok {
			_ = json.Unmarshal(raw, &next)
		}
		// An empty page with a cursor would loop for ever against a control
		// plane that is wrong about having more.
		if next == "" || len(items) == 0 {
			return all, nil
		}
		q.Set("cursor", next)
	}
}

// remoteError is a refusal the control plane stated.
//
// It carries the stable code of docs/specs/09-api.md §3 rather than a status
// alone, because the code is what distinguishes refusals that share a status:
// 403 is both "you may not" and "this needs a justification", and those are
// different exit codes to a script.
type remoteError struct {
	status int
	code   string
	msg    string
	detail map[string]any
}

func (e *remoteError) Error() string { return e.msg }

func remoteFailure(status int, raw []byte) error {
	var body struct {
		Error api.Error `json:"error"`
	}
	if err := json.Unmarshal(raw, &body); err == nil && body.Error.Message != "" {
		return &remoteError{status: status, code: body.Error.Code,
			msg: body.Error.Message, detail: body.Error.Detail}
	}
	// Not an envelope: a proxy in front of the control plane, or a panic. Say
	// the status, because there is nothing better to say.
	text := strings.TrimSpace(string(raw))
	if text == "" {
		text = http.StatusText(status)
	}
	return &remoteError{status: status, msg: fmt.Sprintf("%s (HTTP %d)", text, status)}
}

// exit is the code docs/specs/10-cli.md §5 assigns this refusal.
//
// It is a second table beside internal/api's statusFor and that is the risk it
// carries, so remote_test.go holds it to covering every code statusFor can
// produce: a refusal added on the server with no meaning here would otherwise
// arrive as a generic failure.
func (e *remoteError) exit() int {
	switch e.code {
	case "unauthenticated", "forbidden", "too_many_attempts", "reauthentication_failed":
		return ExitAuth
	case "reauthentication_required", "justification_required",
		"justification_too_short", "unattended_forbidden":
		return ExitPolicy
	case "invalid", "bad_request":
		return ExitUsage
	case "conflict", "revision_changed", "intent_changed",
		"idempotency_key_reused", "idempotency_key_in_flight":
		return ExitPrecondition
	case "not_found", "internal":
		return ExitFailure
	}
	return ExitFailure
}
