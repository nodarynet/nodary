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
	"github.com/nodarynet/nodary/internal/audit"
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
func remoteFor(e env, verb, target, credsPath string, local ...string) (*remote, int) {
	if strings.TrimSpace(target) == "" {
		return nil, -1
	}
	// --db and --secret-key describe this host's state and --server describes
	// another machine's, so naming both is a contradiction. The quiet
	// resolution — remote wins, the others ignored — is the failure this whole
	// flag is careful about: an operator who believed they were acting on one
	// control plane and acted on another.
	for _, v := range local {
		if strings.TrimSpace(v) != "" {
			fmt.Fprintf(e.stderr, "nodary %s: --server names another control plane, and "+
				"--db and --secret-key describe this host's. Pass one.\n", verb)
			return nil, ExitUsage
		}
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
	_, err := r.doWith(method, path, body, out, nil)
	return err
}

// get reads one object and returns the revision it was read at.
//
// The ETag is docs/specs/09-api.md §2's version of the whole configuration,
// and it is what a read-modify-write over the network sends back as If-Match.
// The local route has no use for one — it reads and writes inside a single
// transaction — but this one reads the object in one request and replaces it
// in another, which is a lost-update window the local route does not have.
func (r *remote) get(path string, out any) (etag string, err error) {
	h, err := r.doWith("GET", path, nil, out, nil)
	if err != nil {
		return "", err
	}
	return h.Get(api.HeaderETag), nil
}

func (r *remote) doWith(method, path string, body, out any,
	headers map[string]string) (http.Header, error) {
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, r.base+api.Prefix+path, rdr)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if r.cred.Token != "" {
		req.Header.Set("Authorization", "Bearer "+r.cred.Token)
	}
	for k, v := range headers {
		if v != "" {
			req.Header.Set(k, v)
		}
	}
	resp, err := r.c.Do(req)
	if err != nil {
		// The pin failure is named rather than folded into "unreachable". A
		// certificate that does not match is a different problem from a host
		// that is down, and an operator told to check the network will not
		// find it.
		if errors.Is(err, agent.ErrPin) {
			return nil, fmt.Errorf("%s does not present the certificate pinned for it: %w", r.base, err)
		}
		return nil, fmt.Errorf("%w: %s: %v", errUnreachable, r.base, err)
	}
	defer resp.Body.Close()

	// Bounded. A control plane is trusted to be correct, not to be healthy:
	// something wedged serving an endless body should fail this command rather
	// than fill this machine's memory.
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		return nil, fmt.Errorf("%w: reading the answer from %s: %v", errUnreachable, r.base, err)
	}
	if resp.StatusCode >= 400 {
		return resp.Header, remoteFailure(resp.StatusCode, raw)
	}
	if out == nil {
		return resp.Header, nil
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return resp.Header, fmt.Errorf("%s answered with something this release cannot read: %v", r.base, err)
	}
	return resp.Header, nil
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

// remoteAct is one mutation to make over the network.
type remoteAct struct {
	method, path string
	body         any
	// ifMatch is the revision a read-modify-write read its object at, which
	// the control plane refuses the act against if the configuration has moved
	// since (docs/specs/09-api.md §2). Empty for a verb that reads nothing
	// first: there is nothing for it to have raced with.
	ifMatch string
}

// remoteOutcome is what internal/api's mutate writes, in either phase.
type remoteOutcome struct {
	Applied    bool           `json:"applied"`
	DryRun     bool           `json:"dry_run"`
	Action     string         `json:"action"`
	IntentHash string         `json:"intent_hash"`
	AuditSeq   int64          `json:"audit_seq"`
	RequestID  string         `json:"request_id"`
	Change     map[string]any `json:"change"`
	Result     map[string]any `json:"result"`
}

// attested is session.attested over the network: the same ceremony of
// docs/specs/07-identity-audit.md §2, reached by the other road 09 §2 promises.
//
// It is a second sequence beside the local one and cannot be shared with it —
// there the preview, the hash and the act are three calls into core with a
// database handle between them, and here they are two HTTP requests. What is
// shared is everything the operator sees and everything that decides: the
// preview is rendered by the same Render on the control plane, the hash is the
// same core.Preview hash, the confirmation and the dry run print through the
// same writeDryRun and showPreview, and the ceremony itself is enforced in one
// place — core.Act, on the far side — rather than being re-decided here. A
// front end that decided any of it would be the second implementation of
// attestation this arrangement exists to prevent.
func (r *remote) attested(e env, verb string, a remoteAct,
	f ceremonyFlags, format string) (remoteOutcome, bool, int) {
	if strings.ContainsAny(*f.justify, "\r\n") {
		fmt.Fprintf(e.stderr, "nodary %s: --justify travels in a header over --server "+
			"and cannot contain a line break.\n", verb)
		return remoteOutcome{}, false, ExitUsage
	}

	// Rendered on the control plane so the operator is shown what they are
	// approving, exactly as the local route renders it against the database.
	// The hash comes back and is sent with the act, which is what binds the
	// two: what gets applied is what was on the screen.
	var prev remoteOutcome
	if err := r.do(a.method, addQuery(a.path, "dry_run=true"), a.body, &prev); err != nil {
		fmt.Fprintf(e.stderr, "nodary %s: %v\n", verb, err)
		return remoteOutcome{}, false, exitFor(err)
	}
	if *f.dryRun {
		return prev, false, writeDryRun(e, verb, format, prev.Action, prev.IntentHash, prev.Change)
	}
	if !*f.yes && e.interactive() {
		showPreview(e, prev.Action, prev.IntentHash, prev.Change)
		if !confirm(e) {
			fmt.Fprintf(e.stderr, "nodary %s: cancelled; nothing was applied\n", verb)
			return prev, false, ExitCancelled
		}
	}

	out, err := r.act(a, prev.IntentHash, *f.justify, *f.totp)
	// The one refusal a human can still satisfy, and asking is the front end's
	// job: the control plane has nobody to prompt, so it says what is missing
	// and each front end answers in its own way. The local route does the same
	// thing with core.ErrTOTPRequired; over the wire the same refusal arrives
	// as 09 §3's code.
	var refusal *remoteError
	if errors.As(err, &refusal) && refusal.code == "reauthentication_required" && e.interactive() {
		var code string
		if code, err = promptTOTP(e); err == nil {
			out, err = r.act(a, prev.IntentHash, *f.justify, code)
		}
	}
	if err != nil {
		fmt.Fprintf(e.stderr, "nodary %s: %v\n", verb, err)
		// A refusal is recorded on the control plane too, and an operator
		// disputing one needs the sequence to point at. It is not in the error
		// envelope, so the record is named only where the far side named it.
		reportRecord(e, audit.Record{Seq: out.AuditSeq})
		return out, false, exitFor(err)
	}
	return out, true, ExitOK
}

func (r *remote) act(a remoteAct, intent, justify, totp string) (remoteOutcome, error) {
	var out remoteOutcome
	_, err := r.doWith(a.method, a.path, a.body, &out, map[string]string{
		api.HeaderIntent:  intent,
		api.HeaderJustify: justify,
		api.HeaderTOTP:    totp,
		api.HeaderIfMatch: a.ifMatch,
	})
	return out, err
}

func addQuery(path, q string) string {
	if strings.Contains(path, "?") {
		return path + "&" + q
	}
	return path + "?" + q
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
