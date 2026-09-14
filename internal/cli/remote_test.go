package cli

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/nodarynet/nodary/internal/agent"
	"github.com/nodarynet/nodary/internal/api"
	"github.com/nodarynet/nodary/internal/identity"
)

// controlPlane is a TLS server standing in for one, with the fingerprint an
// operator would pin.
func controlPlane(t *testing.T, h http.HandlerFunc) (base, fingerprint string) {
	t.Helper()
	srv := httptest.NewTLSServer(h)
	t.Cleanup(srv.Close)
	return srv.URL, agent.Fingerprint(srv.Certificate().Raw)
}

func whoamiServer(t *testing.T, user, role string) (base, fingerprint string) {
	t.Helper()
	return controlPlane(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != api.Prefix+"/auth/whoami" {
			http.Error(w, "unexpected path "+r.URL.Path, http.StatusNotFound)
			return
		}
		if r.Header.Get("Authorization") != "Bearer nodary_pt_secret" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]any{"error": map[string]any{
				"code": "unauthenticated", "message": "the token is not recognized"}})
			return
		}
		json.NewEncoder(w).Encode(map[string]any{
			"user": user, "role": role, "method": "token"})
	})
}

func credsFile(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "credentials")
}

// login writes the credential every other --server verb reads, so the one
// thing it must not do is write one that does not work. It is verified against
// the control plane before it is saved: a file that authenticates nothing
// fails at the point of use, naming a verb rather than the credential, and the
// operator has no reason to suspect this step.
func TestLoginVerifiesTheCredentialBeforeItWritesIt(t *testing.T) {
	base, fp := whoamiServer(t, "alice", "admin")
	path := credsFile(t)

	code, out, errb := runWithStdin(t, "nodary_pt_secret\n",
		"login", "--server", base, "--ca-fingerprint", fp, "--credentials", path)
	if code != ExitOK {
		t.Fatalf("login = %d\n%s%s", code, out, errb)
	}
	if !strings.Contains(out, "alice") || !strings.Contains(out, "admin") {
		t.Errorf("login did not report who the credential belongs to: %q", out)
	}

	creds, err := identity.LoadCredentials(path)
	if err != nil {
		t.Fatal(err)
	}
	cred, err := creds.Token(base)
	if err != nil {
		t.Fatalf("nothing was stored for %s: %v", base, err)
	}
	if cred.Token != "nodary_pt_secret" || cred.User != "alice" || cred.CAFingerprint != fp {
		t.Errorf("stored %+v, want the token, the user it named and the pin", cred)
	}

	// A token the control plane refuses is not written, and the exit code is
	// the one docs/specs/10-cli.md §5 gives an authentication failure.
	path2 := credsFile(t)
	code, _, errb = runWithStdin(t, "nodary_pt_wrong\n",
		"login", "--server", base, "--ca-fingerprint", fp, "--credentials", path2)
	if code != ExitAuth {
		t.Errorf("a refused token: exit = %d, want %d (%s)", code, ExitAuth, errb)
	}
	if _, err := os.Stat(path2); err == nil {
		t.Error("a credential the control plane refused was written to disk anyway")
	}
}

// The pin is the whole of the client's trust decision, exactly as it is on a
// node: without it, --server sends a personal token to whatever answers the
// name.
func TestLoginRefusesAControlPlaneThatDoesNotMatchThePin(t *testing.T) {
	base, fp := whoamiServer(t, "alice", "admin")
	wrong := fp[:len(fp)-1] + map[bool]string{true: "0", false: "1"}[strings.HasSuffix(fp, "1")]
	path := credsFile(t)

	code, _, errb := runWithStdin(t, "nodary_pt_secret\n",
		"login", "--server", base, "--ca-fingerprint", wrong, "--credentials", path)
	if code == ExitOK {
		t.Fatal("logged in to a control plane presenting an unpinned certificate")
	}
	if !strings.Contains(errb, "pinned") {
		t.Errorf("the refusal does not say the pin failed: %q", errb)
	}
	if _, err := os.Stat(path); err == nil {
		t.Error("a credential was written for a server whose certificate did not match")
	}
}

// A first login has nothing to pin against, so the fingerprint is required
// rather than taken on trust. Trust on first use would make the pin decorative
// for exactly the operator who has never connected before.
func TestAFirstLoginRequiresTheFingerprintAndALaterOneDoesNot(t *testing.T) {
	base, fp := whoamiServer(t, "alice", "admin")
	path := credsFile(t)

	code, _, errb := runWithStdin(t, "nodary_pt_secret\n",
		"login", "--server", base, "--credentials", path)
	if code != ExitUsage {
		t.Fatalf("a first login with no pin: exit = %d, want %d (%s)", code, ExitUsage, errb)
	}
	if !strings.Contains(errb, "server install") {
		t.Errorf("the refusal does not say where the fingerprint comes from: %q", errb)
	}

	if code, _, errb = runWithStdin(t, "nodary_pt_secret\n",
		"login", "--server", base, "--ca-fingerprint", fp, "--credentials", path); code != ExitOK {
		t.Fatalf("login = %d (%s)", code, errb)
	}
	// The second one reuses the stored pin: rotating a token must not require
	// the operator to go and find the fingerprint again.
	if code, _, errb = runWithStdin(t, "nodary_pt_secret\n",
		"login", "--server", base, "--credentials", path); code != ExitOK {
		t.Fatalf("a second login with no pin: exit = %d, want %d (%s)", code, ExitOK, errb)
	}
}

// The credential is keyed by the appliance, and the key has to be one value
// for the several ways an operator writes the same one.
func TestOneApplianceIsOneKeyHoweverItIsWritten(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{"https://host:8443", "https://host:8443"},
		{"host:8443", "https://host:8443"},
		{"  https://host:8443/  ", "https://host:8443"},
		{"https://host:8443/api/v1", "https://host:8443"},
	} {
		got, err := normalizeServer(c.in)
		if err != nil {
			t.Errorf("normalizeServer(%q): %v", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("normalizeServer(%q) = %q, want %q", c.in, got, c.want)
		}
	}
	// A credential is not sent over a channel that does not authenticate the
	// far end, and "no scheme" resolves to https rather than to the other one.
	for _, bad := range []string{"http://host:8443", "", "https://"} {
		if got, err := normalizeServer(bad); err == nil {
			t.Errorf("normalizeServer(%q) = %q, want a refusal", bad, got)
		}
	}
}

// --server is rolling out one verb at a time, and the failure that matters is
// not a poor message: it is an operator believing they acted on an appliance
// across the room while the command edited this host's database.
func TestAVerbThatDoesNotSpeakToAServerRefusesRatherThanActingLocally(t *testing.T) {
	code, out, errb := run(t, "user", "list", "--server", "https://host:8443")
	if code != ExitUsage {
		t.Fatalf("exit = %d, want %d\n%s%s", code, ExitUsage, out, errb)
	}
	if !strings.Contains(errb, "--server") {
		t.Errorf("the refusal does not name the flag: %q", errb)
	}
	if out != "" {
		t.Errorf("a verb refused for --server produced output anyway: %q", out)
	}
}

// A control plane that is down is not a refusal, and docs/specs/10-cli.md §5
// gives it its own code: a script retries an unreachable appliance and must
// not retry a 403.
func TestAnUnreachableControlPlaneIsItsOwnExitCode(t *testing.T) {
	base, fp := whoamiServer(t, "alice", "admin")
	path := credsFile(t)
	if code, _, errb := runWithStdin(t, "nodary_pt_secret\n",
		"login", "--server", base, "--ca-fingerprint", fp, "--credentials", path); code != ExitOK {
		t.Fatalf("login = %d (%s)", code, errb)
	}
	creds, err := identity.LoadCredentials(path)
	if err != nil {
		t.Fatal(err)
	}
	cred, _ := creds.Token(base)
	r := &remote{base: "https://127.0.0.1:1", cred: cred}
	if r.c, err = agent.Client(fp, nil); err != nil {
		t.Fatal(err)
	}
	err = r.do("GET", "/auth/whoami", nil, nil)
	if err == nil {
		t.Fatal("a closed port answered")
	}
	if got := exitFor(err); got != ExitUnreachable {
		t.Errorf("exit = %d, want %d (%v)", got, ExitUnreachable, err)
	}
}

// The stable codes of docs/specs/09-api.md §3 are a second table beside
// internal/api's statusFor, and a second table is one that drifts. A refusal
// the control plane can state and this client has no meaning for arrives as a
// generic failure, so the exit code a script sees would silently stop matching
// the one the same refusal produces locally.
func TestEveryRefusalTheApiCanStateHasAnExitCodeHere(t *testing.T) {
	quoted := regexp.MustCompile(`"(\w+)"`)
	served := map[string]bool{}
	for _, m := range quoted.FindAllStringSubmatch(
		between(t, filepath.Join("..", "api", "errors.go"), "func statusFor(", "\nvar ("), -1) {
		served[m[1]] = true
	}
	if len(served) < 10 {
		t.Fatalf("found %d codes in statusFor, which is too few to be right", len(served))
	}
	handled := map[string]bool{}
	for _, m := range quoted.FindAllStringSubmatch(
		between(t, "remote.go", "func (e *remoteError) exit()", "\n}"), -1) {
		handled[m[1]] = true
	}
	for code := range served {
		if !handled[code] {
			t.Errorf("the API can refuse with %q and remoteError.exit does not name it; "+
				"decide which exit code docs/specs/10-cli.md §5 gives it", code)
		}
	}
}

// between returns the part of a file's source from one marker to the next, so a
// test can read a single function rather than the whole file.
func between(t *testing.T, path, from, to string) string {
	t.Helper()
	src, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	body := string(src)
	start := strings.Index(body, from)
	if start < 0 {
		t.Fatalf("%s no longer contains %q; update the test", path, from)
	}
	end := strings.Index(body[start:], to)
	if end < 0 {
		t.Fatalf("%s: %q does not end with %q; update the test", path, from, to)
	}
	return body[start : start+end]
}
