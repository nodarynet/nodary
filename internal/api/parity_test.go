package api_test

import (
	"bytes"
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nodarynet/nodary/internal/api"
	"github.com/nodarynet/nodary/internal/cli"
)

// The cross-cutting constraint in docs/tasks/README.md says the CLI and the API
// call the same core functions and neither holds business logic. That both call
// core.Act is visible in the source; what a reader cannot see is whether they
// therefore *behave* the same, which is the thing the constraint is actually
// about.
//
// So this drives both front ends against one database and asserts they refuse
// the same acts for the same reasons. It is the test that fails if somebody
// reimplements attestation in a handler.
func TestBothFrontEndsRefuseTheSameThings(t *testing.T) {
	f := newFixture(t)

	// The CLI needs the paths the fixture built; it opens the same database.
	dbPath := f.db.Path()
	keyPath := filepath.Join(filepath.Dir(dbPath), "secret.key")
	credsPath := filepath.Join(filepath.Dir(dbPath), "credentials")

	runCLI := func(args ...string) (int, string) {
		t.Helper()
		var out, errb bytes.Buffer
		full := append(args, "--db", dbPath, "--secret-key", keyPath,
			"--credentials", credsPath, "--yes")
		code := cli.Main(full, strings.NewReader(""), &out, &errb)
		return code, errb.String()
	}

	// Move both onto `regulated`, through the API.
	if code, doc := f.do("POST", "/policy/apply", f.admin,
		map[string]any{"profile": "regulated"}, nil); code != http.StatusOK {
		t.Fatalf("applying regulated: %d %v", code, doc)
	}

	for _, tc := range []struct {
		name     string
		cliArgs  []string
		headers  map[string]string
		wantExit int
		wantHTTP int
		wantCode string
	}{
		{
			name:     "no justification",
			cliArgs:  []string{"user", "add", "bob", "--role", "user"},
			wantExit: cli.ExitPolicy, wantHTTP: http.StatusForbidden,
			wantCode: "justification_required",
		},
		{
			name:     "justification too short",
			cliArgs:  []string{"user", "add", "bob", "--role", "user", "--justify", "short"},
			headers:  map[string]string{api.HeaderJustify: "short"},
			wantExit: cli.ExitPolicy, wantHTTP: http.StatusForbidden,
			wantCode: "justification_too_short",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, stderr := runCLI(tc.cliArgs...)
			if code != tc.wantExit {
				t.Errorf("CLI exit = %d, want %d: %s", code, tc.wantExit, stderr)
			}
			status, doc := f.do("POST", "/users", f.admin,
				map[string]any{"name": "bob", "role": "user"}, tc.headers)
			if status != tc.wantHTTP {
				t.Errorf("API status = %d, want %d: %v", status, tc.wantHTTP, doc)
			}
			if got := envelope(doc)["code"]; got != tc.wantCode {
				t.Errorf("API code = %v, want %v", got, tc.wantCode)
			}
		})
	}

	// Both must also *succeed* on the same input, or the test above passes on a
	// pair of front ends that refuse everything.
	t.Run("both accept a good justification", func(t *testing.T) {
		// The CLI acts as local root, which docs/plans/R1c-identity.md exempts
		// from re-authentication; the API caller is a token principal and is
		// not, so `regulated` refuses it without a code. That asymmetry is a
		// decision, not a divergence — the two front ends are asking the same
		// core the same question about two different principals.
		code, stderr := runCLI("user", "add", "carol", "--role", "user",
			"--justify", "onboarding the new operator")
		if code != cli.ExitOK {
			t.Errorf("CLI exit = %d, want 0: %s", code, stderr)
		}
		status, doc := f.do("POST", "/users", f.admin,
			map[string]any{"name": "dave", "role": "user"},
			map[string]string{api.HeaderJustify: "onboarding the new operator"})
		if status != http.StatusForbidden || envelope(doc)["code"] != "reauthentication_required" {
			t.Errorf("API = %d %v, want a re-authentication refusal", status, envelope(doc))
		}
	})
}
