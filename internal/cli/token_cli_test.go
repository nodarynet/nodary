package cli

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/nodarynet/nodary/internal/paths"
)

func TestTokenCreatePrintsTheCredentialAloneOnStdout(t *testing.T) {
	a := newAppliance(t)
	a.addUser("alice", "operator")

	code, stdout, stderr := a.run("token", "create", "--user", "alice", "--name", "laptop")
	if code != ExitOK {
		t.Fatalf("exit = %d: %s", code, stderr)
	}
	plain := strings.TrimSpace(stdout)
	if plain != strings.TrimRight(stdout, "\n") {
		t.Errorf("stdout carries decoration around the credential: %q", stdout)
	}
	if !strings.HasPrefix(plain, "nodary_pt_") {
		t.Fatalf("stdout = %q, want a personal token", stdout)
	}
	// Everything a human needs is on the other stream, so the capture is clean.
	for _, want := range []string{"shown once", "expires", "tok_"} {
		if !strings.Contains(stderr, want) {
			t.Errorf("stderr should mention %q: %q", want, stderr)
		}
	}
	if strings.Contains(stderr, plain) {
		t.Error("the credential was repeated on stderr")
	}

	// It never appears again, in any form.
	for _, args := range [][]string{
		{"token", "list"},
		{"token", "list", "--format", "json"},
		{"user", "show", "alice", "--format", "json"},
	} {
		_, out, _ := a.run(args...)
		if strings.Contains(out, plain) {
			t.Errorf("%v carries the credential: %q", args, out)
		}
	}

	code, stdout, _ = a.run("token", "list", "--format", "json")
	if code != ExitOK {
		t.Fatal(code)
	}
	var doc struct {
		Tokens []tokenReport `json:"tokens"`
	}
	if err := json.Unmarshal([]byte(stdout), &doc); err != nil {
		t.Fatalf("%v in %q", err, stdout)
	}
	if len(doc.Tokens) != 1 {
		t.Fatalf("tokens = %+v", doc.Tokens)
	}
	got := doc.Tokens[0]
	if got.Kind != "pt" || got.Name != "laptop" || got.State != "active" {
		t.Errorf("token = %+v", got)
	}
	// The display prefix identifies the credential without being one.
	if !strings.HasPrefix(plain, got.Prefix) || got.Prefix == plain {
		t.Errorf("prefix %q does not identify %q", got.Prefix, plain)
	}
}

// TestSavedCredentialsAuthenticateTheNextCommand is R1-22 end to end, and the
// point of the file: the next command acts as alice rather than as the machine.
func TestSavedCredentialsAuthenticateTheNextCommand(t *testing.T) {
	a := newAppliance(t)
	a.addUser("alice", "admin")

	if code, _, stderr := a.run("token", "create", "--user", "alice", "--save"); code != ExitOK {
		t.Fatalf("exit = %d: %s", code, stderr)
	}
	fi, err := os.Stat(a.creds)
	if err != nil {
		t.Fatal(err)
	}
	if got := fi.Mode().Perm(); got != paths.ModeCredentials {
		t.Errorf("credentials mode = %#o, want %#o", got, paths.ModeCredentials)
	}

	// Acting as alice now: the record has to name her, not the operating
	// system account that ran the command.
	if code, _, stderr := a.run("user", "add", "bob", "--role", "viewer"); code != ExitOK {
		t.Fatalf("as alice: exit = %d: %s", code, stderr)
	}
	_, stdout, _ := a.run("user", "show", "alice", "--format", "json")
	var who struct {
		User userReport `json:"user"`
	}
	if err := json.Unmarshal([]byte(stdout), &who); err != nil {
		t.Fatal(err)
	}

	code, stdout, _ := run(t, "audit", "list", "--db", a.db, "--action", "user.add",
		"--format", "json")
	if code != ExitOK {
		t.Fatal(code)
	}
	var records struct {
		Records []struct {
			Actor struct {
				ID      string `json:"id"`
				Method  string `json:"method"`
				Session string `json:"session"`
			} `json:"actor"`
		} `json:"records"`
	}
	if err := json.Unmarshal([]byte(stdout), &records); err != nil {
		t.Fatalf("%v in %q", err, stdout)
	}
	if len(records.Records) != 2 {
		t.Fatalf("records = %+v, want two user.add", records.Records)
	}
	// Newest first: adding bob was done with the credential.
	latest := records.Records[0].Actor
	if latest.ID != who.User.ID || latest.Method != "token" || latest.Session == "" {
		t.Errorf("actor = %+v, want alice by token", latest)
	}
	// And the first one, before any credential existed, was local.
	if first := records.Records[1].Actor; first.Method != "local" {
		t.Errorf("the bootstrap action was recorded as %+v, want local", first)
	}
}

// TestAnAuthenticatedNonAdminIsRefused is where the role table stops being
// theoretical: the principal comes from a credential, and the check bites.
func TestAnAuthenticatedNonAdminIsRefused(t *testing.T) {
	a := newAppliance(t)
	a.addUser("alice", "operator")
	if code, _, stderr := a.run("token", "create", "--user", "alice", "--save"); code != ExitOK {
		t.Fatalf("exit = %d: %s", code, stderr)
	}

	code, stdout, stderr := a.run("user", "add", "bob", "--role", "viewer")
	if code != ExitAuth {
		t.Fatalf("exit = %d, want %d: %s", code, ExitAuth, stderr)
	}
	if stdout != "" {
		t.Errorf("a refusal wrote to stdout: %q", stdout)
	}
	if !strings.Contains(stderr, "user.manage") {
		t.Errorf("stderr should name the missing permission: %q", stderr)
	}
	// The refusal is itself recorded, and the operator is told where.
	if !strings.Contains(stderr, "audit record") {
		t.Errorf("a refusal must name its record: %q", stderr)
	}

	if _, out, _ := a.run("user", "list"); strings.Contains(out, "bob") {
		t.Error("a refused add created the user")
	}
}

func TestTokenRevoke(t *testing.T) {
	a := newAppliance(t)
	a.addUser("alice", "operator")
	_, stdout, _ := a.run("token", "create", "--user", "alice")
	plain := strings.TrimSpace(stdout)

	_, stdout, _ = a.run("token", "list", "--format", "json")
	var doc struct {
		Tokens []tokenReport `json:"tokens"`
	}
	if err := json.Unmarshal([]byte(stdout), &doc); err != nil {
		t.Fatal(err)
	}
	id := doc.Tokens[0].ID

	if code, _, stderr := a.run("token", "revoke", id); code != ExitOK {
		t.Fatalf("revoke: exit = %d: %s", code, stderr)
	}
	// Revoking twice is a precondition failure, so a script can tell "already
	// gone" from "that did not work".
	if code, _, _ := a.run("token", "revoke", id); code != ExitPrecondition {
		t.Errorf("second revoke: exit = %d, want %d", code, ExitPrecondition)
	}
	if code, _, _ := a.run("token", "revoke", "tok_missing"); code != ExitFailure {
		t.Errorf("unknown id: exit = %d, want %d", code, ExitFailure)
	}

	_, stdout, _ = a.run("token", "list", "--format", "json")
	if err := json.Unmarshal([]byte(stdout), &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Tokens[0].State != "revoked" || doc.Tokens[0].RevokedAt == "" {
		t.Errorf("token = %+v, want revoked with a time", doc.Tokens[0])
	}
	_ = plain
}

func TestTokenJoinMustExpire(t *testing.T) {
	a := newAppliance(t)

	code, stdout, stderr := a.run("token", "join", "--uses", "2", "--expires", "2h")
	if code != ExitOK {
		t.Fatalf("exit = %d: %s", code, stderr)
	}
	if !strings.HasPrefix(strings.TrimSpace(stdout), "nodary_jt_") {
		t.Fatalf("stdout = %q, want a join token", stdout)
	}
	if !strings.Contains(stderr, "2 use(s)") {
		t.Errorf("stderr should say how many uses: %q", stderr)
	}

	// A join token that never expires enrolls anybody, forever.
	code, _, stderr = a.run("token", "join", "--expires", "never")
	if code != ExitUsage {
		t.Errorf("never: exit = %d, want %d", code, ExitUsage)
	}
	// The library refuses a zero expiry too, so this asserts on the reason the
	// command gives rather than only on the refusal: the two are redundant,
	// and the one worth keeping is the one that says what goes wrong.
	if !strings.Contains(stderr, "enrolls anybody, forever") {
		t.Errorf("stderr should say why never is refused: %q", stderr)
	}

	code, stdout, _ = a.run("token", "list", "--format", "json")
	if code != ExitOK {
		t.Fatal(code)
	}
	var doc struct {
		JoinTokens []joinReport `json:"join_tokens"`
	}
	if err := json.Unmarshal([]byte(stdout), &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.JoinTokens) != 1 || doc.JoinTokens[0].UsesLeft != 2 {
		t.Fatalf("join tokens = %+v", doc.JoinTokens)
	}
	if !strings.HasPrefix(doc.JoinTokens[0].Prefix, "nodary_jt_") {
		t.Errorf("join token %+v has no usable prefix", doc.JoinTokens[0])
	}
}

func TestTokenCreateUsage(t *testing.T) {
	a := newAppliance(t)
	a.addUser("alice", "operator")

	for _, tc := range []struct {
		what string
		args []string
	}{
		{"no user", []string{"token", "create"}},
		{"a join token for a user", []string{"token", "create", "--user", "alice", "--kind", "jt"}},
		{"an unknown kind", []string{"token", "create", "--user", "alice", "--kind", "zz"}},
		{"a bad lifetime", []string{"token", "create", "--user", "alice", "--expires", "soon"}},
		{"saving a service key", []string{"token", "create", "--user", "alice", "--kind", "sk", "--save"}},
		{"a stray argument", []string{"token", "create", "--user", "alice", "extra"}},
	} {
		code, stdout, stderr := a.run(tc.args...)
		if code != ExitUsage {
			t.Errorf("%s: exit = %d, want %d (%s)", tc.what, code, ExitUsage, stderr)
		}
		if stdout != "" {
			t.Errorf("%s: wrote %q to stdout", tc.what, stdout)
		}
	}
}

func TestParseLifetime(t *testing.T) {
	for _, tc := range []struct {
		in    string
		hours float64
		bad   bool
	}{
		{"never", 0, false},
		{"90d", 90 * 24, false},
		{"0d", 0, false},
		{"12h", 12, false},
		{"30m", 0.5, false},
		{"", 0, true},
		{"soon", 0, true},
		{"-5d", 0, true},
		{"-12h", 0, true},
		{"xd", 0, true},
	} {
		d, err := parseLifetime(tc.in)
		if tc.bad {
			if err == nil {
				t.Errorf("parseLifetime(%q) = %v, want an error", tc.in, d)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseLifetime(%q): %v", tc.in, err)
			continue
		}
		if got := d.Hours(); got != tc.hours {
			t.Errorf("parseLifetime(%q) = %vh, want %vh", tc.in, got, tc.hours)
		}
	}
}
