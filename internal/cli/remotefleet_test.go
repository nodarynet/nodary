package cli

import (
	"context"
	"io"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nodarynet/nodary/internal/agent"
	"github.com/nodarynet/nodary/internal/api"
	"github.com/nodarynet/nodary/internal/audit"
	"github.com/nodarynet/nodary/internal/secret"
	"github.com/nodarynet/nodary/internal/store"
)

// servedBy stands the real control plane up over TLS against this appliance's
// own database, and logs a credential in for role.
//
// A hand-written stub would answer whatever this test expected, which is the
// one thing a client test must not rely on: what is being checked is that the
// CLI and the handler agree about a JSON shape neither of them declares in one
// place. Against the real handler, a field renamed on one side fails here.
func (a *appliance) servedBy(t *testing.T, user, role string) (base string) {
	t.Helper()
	ctx := context.Background()

	a.addUser(user, role)
	code, token, stderr := a.run("token", "create", "--user", user, "--justify", "remote administration")
	if code != ExitOK {
		t.Fatalf("token create: exit %d, %s", code, stderr)
	}
	token = strings.TrimSpace(token)

	db, err := store.Open(ctx, a.db)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if err := db.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	key, err := secret.Create(a.key)
	if err != nil {
		t.Fatal(err)
	}
	delivery, err := audit.DeliveryFor("none", "", io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { delivery.Close() })

	pki := filepath.Join(a.dir, "pki")
	if err := os.MkdirAll(pki, 0o750); err != nil {
		t.Fatal(err)
	}
	if _, err := api.EnsureAgentCA(ctx, pki, key, time.Now()); err != nil {
		t.Fatal(err)
	}
	srv := api.New(api.Options{DB: db, Log: audit.New(db, delivery),
		Key: func() (*secret.Key, error) { return key, nil }, PKI: pki, Now: time.Now})

	ts := httptest.NewTLSServer(srv.Handler())
	t.Cleanup(ts.Close)

	if code, _, stderr := runWithStdin(t, token+"\n", "login", "--server", ts.URL,
		"--ca-fingerprint", agent.Fingerprint(ts.Certificate().Raw),
		"--credentials", a.creds); code != ExitOK {
		t.Fatalf("login: exit %d, %s", code, stderr)
	}
	return ts.URL
}

// The whole point of --server is that the answer is the same one. The endpoint
// and the verb both call internal/fleet (R2-34), so a difference here is a
// difference in what crossed the wire, which is the only new thing.
func TestNodeListAndShowAnswerTheSameOverServerAsLocally(t *testing.T) {
	a := newAppliance(t)
	a.enrolled("gpu-01")
	base := a.servedBy(t, "alice", "admin")

	for _, c := range []struct {
		what string
		args []string
	}{
		{"node list", []string{"node", "list"}},
		{"node show", []string{"node", "show", "gpu-01"}},
		{"route list", []string{"route", "list"}},
		{"limits show", []string{"limits", "show"}},
	} {
		local, out, stderr := run(t, append(append([]string{}, c.args...), "--db", a.db, "--format", "json")...)
		if local != ExitOK {
			t.Fatalf("%s locally: exit %d, %s", c.what, local, stderr)
		}
		remoteCode, remoteOut, stderr := run(t, append(append([]string{}, c.args...),
			"--server", base, "--credentials", a.creds, "--format", "json")...)
		if remoteCode != ExitOK {
			t.Fatalf("%s over --server: exit %d, %s", c.what, remoteCode, stderr)
		}
		if remoteOut != out {
			t.Errorf("%s differs between the two routes:\n  local  %s\n  remote %s",
				c.what, out, remoteOut)
		}
	}
}

// A node that is not there is a refusal, not an empty rendering, and it says
// the same thing either way.
func TestAMissingNodeIsRefusedOverServerToo(t *testing.T) {
	a := newAppliance(t)
	base := a.servedBy(t, "alice", "admin")

	code, _, stderr := run(t, "node", "show", "nowhere", "--server", base,
		"--credentials", a.creds)
	if code == ExitOK {
		t.Fatal("a node that does not exist was shown")
	}
	if !strings.Contains(stderr, "nowhere") {
		t.Errorf("the refusal does not name the node: %q", stderr)
	}
}

// A viewer may read the fleet and an unauthenticated caller may not, and both
// answers have to come back as the exit code the same refusal costs locally.
func TestTheControlPlanesAnswerDecidesWhoMayRead(t *testing.T) {
	a := newAppliance(t)
	a.enrolled("gpu-01")
	base := a.servedBy(t, "viewer-vera", "viewer")

	if code, _, stderr := run(t, "node", "list", "--server", base,
		"--credentials", a.creds); code != ExitOK {
		t.Fatalf("a viewer could not read the fleet: exit %d, %s", code, stderr)
	}

	// The credential is what authorizes, so a file with none is ExitAuth and
	// names the verb that fixes it rather than falling back to this host.
	code, out, stderr := run(t, "node", "list", "--server", base,
		"--credentials", filepath.Join(t.TempDir(), "none"))
	if code != ExitAuth {
		t.Errorf("no credential: exit = %d, want %d (%s)", code, ExitAuth, stderr)
	}
	if !strings.Contains(stderr, "nodary login") {
		t.Errorf("the refusal does not say how to fix it: %q", stderr)
	}
	if out != "" {
		t.Errorf("output was produced without a credential: %q", out)
	}
}

// --server and --db name different control planes. Resolving that quietly is
// the failure this flag is most careful about: an operator who believed they
// were reading one database and read another.
func TestServerAndDbTogetherAreRefused(t *testing.T) {
	a := newAppliance(t)
	base := a.servedBy(t, "alice", "admin")

	code, out, stderr := run(t, "node", "list", "--server", base, "--db", a.db,
		"--credentials", a.creds)
	if code != ExitUsage {
		t.Fatalf("exit = %d, want %d\n%s%s", code, ExitUsage, out, stderr)
	}
	if !strings.Contains(stderr, "--db") {
		t.Errorf("the refusal does not name both flags: %q", stderr)
	}
}
