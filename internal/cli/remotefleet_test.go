package cli

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/nodarynet/nodary/internal/agent"
	"github.com/nodarynet/nodary/internal/api"
	"github.com/nodarynet/nodary/internal/audit"
	"github.com/nodarynet/nodary/internal/identity"
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
	a.pin = agent.Fingerprint(ts.Certificate().Raw)

	if code, _, stderr := runWithStdin(t, token+"\n", "login", "--server", ts.URL,
		"--ca-fingerprint", a.pin, "--credentials", a.creds); code != ExitOK {
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

// The whole argument for --server, asserted rather than described: the record
// names the person holding the credential, and the same act run on the host
// names root and the method `local`.
func TestAnApprovalOverServerIsAttributedToThePersonNotToRoot(t *testing.T) {
	a := newAppliance(t)
	a.enrolled("gpu-01")
	base := a.servedBy(t, "alice", "admin")

	code, _, stderr := run(t, "node", "approve", "gpu-01", "--server", base,
		"--credentials", a.creds, "--justify", "alice approved this node")
	if code != ExitOK {
		t.Fatalf("node approve over --server: exit %d, %s", code, stderr)
	}

	code, out, stderr := a.run("audit", "list", "--format", "json")
	if code != ExitOK {
		t.Fatalf("audit list: exit %d, %s", code, stderr)
	}
	var listing struct {
		Records []struct {
			Action string `json:"action"`
			Actor  struct {
				ID     string `json:"id"`
				Method string `json:"method"`
			} `json:"actor"`
			Justification string `json:"justification"`
		} `json:"records"`
	}
	if err := json.Unmarshal([]byte(out), &listing); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	var found bool
	for _, rec := range listing.Records {
		if rec.Action != "node.approve" {
			continue
		}
		found = true
		if rec.Actor.Method == "local" {
			t.Errorf("an approval made over the network was recorded as a local act")
		}
		if rec.Actor.ID == "root" || rec.Actor.ID == "" {
			t.Errorf("actor = %q, want the account the credential belongs to", rec.Actor.ID)
		}
		if rec.Justification != "alice approved this node" {
			t.Errorf("justification = %q; --justify did not reach the control plane",
				rec.Justification)
		}
	}
	if !found {
		t.Fatalf("no node.approve record was written at all:\n%s", out)
	}

	// And the node actually moved, which is the other half: a record of
	// something that did not happen would pass every assertion above.
	code, out, stderr = run(t, "node", "show", "gpu-01", "--server", base,
		"--credentials", a.creds, "--format", "json")
	if code != ExitOK {
		t.Fatalf("node show: exit %d, %s", code, stderr)
	}
	if !strings.Contains(out, `"state": "approved"`) {
		t.Errorf("the node did not move to approved:\n%s", out)
	}
}

// --dry-run over the network renders and hashes on the control plane and
// applies nothing, which is what makes the hash worth binding: it is the same
// core.Preview hash the apply is checked against.
func TestADryRunOverServerAppliesNothing(t *testing.T) {
	a := newAppliance(t)
	a.enrolled("gpu-01")
	base := a.servedBy(t, "alice", "admin")

	code, out, stderr := run(t, "node", "approve", "gpu-01", "--server", base,
		"--credentials", a.creds, "--justify", "checking first", "--dry-run", "--format", "json")
	if code != ExitOK {
		t.Fatalf("exit %d, %s", code, stderr)
	}
	var doc struct {
		DryRun     bool   `json:"dry_run"`
		Action     string `json:"action"`
		IntentHash string `json:"intent_hash"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if !doc.DryRun || doc.Action != "node.approve" || doc.IntentHash == "" {
		t.Errorf("dry run = %+v, want the action and a hash", doc)
	}

	code, out, stderr = run(t, "node", "show", "gpu-01", "--server", base,
		"--credentials", a.creds, "--format", "json")
	if code != ExitOK {
		t.Fatalf("node show: exit %d, %s", code, stderr)
	}
	if !strings.Contains(out, `"state": "pending"`) {
		t.Errorf("a dry run moved the node:\n%s", out)
	}
}

// The permission table is the control plane's, and it stays the control
// plane's: a viewer with a valid credential is refused the act, at the exit
// code the same refusal costs locally.
func TestAViewerIsRefusedTheActOverServer(t *testing.T) {
	a := newAppliance(t)
	a.enrolled("gpu-01")
	base := a.servedBy(t, "viewer-vera", "viewer")

	code, _, stderr := run(t, "node", "approve", "gpu-01", "--server", base,
		"--credentials", a.creds, "--justify", "not mine to make")
	if code != ExitAuth {
		t.Fatalf("exit = %d, want %d (%s)", code, ExitAuth, stderr)
	}
	code, out, _ := run(t, "node", "show", "gpu-01", "--db", a.db, "--format", "json")
	if code != ExitOK || !strings.Contains(out, `"state": "pending"`) {
		t.Errorf("a refused approval moved the node anyway:\n%s", out)
	}
}

// The three model verbs over --server, against the endpoints that run the same
// config.SetDisabled and fleet.RestartTargets the local verbs run.
func TestModelEnableDisableAndRestartOverServer(t *testing.T) {
	a := newAppliance(t)
	a.enrolled("gpu-01")
	base := a.servedBy(t, "alice", "admin")
	if code, _, stderr := a.run("node", "approve", "gpu-01", "--yes",
		"--justify", "test fixture"); code != ExitOK {
		t.Fatalf("node approve: exit %d, %s", code, stderr)
	}
	a.registerModel(t, "acme/tiny", "gpu-01")

	for _, c := range []struct {
		verb string
		want bool
	}{{"disable", true}, {"enable", false}} {
		code, _, stderr := run(t, "model", c.verb, "acme/tiny", "--server", base,
			"--credentials", a.creds, "--justify", "toggling over the network")
		if code != ExitOK {
			t.Fatalf("model %s over --server: exit %d, %s", c.verb, code, stderr)
		}
		if got := a.deploymentDisabled(t, "acme/tiny"); got != c.want {
			t.Errorf("model %s over --server: disabled = %v, want %v", c.verb, got, c.want)
		}
	}

	// Restart is edge-triggered and its own table, so the evidence it worked is
	// the record rather than a column in the snapshot.
	code, _, stderr := run(t, "model", "restart", "acme/tiny", "--node", "gpu-01",
		"--server", base, "--credentials", a.creds, "--justify", "cycling it")
	if code != ExitOK {
		t.Fatalf("model restart over --server: exit %d, %s", code, stderr)
	}
	code, out, stderr := a.run("audit", "list", "--format", "json")
	if code != ExitOK {
		t.Fatalf("audit list: exit %d, %s", code, stderr)
	}
	for _, want := range []string{"model.disable", "model.enable", "model.restart"} {
		if !strings.Contains(out, `"`+want+`"`) {
			t.Errorf("no %s record was written:\n%s", want, out)
		}
	}

	// A model with no deployment is a refusal naming it, not a quiet no-op
	// that leaves an operator believing something stopped.
	code, _, stderr = run(t, "model", "disable", "acme/absent", "--server", base,
		"--credentials", a.creds, "--justify", "nothing to disable")
	if code == ExitOK {
		t.Error("disabling a model with no deployment reported success")
	}
	if !strings.Contains(stderr, "acme/absent") {
		t.Errorf("the refusal does not name the model: %q", stderr)
	}
}

// --node narrows the toggle, and it has to narrow it on the far side too: a
// flag accepted here and dropped on the wire turns "disable it on gpu-02" into
// "disable it everywhere", which is an outage rather than a change.
func TestNodeNarrowsAToggleOverServer(t *testing.T) {
	a := newAppliance(t)
	for _, n := range []string{"gpu-01", "gpu-02"} {
		a.enrolled(n)
		if code, _, stderr := a.run("node", "approve", n, "--yes",
			"--justify", "test fixture"); code != ExitOK {
			t.Fatalf("node approve %s: exit %d, %s", n, code, stderr)
		}
	}
	base := a.servedBy(t, "alice", "admin")
	a.registerModel(t, "acme/tiny", "gpu-01")
	a.registerModelOnGPU(t, "acme/tiny", "gpu-02", 0)

	if code, _, stderr := run(t, "model", "disable", "acme/tiny", "--node", "gpu-02",
		"--server", base, "--credentials", a.creds, "--justify", "draining one node"); code != ExitOK {
		t.Fatalf("model disable --node: exit %d, %s", code, stderr)
	}

	code, out, stderr := run(t, "node", "show", "gpu-01", "--server", base,
		"--credentials", a.creds, "--format", "json")
	if code != ExitOK {
		t.Fatalf("node show gpu-01: exit %d, %s", code, stderr)
	}
	if strings.Contains(out, `"disabled": true`) {
		t.Error("--node did not narrow the toggle: gpu-01 was disabled too")
	}
	if code, out, stderr = run(t, "node", "show", "gpu-02", "--server", base,
		"--credentials", a.creds, "--format", "json"); code != ExitOK {
		t.Fatalf("node show gpu-02: exit %d, %s", code, stderr)
	}
	if !strings.Contains(out, `"disabled": true`) {
		t.Errorf("the node named was not disabled:\n%s", out)
	}
}

// `route set` reads the route and replaces it, which is three steps where the
// local route has one transaction — so the membership it writes has to be
// built from what it read, and the revision it read at has to travel with the
// write.
func TestRouteSetOverServerEditsRatherThanReplaces(t *testing.T) {
	a := newAppliance(t)
	a.enrolled("gpu-01")
	if code, _, stderr := a.run("node", "approve", "gpu-01", "--yes",
		"--justify", "test fixture"); code != ExitOK {
		t.Fatalf("node approve: exit %d, %s", code, stderr)
	}
	base := a.servedBy(t, "alice", "admin")
	a.registerModel(t, "acme/tiny", "gpu-01")

	members := func() []string {
		t.Helper()
		code, out, stderr := run(t, "route", "show", "tiny", "--server", base,
			"--credentials", a.creds, "--format", "json")
		if code != ExitOK {
			t.Fatalf("route show: exit %d, %s", code, stderr)
		}
		var route struct {
			Members []struct {
				DeploymentID string `json:"deployment_id"`
			} `json:"members"`
		}
		if err := json.Unmarshal([]byte(out), &route); err != nil {
			t.Fatalf("%v\n%s", err, out)
		}
		ids := []string{}
		for _, m := range route.Members {
			ids = append(ids, m.DeploymentID)
		}
		return ids
	}

	// A second real deployment to move in and out of the route. A member the
	// control plane does not have is refused by the applier, which is a
	// different test below.
	a.registerModelOnGPU(t, "acme/other", "gpu-01", 1)
	second := "other-gpu-01"

	// register put one member in. Adding a second must keep the first: a PUT
	// built from flags alone rather than from what was read would drop it.
	before := members()
	if len(before) != 1 {
		t.Fatalf("fixture: members = %v, want one", before)
	}
	if code, _, stderr := run(t, "route", "set", "tiny", "--add", second,
		"--server", base, "--credentials", a.creds, "--justify", "adding a replica"); code != ExitOK {
		t.Fatalf("route set --add: exit %d, %s", code, stderr)
	}
	after := members()
	if len(after) != 2 || !slices.Contains(after, before[0]) || !slices.Contains(after, second) {
		t.Errorf("members = %v, want %v plus %s", after, before, second)
	}

	// And removing takes one away rather than emptying the route.
	if code, _, stderr := run(t, "route", "set", "tiny", "--remove", second,
		"--server", base, "--credentials", a.creds, "--justify", "removing it again"); code != ExitOK {
		t.Fatalf("route set --remove: exit %d, %s", code, stderr)
	}
	if got := members(); len(got) != 1 || got[0] != before[0] {
		t.Errorf("members = %v, want %v", got, before)
	}

	// A route that does not exist yet is created, the way the local verb
	// creates one, rather than refused for not being there to read.
	if code, _, stderr := run(t, "route", "set", "fresh", "--add", second,
		"--server", base, "--credentials", a.creds, "--justify", "a new route"); code != ExitOK {
		t.Fatalf("route set on a new route: exit %d, %s", code, stderr)
	}
	code, out, stderr := run(t, "route", "list", "--server", base,
		"--credentials", a.creds, "--format", "json")
	if code != ExitOK {
		t.Fatalf("route list: exit %d, %s", code, stderr)
	}
	if !strings.Contains(out, `"fresh"`) {
		t.Errorf("the new route was not created:\n%s", out)
	}
}

// limits set builds the whole object from its flags, so the remote route is a
// plain replace and the values have to arrive intact.
func TestLimitsSetOverServer(t *testing.T) {
	a := newAppliance(t)
	base := a.servedBy(t, "alice", "admin")

	if code, _, stderr := run(t, "limits", "set", "--kind", "global", "--rpm", "60",
		"--tpm", "9000", "--server", base, "--credentials", a.creds,
		"--justify", "site-wide ceiling"); code != ExitOK {
		t.Fatalf("limits set over --server: exit %d, %s", code, stderr)
	}
	code, out, stderr := run(t, "limits", "show", "--server", base,
		"--credentials", a.creds, "--format", "json")
	if code != ExitOK {
		t.Fatalf("limits show: exit %d, %s", code, stderr)
	}
	for _, want := range []string{`"rpm": 60`, `"tpm": 9000`, `"subject_kind": "global"`} {
		if !strings.Contains(out, want) {
			t.Errorf("limits show does not carry %s:\n%s", want, out)
		}
	}
}

// The constraint R2-34 is about, at the level a script sees: one refusal, two
// roads, one exit code.
//
// It is not automatic. docs/specs/09-api.md §3's codes and
// docs/specs/10-cli.md §5's exit codes are two tables, and they are filled in
// by different people at different times — `config.ErrInvalid` and
// `identity.ErrBadName` shared one code while the CLI answered them 1 and 2,
// which this caught.
func TestOneRefusalCostsOneExitCodeWhicheverRoadItTook(t *testing.T) {
	a := newAppliance(t)
	a.enrolled("gpu-01")
	if code, _, stderr := a.run("node", "approve", "gpu-01", "--yes",
		"--justify", "test fixture"); code != ExitOK {
		t.Fatalf("node approve: exit %d, %s", code, stderr)
	}
	base := a.servedBy(t, "alice", "admin")
	a.registerModel(t, "acme/tiny", "gpu-01")

	for _, c := range []struct {
		what string
		args []string
	}{
		{"a node that does not exist",
			[]string{"node", "drain", "nowhere", "--yes", "--justify", "no such node"}},
		{"a model with no deployment",
			[]string{"model", "disable", "acme/absent", "--yes", "--justify", "no such model"}},
		{"a route naming a deployment the control plane does not have",
			[]string{"route", "set", "tiny", "--add", "nowhere", "--yes", "--justify", "a typo"}},
		{"a restart of a model that is not on that node",
			[]string{"model", "restart", "acme/tiny", "--node", "gpu-02", "--yes",
				"--justify", "wrong node"}},
	} {
		local, _, localErr := run(t, append(append([]string{}, c.args...),
			"--db", a.db, "--secret-key", a.key)...)
		remote, _, remoteErr := run(t, append(append([]string{}, c.args...),
			"--server", base, "--credentials", a.creds)...)
		if local == ExitOK || remote == ExitOK {
			t.Fatalf("%s was not refused: local %d, remote %d\n%s%s",
				c.what, local, remote, localErr, remoteErr)
		}
		if local != remote {
			t.Errorf("%s: exit %d locally and %d over --server\n  local  %s  remote %s",
				c.what, local, remote, localErr, remoteErr)
		}
	}
}

// The user verbs over --server, and the one field the listing withholds.
func TestUserVerbsOverServer(t *testing.T) {
	a := newAppliance(t)
	base := a.servedBy(t, "alice", "admin")

	code, out, stderr := run(t, "user", "add", "bob", "--role", "operator",
		"--email", "bob@example.test", "--server", base, "--credentials", a.creds,
		"--justify", "onboarding bob")
	if code != ExitOK {
		t.Fatalf("user add over --server: exit %d, %s", code, stderr)
	}
	if !strings.Contains(out, "bob") || !strings.Contains(out, "operator") {
		t.Errorf("user add did not report the account it made: %q", out)
	}

	// The same document either way. `user add --format json` is a stable schema
	// (docs/specs/10-cli.md §2), and a caller who created the account supplied
	// the address, so nothing here is withheld from them.
	code, out, stderr = run(t, "user", "add", "carol", "--role", "viewer",
		"--email", "carol@example.test", "--server", base, "--credentials", a.creds,
		"--justify", "onboarding carol", "--format", "json")
	if code != ExitOK {
		t.Fatalf("user add --format json: exit %d, %s", code, stderr)
	}
	for _, want := range []string{`"name": "carol"`, `"role": "viewer"`,
		`"state": "active"`, `"email": "carol@example.test"`, `"created_at"`} {
		if !strings.Contains(out, want) {
			t.Errorf("user add --format json is missing %s:\n%s", want, out)
		}
	}

	// An admin's listing carries the addresses they manage.
	code, out, stderr = run(t, "user", "list", "--server", base,
		"--credentials", a.creds, "--format", "json")
	if code != ExitOK {
		t.Fatalf("user list: exit %d, %s", code, stderr)
	}
	if !strings.Contains(out, "bob@example.test") {
		t.Errorf("an admin's listing withholds the address they manage:\n%s", out)
	}
	if !strings.Contains(out, "created_at") {
		t.Errorf("the listing carries no created_at, which the local verb renders:\n%s", out)
	}

	if code, _, stderr = run(t, "user", "delete", "bob", "--server", base,
		"--credentials", a.creds, "--justify", "bob left"); code != ExitOK {
		t.Fatalf("user delete over --server: exit %d, %s", code, stderr)
	}
	if code, out, _ = run(t, "user", "list", "--server", base,
		"--credentials", a.creds); code != ExitOK || strings.Contains(out, "bob") {
		t.Errorf("bob is still listed after being deleted:\n%s", out)
	}

	// Suspension is a PATCH and deletion is a DELETE, which is not arbitrary:
	// the irreversible act must not be reachable by putting a different word in
	// a body. Suspending leaves the account there and stops it authenticating.
	if code, _, stderr = run(t, "user", "suspend", "carol", "--server", base,
		"--credentials", a.creds, "--justify", "on leave"); code != ExitOK {
		t.Fatalf("user suspend over --server: exit %d, %s", code, stderr)
	}
	code, out, stderr = run(t, "user", "show", "carol", "--server", base,
		"--credentials", a.creds, "--format", "json")
	if code != ExitOK {
		t.Fatalf("user show: exit %d, %s", code, stderr)
	}
	if !strings.Contains(out, `"state": "suspended"`) {
		t.Errorf("carol is not suspended:\n%s", out)
	}

	// `user show` reads the same listing `user list` does, so there is one
	// place deciding what a caller may see rather than two.
	local, out, stderr := a.run("user", "show", "carol", "--format", "json")
	if local != ExitOK {
		t.Fatalf("user show locally: exit %d, %s", local, stderr)
	}
	remoteCode, remoteOut, stderr := run(t, "user", "show", "carol", "--server", base,
		"--credentials", a.creds, "--format", "json")
	if remoteCode != ExitOK {
		t.Fatalf("user show over --server: exit %d, %s", remoteCode, stderr)
	}
	if remoteOut != out {
		t.Errorf("user show differs between the two routes:\n  local  %s\n  remote %s",
			out, remoteOut)
	}

	// A name nothing holds is a refusal, not an empty rendering.
	if code, _, stderr = run(t, "user", "show", "nobody", "--server", base,
		"--credentials", a.creds); code == ExitOK {
		t.Errorf("showing a user that does not exist reported success (%s)", stderr)
	}
}

// The token verbs over --server, and the loop they close: an administrator on
// their own machine can now mint the credential the next administrator logs in
// with, without a shell on the control plane.
func TestTokenVerbsOverServer(t *testing.T) {
	a := newAppliance(t)
	base := a.servedBy(t, "alice", "admin")
	a.addUser("bob", "operator")

	code, out, stderr := run(t, "token", "create", "--user", "bob", "--name", "laptop",
		"--expires", "30d", "--server", base, "--credentials", a.creds,
		"--justify", "bob needs to administer the fleet")
	if code != ExitOK {
		t.Fatalf("token create over --server: exit %d, %s", code, stderr)
	}
	minted := strings.TrimSpace(out)
	if !strings.HasPrefix(minted, "nodary_") {
		t.Fatalf("stdout is not a credential: %q", minted)
	}
	// The description an operator cannot ask for afterwards.
	for _, want := range []string{"bob", "id ", "expires"} {
		if !strings.Contains(stderr, want) {
			t.Errorf("token create does not report %q:\n%s", want, stderr)
		}
	}

	// The minted credential works, which is the only test of it that means
	// anything.
	other := filepath.Join(t.TempDir(), "credentials")
	if code, _, stderr = runWithStdin(t, minted+"\n", "login", "--server", base,
		"--ca-fingerprint", a.pin, "--credentials", other); code != ExitOK {
		t.Fatalf("logging in with the minted token: exit %d, %s", code, stderr)
	}

	// The listing carries what the local verb carries: the label and the
	// expiry, which the endpoint used to omit entirely.
	code, out, stderr = run(t, "token", "list", "--server", base, "--credentials", a.creds)
	if code != ExitOK {
		t.Fatalf("token list: exit %d, %s", code, stderr)
	}
	for _, want := range []string{"laptop", "active"} {
		if !strings.Contains(out, want) {
			t.Errorf("token list does not carry %q:\n%s", want, out)
		}
	}

	// `--user` names the account, not its id — the endpoint took an id, so
	// `?user=bob` used to match nothing and say so with an empty list.
	code, out, stderr = run(t, "token", "list", "--user", "bob", "--server", base,
		"--credentials", a.creds)
	if code != ExitOK {
		t.Fatalf("token list --user: exit %d, %s", code, stderr)
	}
	if !strings.Contains(out, "laptop") {
		t.Errorf("filtering by user name found nothing:\n%s", out)
	}

	// Revoking ends it, and the credential stops working.
	id := strings.Fields(strings.Split(out, "\n")[1])[0]
	if code, _, stderr = run(t, "token", "revoke", id, "--server", base,
		"--credentials", a.creds, "--justify", "bob left"); code != ExitOK {
		t.Fatalf("token revoke over --server: exit %d, %s", code, stderr)
	}
	if code, _, stderr = run(t, "node", "list", "--server", base,
		"--credentials", other); code != ExitAuth {
		t.Errorf("a revoked credential still works: exit %d, %s", code, stderr)
	}
}

// A profile that caps how long a credential may live binds both front ends.
//
// It bound one. `POST /tokens` hardcoded ninety days, so it ignored what the
// caller asked for and what the profile allows in the same line — and the
// comment on the CLI's own check records that this went unread until a review
// minted a ten-year service key under a profile capping them at one.
func TestTheProfilesTokenLifetimeCapBindsOverServerToo(t *testing.T) {
	a := newAppliance(t)
	base := a.servedBy(t, "alice", "admin")
	a.addUser("bob", "operator")

	// The default profile, whose cap is 3650 days. Not `regulated`: that one
	// also demands a TOTP code, and the ceremony refusal would fire first and
	// prove nothing about the lifetime.
	code, _, stderr := run(t, "token", "create", "--user", "bob", "--expires", "4000d",
		"--server", base, "--credentials", a.creds, "--justify", "an eleven-year key")
	if code != ExitPolicy {
		t.Fatalf("exit = %d, want %d (%s)", code, ExitPolicy, stderr)
	}
	if !strings.Contains(stderr, "token_max_ttl_days") {
		t.Errorf("the refusal does not name the setting that made it: %q", stderr)
	}

	// And a lifetime inside the cap is honored rather than replaced by the
	// ninety days this endpoint used to mint whatever was asked for.
	code, _, stderr = run(t, "token", "create", "--user", "bob", "--expires", "200d",
		"--server", base, "--credentials", a.creds, "--justify", "a longer key")
	if code != ExitOK {
		t.Fatalf("exit = %d, want %d (%s)", code, ExitOK, stderr)
	}
	code, out, stderr := run(t, "token", "list", "--user", "bob", "--server", base,
		"--credentials", a.creds, "--format", "json")
	if code != ExitOK {
		t.Fatalf("token list: exit %d, %s", code, stderr)
	}
	// 200 days out is next year; 90 days is not.
	want := time.Now().AddDate(0, 0, 200).UTC().Format("2006-01-02")
	if !strings.Contains(out, want) {
		t.Errorf("--expires did not reach the control plane; no credential expires %s:\n%s",
			want, out)
	}
}

// The chain read over the network is the chain. An assessor asking "who
// approved this node" should not need a shell on the machine holding it.
func TestAuditAndUsageReadOverServer(t *testing.T) {
	a := newAppliance(t)
	a.enrolled("gpu-01")
	base := a.servedBy(t, "alice", "admin")
	if code, _, stderr := run(t, "node", "approve", "gpu-01", "--server", base,
		"--credentials", a.creds, "--justify", "approving over the network"); code != ExitOK {
		t.Fatalf("node approve: exit %d, %s", code, stderr)
	}

	code, local, stderr := a.run("audit", "list", "--action", "node.approve", "--format", "json")
	if code != ExitOK {
		t.Fatalf("audit list locally: exit %d, %s", code, stderr)
	}
	code, remote, stderr := run(t, "audit", "list", "--action", "node.approve",
		"--server", base, "--credentials", a.creds, "--format", "json")
	if code != ExitOK {
		t.Fatalf("audit list over --server: exit %d, %s", code, stderr)
	}
	if remote != local {
		t.Errorf("the chain reads differently over --server:\n  local  %s\n  remote %s",
			local, remote)
	}
	if !strings.Contains(remote, "approving over the network") {
		t.Errorf("the justification is not in the record:\n%s", remote)
	}

	// --limit means "the newest N" and must not be turned into "follow the
	// cursor to the end of the chain" by the paging the endpoint offers.
	code, out, stderr := run(t, "audit", "list", "--limit", "1",
		"--server", base, "--credentials", a.creds, "--format", "json")
	if code != ExitOK {
		t.Fatalf("audit list --limit: exit %d, %s", code, stderr)
	}
	var listing struct {
		Records []map[string]any `json:"records"`
	}
	if err := json.Unmarshal([]byte(out), &listing); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if len(listing.Records) != 1 {
		t.Errorf("--limit 1 returned %d records", len(listing.Records))
	}

	// Nothing has been served, so the honest answer is an empty report rather
	// than a failure.
	code, local, stderr = run(t, "usage", "show", "--db", a.db, "--format", "json")
	if code != ExitOK {
		t.Fatalf("usage show locally: exit %d, %s", code, stderr)
	}
	code, remote, stderr = run(t, "usage", "show", "--server", base,
		"--credentials", a.creds, "--format", "json")
	if code != ExitOK {
		t.Fatalf("usage show over --server: exit %d, %s", code, stderr)
	}
	if remote != local {
		t.Errorf("usage reads differently over --server:\n  local  %s\n  remote %s",
			local, remote)
	}
}

// The configuration reads over --server. `config show` and `config export`
// render the same TOML an operator would feed back to `config apply`, so a
// difference here is a document that would not round trip.
func TestConfigReadsOverServer(t *testing.T) {
	a := newAppliance(t)
	a.enrolled("gpu-01")
	if code, _, stderr := a.run("node", "approve", "gpu-01", "--yes",
		"--justify", "test fixture"); code != ExitOK {
		t.Fatalf("node approve: exit %d, %s", code, stderr)
	}
	base := a.servedBy(t, "alice", "admin")
	a.registerModel(t, "acme/tiny", "gpu-01")

	for _, c := range []struct {
		what string
		args []string
	}{
		{"config export", []string{"config", "export"}},
		{"config show", []string{"config", "show"}},
		{"config show --rev 1", []string{"config", "show", "--rev", "1"}},
		{"config list", []string{"config", "list", "--format", "json"}},
		{"config verify", []string{"config", "verify", "--format", "json"}},
		{"config diff 1 2", []string{"config", "diff", "1", "2"}},
	} {
		local, out, stderr := run(t, append(append([]string{}, c.args...), "--db", a.db)...)
		if local != ExitOK {
			t.Fatalf("%s locally: exit %d, %s", c.what, local, stderr)
		}
		remote, remoteOut, stderr := run(t, append(append([]string{}, c.args...),
			"--server", base, "--credentials", a.creds)...)
		if remote != ExitOK {
			t.Fatalf("%s over --server: exit %d, %s", c.what, remote, stderr)
		}
		if remoteOut != out {
			t.Errorf("%s differs between the two routes:\n  local  %s\n  remote %s",
				c.what, out, remoteOut)
		}
	}

	// `-f FILE` reads a file on this machine, which the control plane cannot
	// see — so the comparison has to happen here whichever road the live
	// configuration came down.
	exported := filepath.Join(t.TempDir(), "config.toml")
	if code, _, stderr := run(t, "config", "export", "--server", base,
		"--credentials", a.creds, "--out", exported); code != ExitOK {
		t.Fatalf("config export --out: exit %d, %s", code, stderr)
	}
	code, out, stderr := run(t, "config", "diff", "-f", exported, "--server", base,
		"--credentials", a.creds)
	if code != ExitOK {
		t.Fatalf("config diff -f: exit %d, %s", code, stderr)
	}
	if !strings.Contains(out, "no change") {
		t.Errorf("a configuration exported and diffed against itself is not identical:\n%s", out)
	}
}

// `config apply` over --server: the declarative route, which is how a site
// keeps its configuration in version control and applies it from a laptop
// rather than from a shell on the control plane.
func TestConfigApplyAndRollbackOverServer(t *testing.T) {
	a := newAppliance(t)
	a.enrolled("gpu-01")
	if code, _, stderr := a.run("node", "approve", "gpu-01", "--yes",
		"--justify", "test fixture"); code != ExitOK {
		t.Fatalf("node approve: exit %d, %s", code, stderr)
	}
	base := a.servedBy(t, "alice", "admin")
	a.registerModel(t, "acme/tiny", "gpu-01")

	doc := filepath.Join(t.TempDir(), "config.toml")
	if code, _, stderr := run(t, "config", "export", "--server", base,
		"--credentials", a.creds, "--out", doc); code != ExitOK {
		t.Fatalf("config export: exit %d, %s", code, stderr)
	}
	body, err := os.ReadFile(doc)
	if err != nil {
		t.Fatal(err)
	}
	// One edit an operator would make: a second route naming the deployment
	// that already exists.
	edited := string(body) + "\n[[route]]\nname = \"tiny-alias\"\nstrategy = \"round-robin\"\n" +
		"member = [{ deployment_id = \"tiny-gpu-01\", weight = 1 }]\n"
	if err := os.WriteFile(doc, []byte(edited), 0o600); err != nil {
		t.Fatal(err)
	}

	// A dry run first: rendered and hashed on the control plane, applying
	// nothing.
	code, out, stderr := run(t, "config", "apply", "-f", doc, "--server", base,
		"--credentials", a.creds, "--justify", "adding an alias", "--dry-run")
	if code != ExitOK {
		t.Fatalf("config apply --dry-run: exit %d, %s", code, stderr)
	}
	if !strings.Contains(out, "tiny-alias") {
		t.Errorf("the preview does not name the change:\n%s", out)
	}
	if code, out, _ = run(t, "route", "list", "--server", base,
		"--credentials", a.creds); code != ExitOK || strings.Contains(out, "tiny-alias") {
		t.Errorf("a dry run applied the change:\n%s", out)
	}

	code, out, stderr = run(t, "config", "apply", "-f", doc, "--server", base,
		"--credentials", a.creds, "--justify", "adding an alias")
	if code != ExitOK {
		t.Fatalf("config apply: exit %d, %s", code, stderr)
	}
	if !strings.Contains(out, "tiny-alias") {
		t.Errorf("the apply does not report what it changed:\n%s", out)
	}
	if code, out, _ = run(t, "route", "list", "--server", base,
		"--credentials", a.creds); code != ExitOK || !strings.Contains(out, "tiny-alias") {
		t.Fatalf("the route was not created:\n%s", out)
	}

	// The record names the person and the reason, which is the whole point.
	code, records, stderr := a.run("audit", "list", "--action", "config.apply", "--format", "json")
	if code != ExitOK {
		t.Fatalf("audit list: exit %d, %s", code, stderr)
	}
	if !strings.Contains(records, "adding an alias") {
		t.Errorf("the justification is not in the chain:\n%s", records)
	}

	// And a rollback undoes it, resolved by the control plane from its own
	// revision rather than by shipping a snapshot back to it.
	code, revs, stderr := run(t, "config", "list", "--server", base,
		"--credentials", a.creds, "--format", "json")
	if code != ExitOK {
		t.Fatalf("config list: exit %d, %s", code, stderr)
	}
	var listing []struct {
		Seq int64 `json:"seq"`
	}
	if err := json.Unmarshal([]byte(revs), &listing); err != nil {
		t.Fatalf("%v\n%s", err, revs)
	}
	if len(listing) < 2 {
		t.Fatalf("expected at least two revisions:\n%s", revs)
	}
	// config list is newest-first, so the one before the apply is the second.
	if code, _, stderr = run(t, "config", "rollback", strconv.FormatInt(listing[1].Seq, 10),
		"--prune", "--server", base, "--credentials", a.creds,
		"--justify", "the alias was a mistake"); code != ExitOK {
		t.Fatalf("config rollback: exit %d, %s", code, stderr)
	}
	if code, out, _ = run(t, "route", "list", "--server", base,
		"--credentials", a.creds); code != ExitOK || strings.Contains(out, "tiny-alias") {
		t.Errorf("the rollback did not remove the route:\n%s", out)
	}
}

// A document this control plane cannot read is its refusal to make, and it has
// to say what is wrong with it — not "the server failed to handle this
// request".
func TestAnUnreadableConfigurationIsRefusedWithItsReason(t *testing.T) {
	a := newAppliance(t)
	base := a.servedBy(t, "alice", "admin")

	doc := filepath.Join(t.TempDir(), "broken.toml")
	if err := os.WriteFile(doc, []byte("[[route]\nname = \"oops\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, _, stderr := run(t, "config", "apply", "-f", doc, "--server", base,
		"--credentials", a.creds, "--justify", "a typo")
	if code == ExitOK {
		t.Fatal("a malformed document was applied")
	}
	if strings.Contains(stderr, "the server failed to handle this request") {
		t.Errorf("a typo came back as a server failure: %q", stderr)
	}
	if !strings.Contains(stderr, "invalid configuration") {
		t.Errorf("the refusal does not say the document is the problem: %q", stderr)
	}
}

// PATCH sets one state and refuses the rest. Deletion is irreversible and has
// its own method, so it must not be reachable by putting a different word in a
// body — a client typo should not be able to delete an account.
func TestPatchingAUserWillOnlySuspend(t *testing.T) {
	a := newAppliance(t)
	base := a.servedBy(t, "alice", "admin")
	a.addUser("bob", "operator")

	creds, err := identity.LoadCredentials(a.creds)
	if err != nil {
		t.Fatal(err)
	}
	cred, err := creds.Token(base)
	if err != nil {
		t.Fatal(err)
	}
	client, err := agent.Client(a.pin, nil)
	if err != nil {
		t.Fatal(err)
	}
	r := &remote{base: base, cred: cred, c: client}

	for _, state := range []string{"deleted", "active", "", "nonsense"} {
		err := r.do("PATCH", "/users/bob?dry_run=true",
			map[string]any{"state": state}, nil)
		if err == nil {
			t.Errorf("PATCH accepted state %q", state)
			continue
		}
		var refusal *remoteError
		if !errors.As(err, &refusal) || refusal.code != "bad_request" {
			t.Errorf("state %q: %v, want a bad request", state, err)
		}
	}
	if code, out, _ := a.run("user", "list"); code != ExitOK || !strings.Contains(out, "bob") {
		t.Errorf("bob was removed by a refused patch:\n%s", out)
	}
}

// The policy verbs over --server. `policy apply` is the act R2-44's remainder
// named; `show` and `diff` come with it, because an administrator who cannot
// read the posture from their own machine has no way to decide what to apply.
func TestPolicyReadsOverServer(t *testing.T) {
	a := newAppliance(t)
	base := a.servedBy(t, "alice", "admin")

	for _, c := range []struct {
		what string
		args []string
	}{
		{"show", []string{"policy", "show", "--format", "json"}},
		{"diff", []string{"policy", "diff", "regulated", "--format", "json"}},
	} {
		localCode, local, localErr := run(t, append(append([]string{}, c.args...), "--db", a.db)...)
		remoteCode, remote, remoteErr := run(t, append(append([]string{}, c.args...),
			"--server", base, "--credentials", a.creds)...)
		if localCode != ExitOK || remoteCode != ExitOK {
			t.Fatalf("policy %s: local %d (%s), remote %d (%s)",
				c.what, localCode, localErr, remoteCode, remoteErr)
		}
		if local != remote {
			t.Errorf("policy %s differs between the two roads:\n  local  %s\n  remote %s",
				c.what, local, remote)
		}
	}
}

// A file on the operator's machine reaches a control plane that has never seen
// it, and is parsed by the machine that applies it. Sending this side's
// reading of the document instead would apply what this binary understood
// rather than what that one did — the divergence `config apply` sends raw TOML
// to avoid, and the reason the body carries bytes for a file and a name for a
// built-in.
func TestAPolicyFileTravelsToTheControlPlaneOverServer(t *testing.T) {
	a := newAppliance(t)
	base := a.servedBy(t, "alice", "admin")

	path := filepath.Join(t.TempDir(), "site.toml")
	if err := os.WriteFile(path, []byte(`[policy]
name = "site"

require_totp             = false
require_justification    = true
min_justification_length = 20
require_signed_artifacts = true
allow_unattended_tokens  = true
allow_custom_backends    = true
allow_derived_images     = true
require_pinned_derives   = false

egress_default           = "deny"
require_model_manifest   = false

audit_retention_days     = 2555
usage_retention_days     = 90
session_ttl_minutes      = 60
token_max_ttl_days       = 30
`), 0o644); err != nil {
		t.Fatal(err)
	}

	code, _, stderr := run(t, "policy", "apply", path, "--yes",
		"--justify", "the site's own posture, applied remotely",
		"--server", base, "--credentials", a.creds)
	if code != ExitOK {
		t.Fatalf("policy apply of a file over --server: exit %d, %s", code, stderr)
	}

	code, out, stderr := run(t, "policy", "show", "--server", base,
		"--credentials", a.creds, "--format", "json")
	if code != ExitOK {
		t.Fatalf("policy show: exit %d, %s", code, stderr)
	}
	for _, want := range []string{`"name": "site"`, `"min_justification_length": 20`,
		`"audit_retention_days": 2555`, `"token_max_ttl_days": 30`} {
		if !strings.Contains(out, want) {
			t.Errorf("the applied profile does not carry %s — the file's own values did not "+
				"reach the control plane:\n%s", want, out)
		}
	}
}

// Applying a profile that denies something already registered has to say so,
// and over --server the catalog it is computed from is on the other machine.
// Flagged, not stopped: nothing is turned off, and the operator is told what
// they would have to decide.
func TestPolicyApplyOverServerReportsWhatItNowDenies(t *testing.T) {
	a := newAppliance(t)
	a.enrolled("gpu-01")
	if code, _, stderr := a.run("node", "approve", "gpu-01", "--yes",
		"--justify", "test fixture"); code != ExitOK {
		t.Fatalf("node approve: exit %d, %s", code, stderr)
	}
	base := a.servedBy(t, "alice", "admin")

	models := t.TempDir()
	dir := filepath.Join(models, "hub", "models--acme--tiny")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "config.json"), []byte(`{}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if code, _, stderr := a.run("model", "register", "acme/tiny", "--node", "gpu-01",
		"--models-dir", models, "--port", "8001", "--origin-country", "CN",
		"--yes", "--justify", "registered before the profile changed"); code != ExitOK {
		t.Fatalf("model register: exit %d, %s", code, stderr)
	}

	code, _, stderr := run(t, "policy", "apply", "regulated", "--yes",
		"--justify", "tightening the posture from my laptop",
		"--server", base, "--credentials", a.creds)
	if code != ExitOK {
		t.Fatalf("policy apply over --server: exit %d, %s", code, stderr)
	}
	if !strings.Contains(stderr, "acme/tiny") || !strings.Contains(stderr, "now denies") {
		t.Errorf("applying regulated over --server did not report the model it now denies.\n%s", stderr)
	}
	if !strings.Contains(stderr, "Nothing was stopped") {
		t.Error("the report does not say the model is still running, which is the whole distinction")
	}

	// 07 §4: loosening is permitted, doing it silently is not — and that has
	// to hold over the network, where the posture being left behind is read
	// from the control plane rather than from a database on this machine.
	// --dry-run, and that is the point rather than a convenience: the report is
	// printed before the ceremony, so an operator sees what they are about to
	// relax while they can still decline. (It also sidesteps regulated's TOTP
	// requirement, which this credential correctly cannot satisfy.)
	code, _, stderr = run(t, "policy", "apply", "default", "--dry-run",
		"--justify", "relaxing the posture again from my laptop",
		"--server", base, "--credentials", a.creds)
	if code != ExitOK {
		t.Fatalf("policy apply default --dry-run over --server: exit %d, %s", code, stderr)
	}
	if !strings.Contains(stderr, "loosens:") {
		t.Errorf("going from regulated back to default over --server said nothing about "+
			"loosening the posture.\n%s", stderr)
	}

	// And it is the person's act, not root's — which is the whole of what
	// R2-44 exists for. The actor is the account id, so alice's is looked up
	// rather than assumed to be her name.
	code, out, stderr := run(t, "user", "show", "alice", "--format", "json",
		"--server", base, "--credentials", a.creds)
	if code != ExitOK {
		t.Fatalf("user show: exit %d, %s", code, stderr)
	}
	var who struct {
		User struct {
			ID string `json:"id"`
		} `json:"user"`
	}
	if err := json.Unmarshal([]byte(out), &who); err != nil || who.User.ID == "" {
		t.Fatalf("user show: %v\n%s", err, out)
	}

	code, out, stderr = run(t, "audit", "list", "--limit", "50", "--format", "json",
		"--server", base, "--credentials", a.creds)
	if code != ExitOK {
		t.Fatalf("audit list: exit %d, %s", code, stderr)
	}
	var got struct {
		Records []struct {
			Action string `json:"action"`
			Actor  struct {
				ID     string `json:"id"`
				Method string `json:"method"`
			} `json:"actor"`
		} `json:"records"`
	}
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	var found bool
	for _, r := range got.Records {
		if r.Action != "policy.apply" {
			continue
		}
		found = true
		if r.Actor.ID != who.User.ID || r.Actor.Method == "local" {
			t.Errorf("policy.apply recorded actor %q method %q, want %s over the network",
				r.Actor.ID, r.Actor.Method, who.User.ID)
		}
	}
	if !found {
		t.Errorf("no policy.apply record:\n%s", out)
	}
}

// The staging verbs over --server. Both are one-shot requests the agent picks
// up on its next poll, and both are guarded by a precondition that now lives
// in internal/fleet rather than in either front end.
func TestStagingVerbsOverServer(t *testing.T) {
	a := newAppliance(t)
	a.enrolled("fractal")
	base := a.servedBy(t, "alice", "admin")
	a.modelWithNoDeployment(t, "acme/loose", "local")
	a.modelWithNoDeployment(t, "acme/rotten", "remote")
	a.markCorrupt(t, "fractal", "acme/rotten")

	for _, c := range []struct{ verb, model string }{
		{"unstage", "acme/loose"},
		{"restage", "acme/rotten"},
	} {
		code, _, stderr := run(t, "model", c.verb, c.model, "--node", "fractal", "--yes",
			"--justify", "run from an administrator's own machine",
			"--server", base, "--credentials", a.creds)
		if code != ExitOK {
			t.Fatalf("model %s over --server: exit %d, %s", c.verb, code, stderr)
		}
		if !strings.Contains(stderr, "next poll") {
			t.Errorf("model %s said nothing about when it takes effect: %s", c.verb, stderr)
		}
	}

	got := a.stageResetRows(t)
	slices.Sort(got)
	if len(got) != 2 || got[0] != "acme/loose" || got[1] != "acme/rotten" {
		t.Errorf("stage_reset = %v, want both models requested", got)
	}
}

// The preconditions are the act, so they have to refuse identically on both
// roads — and each has to arrive as its own refusal rather than as a 500 with
// the message withheld, which is what an unwrapped error costs over the wire.
func TestStagingPreconditionsRefuseTheSameOnBothRoads(t *testing.T) {
	a := newAppliance(t)
	a.enrolled("fractal")
	if code, _, stderr := a.run("node", "approve", "fractal", "--yes",
		"--justify", "test fixture"); code != ExitOK {
		t.Fatalf("node approve: exit %d, %s", code, stderr)
	}
	base := a.servedBy(t, "alice", "admin")
	a.registerModel(t, "acme/tiny", "fractal")
	a.modelWithNoDeployment(t, "acme/onmedia", "local")
	// source: remote and not corrupt — the only shape that reaches restage's
	// second precondition, since the first one refuses local weights outright.
	a.modelWithNoDeployment(t, "acme/fetched", "remote")

	for _, c := range []struct {
		what, says string
		args       []string
	}{
		{"unstaging a model a deployment still wants", "still deployed",
			[]string{"model", "unstage", "acme/tiny", "--node", "fractal"}},
		{"restaging something that is not corrupt", "not corrupt",
			[]string{"model", "restage", "acme/fetched", "--node", "fractal"}},
		{"restaging source: local weights", "source: local",
			[]string{"model", "restage", "acme/onmedia", "--node", "fractal"}},
		{"a model that does not exist", "no model named",
			[]string{"model", "unstage", "acme/absent", "--node", "fractal"}},
	} {
		args := append(append([]string{}, c.args...), "--yes", "--justify", "a refusal either way")
		local, _, localErr := run(t, append(append([]string{}, args...),
			"--db", a.db, "--secret-key", a.key)...)
		remote, _, remoteErr := run(t, append(append([]string{}, args...),
			"--server", base, "--credentials", a.creds)...)

		if local == ExitOK || remote == ExitOK {
			t.Fatalf("%s was not refused: local %d, remote %d\n%s%s",
				c.what, local, remote, localErr, remoteErr)
		}
		if local != remote {
			t.Errorf("%s: exit %d locally and %d over --server\n  local  %s  remote %s",
				c.what, local, remote, localErr, remoteErr)
		}
		if !strings.Contains(remoteErr, c.says) {
			t.Errorf("%s over --server did not say why (want %q):\n%s", c.what, c.says, remoteErr)
		}
	}
	if rows := a.stageResetRows(t); len(rows) != 0 {
		t.Errorf("stage_reset = %v, want nothing written by any refusal", rows)
	}
}
