package cli

import (
	"context"
	"encoding/json"
	"io"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
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

	// Suspension has no endpoint, and deleting instead would answer a
	// reversible request with an irreversible act.
	code, _, stderr = run(t, "user", "suspend", "carol", "--server", base,
		"--credentials", a.creds, "--justify", "on leave")
	if code != ExitUsage {
		t.Errorf("user suspend over --server: exit = %d, want %d (%s)", code, ExitUsage, stderr)
	}
	if code, out, _ = run(t, "user", "list", "--server", base,
		"--credentials", a.creds); code != ExitOK || !strings.Contains(out, "carol") {
		t.Errorf("a refused suspension removed the account:\n%s", out)
	}
}
