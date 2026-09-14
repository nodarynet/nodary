package config_test

import (
	"context"
	"database/sql"
	"errors"
	"io"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nodarynet/nodary/internal/audit"
	"github.com/nodarynet/nodary/internal/config"
	"github.com/nodarynet/nodary/internal/identity"
	"github.com/nodarynet/nodary/internal/policy"
	"github.com/nodarynet/nodary/internal/store"
)

// A minimal descriptor that passes the schema. Deliberately not a copy of a
// built-in: what is under test is an operator's own file.
const acmeDescriptor = `[backend]
name           = "acme-serve"
api            = "openai"
weights_layout = "hf-cache"
mount_path     = "/weights"
container_port = 9000
image_default  = "acme/serve:1"

[backend.capabilities]
tensor_parallel = false
expert_parallel = false
quantization    = ["awq"]
lora            = false
cpu_offload     = false

[backend.args]
model_path = "--model={v}"
port       = "--port={v}"

[backend.gpu]
mechanism = "device-flag"

[backend.probe]
health          = "/healthz"
ready           = "/healthz"
ready_timeout_s = 300
`

// registry is a database with a node, applying whole snapshots the way both
// front ends do.
func registry(t *testing.T) (*store.DB, func(string) error, func(*config.Snapshot, bool) (config.Result, error)) {
	t.Helper()
	ctx := context.Background()
	db, err := store.Open(ctx, filepath.Join(t.TempDir(), "nodary.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if err := db.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	if err := db.WriteTx(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx,
			`INSERT INTO node (name, state, created_at) VALUES ('gpu-01', 'approved', ?)`,
			time.Now().UTC().Format(audit.TimeFormat))
		return err
	}); err != nil {
		t.Fatal(err)
	}
	delivery := audit.NewDelivery(nil, audit.Warn, io.Discard)
	t.Cleanup(func() { delivery.Close() })
	log := audit.New(db, delivery)
	root := identity.LocalRoot()
	root.Actor.ID = "test"

	setProfile := func(name string) error {
		prof, src, err := policy.Builtin(name)
		if err != nil {
			return err
		}
		_, err = log.Act(ctx, audit.Request{Actor: root.Actor, Action: "policy.apply"},
			func(m audit.Mutation) error {
				return policy.Apply(ctx, m, root.Role, time.Now(), prof, src)
			})
		return err
	}
	return db, setProfile, func(want *config.Snapshot, prune bool) (config.Result, error) {
		var res config.Result
		_, err := log.Act(ctx, audit.Request{Actor: root.Actor, Action: "config.apply"},
			func(m audit.Mutation) error {
				var err error
				res, err = config.Apply(ctx, m, time.Now(), want, config.Options{Prune: prune})
				return err
			})
		return res, err
	}
}

func snapWith(backends []config.Backend, deployments ...config.Deployment) *config.Snapshot {
	s := &config.Snapshot{Backends: backends, Deployments: deployments}
	if len(deployments) > 0 {
		s.Models = []config.Model{{ID: "acme/tiny", Backend: deployments[0].Backend,
			Source: "local", Artifact: "hf-cache"}}
	}
	return s
}

// R6-07: a descriptor an operator registers is in the configuration, so it is
// in a revision, so it can be exported, rolled back, and — the part that
// matters most — sent to a node.
func TestARegisteredBackendRoundTrips(t *testing.T) {
	db, _, apply := registry(t)
	ctx := context.Background()

	if _, err := apply(snapWith([]config.Backend{{Name: "acme-serve", Source: acmeDescriptor}}),
		false); err != nil {
		t.Fatalf("registering: %v", err)
	}

	snap, err := config.Read(ctx, db.Read())
	if err != nil {
		t.Fatal(err)
	}
	if len(snap.Backends) != 1 || snap.Backends[0].Name != "acme-serve" {
		t.Fatalf("snapshot backends = %+v, want the registered one", snap.Backends)
	}
	// The bytes, not this build's reading of them: an operator's comments and
	// ordering survive, and the digest is of what they wrote.
	if snap.Backends[0].Source != acmeDescriptor {
		t.Error("the descriptor came back re-serialized rather than as the file")
	}

	// And it resolves, so a deployment may use it.
	d, err := config.BackendFor(ctx, db.Read(), "acme-serve")
	if err != nil {
		t.Fatalf("resolving a registered backend: %v", err)
	}
	if d.Backend.WeightsLayout != "hf-cache" || d.Backend.ContainerPort != 9000 {
		t.Errorf("resolved %+v, want the registered descriptor", d.Backend)
	}
}

// The three refusals, each of which is why this is not a plain upsert.
func TestRegisteringABackendRefusesTheThreeWays(t *testing.T) {
	for _, c := range []struct {
		what     string
		backends []config.Backend
		says     string
	}{
		{"a descriptor that does not parse",
			[]config.Backend{{Name: "acme-serve", Source: "[backend]\nname = \"acme-serve\"\nnope = 1\n"}},
			"acme-serve"},
		{"a name that disagrees with the descriptor",
			[]config.Backend{{Name: "other", Source: acmeDescriptor}},
			"declares itself"},
		{"a name that shadows a built-in",
			[]config.Backend{{Name: "vllm", Source: strings.Replace(acmeDescriptor,
				`name           = "acme-serve"`, `name           = "vllm"`, 1)}},
			"built into this binary"},
	} {
		t.Run(c.what, func(t *testing.T) {
			_, _, apply := registry(t)
			_, err := apply(snapWith(c.backends), false)
			if err == nil {
				t.Fatal("registered")
			}
			if !errors.Is(err, config.ErrInvalid) {
				t.Errorf("err = %v, want it recognizable as a bad document", err)
			}
			if !strings.Contains(err.Error(), c.says) {
				t.Errorf("the refusal does not say %q: %v", c.says, err)
			}
		})
	}
}

// A node whose descriptor vanished cannot render an argv at all, so every
// deployment on that backend fails at once for a reason that names neither the
// document nor the line that caused it.
func TestABackendInUseIsNotRemoved(t *testing.T) {
	_, _, apply := registry(t)
	reg := []config.Backend{{Name: "acme-serve", Source: acmeDescriptor}}
	dep := config.Deployment{ID: "dep_one", ModelID: "acme/tiny", NodeName: "gpu-01",
		Backend: "acme-serve", GPUs: []int{0}, Port: 8001}

	if _, err := apply(snapWith(reg, dep), false); err != nil {
		t.Fatalf("registering and deploying: %v", err)
	}
	// The same document with the backend dropped, pruning.
	_, err := apply(snapWith(nil, dep), true)
	if err == nil {
		t.Fatal("a backend was removed while a deployment used it")
	}
	if !strings.Contains(err.Error(), "dep_one") {
		t.Errorf("the refusal does not name what is using it: %v", err)
	}
}

// Without --prune it is an orphan, like everything else the document does not
// mention — a partial document is the ordinary case.
func TestADroppedBackendIsAnOrphanNotADeletion(t *testing.T) {
	db, _, apply := registry(t)
	reg := []config.Backend{{Name: "acme-serve", Source: acmeDescriptor}}
	if _, err := apply(snapWith(reg), false); err != nil {
		t.Fatal(err)
	}
	res, err := apply(snapWith(nil), false)
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, o := range res.Orphans {
		if strings.Contains(o, "acme-serve") {
			found = true
		}
	}
	if !found {
		t.Errorf("orphans = %v, want the unmentioned backend named", res.Orphans)
	}
	if _, err := config.BackendFor(context.Background(), db.Read(), "acme-serve"); err != nil {
		t.Errorf("the backend was deleted without --prune: %v", err)
	}
}

// 04 §5 / 07 §1: a profile that forbids custom backends forbids them at the
// applier, which is the only road in.
func TestAProfileMayForbidCustomBackends(t *testing.T) {
	_, setProfile, apply := registry(t)
	strict, _, err := policy.Builtin("regulated")
	if err != nil {
		t.Fatal(err)
	}
	if strict.AllowCustomBackends {
		t.Fatal("this test needs a profile that forbids them")
	}
	if err := setProfile("regulated"); err != nil {
		t.Fatalf("applying the profile: %v", err)
	}

	_, err = apply(snapWith([]config.Backend{{Name: "acme-serve", Source: acmeDescriptor}}), false)
	if err == nil {
		t.Fatal("a custom backend was registered under a profile that forbids them")
	}
	if !strings.Contains(err.Error(), "regulated") {
		t.Errorf("the refusal does not name the profile: %v", err)
	}
}

// Registering a descriptor has to show up in the change list, or an operator
// attests to a preview that says nothing happened.
func TestRegisteringABackendIsAChange(t *testing.T) {
	_, _, apply := registry(t)
	reg := []config.Backend{{Name: "acme-serve", Source: acmeDescriptor}}

	res, err := apply(snapWith(reg), false)
	if err != nil {
		t.Fatal(err)
	}
	if !hasChange(res.Changes, "+ backend acme-serve") {
		t.Errorf("changes = %v, want the registration named", res.Changes)
	}

	// And re-registering a *different* descriptor under the same name is a
	// change, not nothing: the name is the same and what it means is not.
	edited := strings.Replace(acmeDescriptor, `container_port = 9000`, `container_port = 9001`, 1)
	res, err = apply(snapWith([]config.Backend{{Name: "acme-serve", Source: edited}}), false)
	if err != nil {
		t.Fatal(err)
	}
	if !hasChange(res.Changes, "~ backend acme-serve") {
		t.Errorf("changes = %v, want the edit named", res.Changes)
	}
}

// **Changes() said `~ policy default -> regulated` and Apply did nothing about
// it.** A document that tightened the posture previewed as though it would,
// recorded a revision saying it had, and left the profile where it was — a
// confident claim that the thing happened, which for a chain an assessor reads
// is worse than silence.
func TestAConfigDocumentMayNotMoveThePosture(t *testing.T) {
	db, _, apply := registry(t)
	ctx := context.Background()

	_, src, err := policy.Builtin("regulated")
	if err != nil {
		t.Fatal(err)
	}
	want := snapWith(nil)
	want.Policy = &config.Policy{Name: "regulated", Source: string(src)}

	if _, err := apply(want, false); err == nil {
		t.Fatal("a config document moved the policy profile")
	} else {
		if !errors.Is(err, config.ErrInvalid) {
			t.Errorf("err = %v, want it recognizable as a bad document", err)
		}
		// It says where the change does belong.
		if !strings.Contains(err.Error(), "policy apply") {
			t.Errorf("the refusal does not name the verb that does this: %v", err)
		}
	}
	active, _, err := policy.Active(ctx, db.Read())
	if err != nil {
		t.Fatal(err)
	}
	if active.Name != "default" {
		t.Errorf("the profile moved to %q anyway", active.Name)
	}
}

// An export carries the active profile, so applying an export has to work —
// otherwise the round trip a site in version control depends on is broken.
func TestAnExportedPolicyBlockRoundTrips(t *testing.T) {
	db, setProfile, apply := registry(t)
	ctx := context.Background()

	// A fresh database has no policy row until one is applied, so the state an
	// export is taken from has to exist first.
	if err := setProfile("default"); err != nil {
		t.Fatal(err)
	}
	snap, err := config.Read(ctx, db.Read())
	if err != nil {
		t.Fatal(err)
	}
	if snap.Policy == nil {
		t.Fatal("the applied profile is not in the snapshot")
	}
	want := snapWith([]config.Backend{{Name: "acme-serve", Source: acmeDescriptor}})
	want.Policy = snap.Policy
	if _, err := apply(want, false); err != nil {
		t.Errorf("applying a document carrying the active profile: %v", err)
	}
}

func hasChange(all []string, want string) bool {
	for _, c := range all {
		if c == want {
			return true
		}
	}
	return false
}

// tritonDescriptor is acme-serve speaking a dialect the gateway cannot proxy.
// Identical to acmeDescriptor but for the one line under test, so a refusal
// can only be about that line.
var tritonDescriptor = strings.Replace(acmeDescriptor,
	`api            = "openai"`, `api            = "triton"`, 1)

// routed is a snapshot that registers a backend, places a deployment on it,
// and puts that deployment on a route — the whole road from a descriptor to
// something a client can ask for.
func routed(source string) *config.Snapshot {
	s := snapWith([]config.Backend{{Name: "acme-serve", Source: source}},
		config.Deployment{ID: "tiny-gpu-01", ModelID: "acme/tiny", NodeName: "gpu-01",
			Backend: "acme-serve", Image: "acme/serve:1", GPUs: []int{0}, Port: 8001})
	s.Routes = []config.Route{{Name: "tiny", Strategy: "round-robin",
		Members: []config.RouteMember{{DeploymentID: "tiny-gpu-01", Weight: 1}}}}
	return s
}

// 04 §8: `api` is what says whether the control plane may route to a
// deployment directly. The gateway hands LiteLLM `openai/<model>` for every
// member it renders, so a triton deployment on a route is not a failure
// anybody sees — the proxy comes up healthy and answers each request by
// speaking OpenAI at a server that does not speak it.
func TestARouteRefusesADeploymentThatDoesNotSpeakOpenAI(t *testing.T) {
	_, _, apply := registry(t)

	if _, err := apply(routed(acmeDescriptor), false); err != nil {
		t.Fatalf("an openai backend on a route was refused: %v", err)
	}

	_, _, apply2 := registry(t)
	_, err := apply2(routed(tritonDescriptor), false)
	if err == nil {
		t.Fatal("a triton deployment was added to an OpenAI route")
	}
	for _, want := range []string{"tiny", "tiny-gpu-01", "acme-serve", "triton"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not name %q: %v", want, err)
		}
	}
	if !errors.Is(err, config.ErrInvalid) {
		t.Errorf("the refusal is not ErrInvalid, so an API client gets a 500 with the "+
			"message withheld: %v", err)
	}
}

// The second road, and the one a check beside the INSERT would miss entirely:
// the route does not change, the *backend under it* does. A document that
// re-registers a descriptor names no route at all.
func TestRedefiningABackendCannotChangeTheDialectUnderAStandingRoute(t *testing.T) {
	_, _, apply := registry(t)
	if _, err := apply(routed(acmeDescriptor), false); err != nil {
		t.Fatalf("setting up: %v", err)
	}

	// Only the descriptor. No route, no deployment, no model.
	_, err := apply(&config.Snapshot{
		Backends: []config.Backend{{Name: "acme-serve", Source: tritonDescriptor}},
	}, false)
	if err == nil {
		t.Fatal("a backend serving a route changed dialect and the route kept carrying it")
	}
	if !strings.Contains(err.Error(), "triton") || !errors.Is(err, config.ErrInvalid) {
		t.Errorf("wrong refusal: %v", err)
	}
}

// A member this apply removes is not a member to refuse, which is why the
// check runs after the prune rather than before it. Otherwise the only way out
// of a bad dialect would be to fix the descriptor first — and the descriptor
// may be exactly what the operator is trying to retire.
func TestRetiringTheRouteIsAWayOutOfABadDialect(t *testing.T) {
	db, _, apply := registry(t)

	// Get into the state the long way: a valid route, then the table edited
	// underneath it, which is what a build without this check would leave.
	if _, err := apply(routed(acmeDescriptor), false); err != nil {
		t.Fatalf("setting up: %v", err)
	}
	if err := db.WriteTx(context.Background(), func(tx *sql.Tx) error {
		_, e := tx.ExecContext(context.Background(),
			`UPDATE backend SET body = ? WHERE name = 'acme-serve'`, tritonDescriptor)
		return e
	}); err != nil {
		t.Fatal(err)
	}

	// The whole configuration minus the route, pruned. It has to be allowed:
	// the route is the thing being removed.
	out := routed(tritonDescriptor)
	out.Routes = nil
	if _, err := apply(out, true); err != nil {
		t.Fatalf("a route carrying a bad dialect could not be retired: %v", err)
	}
}
