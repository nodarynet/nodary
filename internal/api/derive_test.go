package api_test

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/nodarynet/nodary/internal/api"
	"github.com/nodarynet/nodary/internal/audit"
	"github.com/nodarynet/nodary/internal/config"
	"github.com/nodarynet/nodary/internal/identity"
)

// dev/specs/04-backends.md §5's own example: the case derived images exist for.
const fipsDescriptor = `[backend]
name     = "vllm-fips"
inherits = "vllm"

[backend.derive]
from      = "vllm/vllm-openai@sha256:61fc8a896b0a4fbbbdc063bc4b0dbc25ce98e02b5050c24aeb7830ac02039b14"
steps     = ["pip install --no-cache-dir opencv-python-headless==4.12.0.88"]
index_url = "https://pypi.internal/simple"
timeout_s = 1800
`

const httpDigest = "sha256:3333333333333333333333333333333333333333333333333333333333333333"

// registerDerive puts §5's example in the catalog through the applier both
// front ends use, so a test cannot create a state the product cannot.
func (f *fixture) registerDerive() {
	f.t.Helper()
	ctx := context.Background()
	root := identity.LocalRoot()
	root.Actor.ID = "test"
	if _, err := f.log.Act(ctx, audit.Request{Actor: root.Actor, Action: "config.apply"},
		func(m audit.Mutation) error {
			snap, err := config.Read(ctx, m.Tx())
			if err != nil {
				return err
			}
			snap.Backends = append(snap.Backends,
				config.Backend{Name: "vllm-fips", Source: fipsDescriptor})
			if _, err := config.Apply(ctx, m, time.Now(), snap, config.Options{}); err != nil {
				return err
			}
			_, err = config.Record(ctx, m, time.Now(), "test", "FIPS override for this site")
			return err
		}); err != nil {
		f.t.Fatalf("registering the derive: %v", err)
	}
}

func justify(s string) map[string]string { return map[string]string{api.HeaderJustify: s} }

// asText flattens a response so an assertion can ask whether a value is
// anywhere in it, without walking a shape that is not the thing under test.
func asText(t *testing.T, doc map[string]any) string {
	t.Helper()
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

// R2-27. The endpoint the CLI's own comment said did not exist: "a --server
// build would have to run somewhere, and the only somewhere is here". Here is
// the control plane, which is where §5 puts a build in the first place.
func TestABuildOverHTTPRecordsWhatItProduced(t *testing.T) {
	f := newFixture(t)
	f.registerDerive()
	st := api.StubBuild(t, httpDigest)

	status, doc := f.do("POST", "/backends/vllm-fips/build", f.admin, nil,
		justify("FIPS: stock opencv aborts at import"))
	if status != http.StatusOK {
		t.Fatalf("build: %d %v", status, doc)
	}
	if st.Builds != 1 {
		t.Fatalf("the endpoint ran %d builds, want 1", st.Builds)
	}
	if st.Asked.Descriptor.Backend.Derive == nil {
		t.Fatal("the build was handed a descriptor with no recipe")
	}
	// §5: a node can neither build this image nor pull it, so without the
	// export there is nothing anywhere a GPU host could fetch.
	if len(st.Saved) != 1 || st.Saved[0] != httpDigest {
		t.Errorf("exported %v, want the digest that was built", st.Saved)
	}
	result, _ := doc["result"].(map[string]any)
	if result["digest"] != httpDigest {
		t.Errorf("result = %v, want the digest it produced", doc["result"])
	}

	// The status endpoint reports it, and the record carries it.
	status, doc = f.do("GET", "/backends/vllm-fips/build", f.admin, nil, nil)
	if status != http.StatusOK {
		t.Fatalf("build status: %d %v", status, doc)
	}
	built, _ := doc["built"].(map[string]any)
	if built["digest"] != httpDigest {
		t.Fatalf("built = %v, want the digest that was recorded", doc["built"])
	}
	if built["stale"] != false {
		t.Errorf("an image built from the recipe in force reads stale: %v", built)
	}
	// §5 names the builder as part of the provenance. The actor id rather
	// than the username, which is what the CLI records too — a name can be
	// reused, and the chain has to keep pointing at the same person.
	if built["built_by"] == "" || built["built_by"] == nil || built["built_at"] == "" {
		t.Errorf("the build records no builder or time: %v", built)
	}

	status, audited := f.do("GET", "/audit?action=backend.build", f.admin, nil, nil)
	if status != http.StatusOK {
		t.Fatalf("audit: %d %v", status, audited)
	}
	// The digest is not in the preview and so not in the intent hash. §5's
	// requirement that the record carry it is met by the audit detail, and
	// this is the assertion that keeps it met.
	for _, want := range []string{"backend.build", httpDigest, "recipe_sha256",
		"stock opencv aborts at import"} {
		if !strings.Contains(asText(t, audited), want) {
			t.Errorf("no audit record carries %q", want)
		}
	}
}

// The design this endpoint turns on: a preview costs nothing, and the hash it
// returns is the one the apply binds. If the preview had to build to render,
// the confirm would have to build again to re-render — and an unpinned recipe
// producing a second digest would refuse its own approval with a 412.
func TestAPreviewedBuildDoesNotBuildAndStillBindsItsHash(t *testing.T) {
	f := newFixture(t)
	f.registerDerive()
	st := api.StubBuild(t, httpDigest)

	status, doc := f.do("POST", "/backends/vllm-fips/build?dry_run=true", f.admin, nil,
		justify("FIPS: stock opencv aborts at import"))
	if status != http.StatusOK {
		t.Fatalf("dry run: %d %v", status, doc)
	}
	if st.Builds != 0 {
		t.Fatalf("a preview spent the build it exists to avoid (%d builds)", st.Builds)
	}
	hash, _ := doc["intent_hash"].(string)
	if hash == "" {
		t.Fatalf("the preview returned no intent_hash: %v", doc)
	}
	if doc["applied"] == true {
		t.Error("a dry run applied")
	}

	headers := justify("FIPS: stock opencv aborts at import")
	headers[api.HeaderIntent] = hash
	status, doc = f.do("POST", "/backends/vllm-fips/build", f.admin, nil, headers)
	if status != http.StatusOK {
		t.Fatalf("applying the hash the preview gave: %d %v", status, doc)
	}
	if doc["intent_hash"] != hash {
		t.Errorf("intent_hash moved between the preview and the apply: %v, want %s",
			doc["intent_hash"], hash)
	}
	if st.Builds != 1 {
		t.Errorf("builds = %d, want the apply to be the one that built", st.Builds)
	}
}

// §5: "a derived image is built once; rebuilding is explicit". A build that
// quietly rebuilt would be the silent change the audit chain exists to prevent.
func TestASecondBuildOverHTTPHasToSayRebuild(t *testing.T) {
	f := newFixture(t)
	f.registerDerive()
	st := api.StubBuild(t, httpDigest)

	if status, doc := f.do("POST", "/backends/vllm-fips/build", f.admin, nil,
		justify("FIPS: stock opencv aborts at import")); status != http.StatusOK {
		t.Fatalf("build: %d %v", status, doc)
	}
	status, doc := f.do("POST", "/backends/vllm-fips/build", f.admin, nil,
		justify("again, for no stated reason"))
	if status != http.StatusUnprocessableEntity {
		t.Fatalf("a second build answered %d, want 422: %v", status, doc)
	}
	// Refused before the build, not after it.
	if st.Builds != 1 {
		t.Errorf("the refused build still ran: %d builds", st.Builds)
	}
	if !strings.Contains(asText(t, doc), "rebuild") {
		t.Errorf("the refusal does not name the verb that would do it: %v", doc)
	}

	second := "sha256:" + strings.Repeat("4", 64)
	st2 := api.StubBuild(t, second)
	if status, doc := f.do("POST", "/backends/vllm-fips/build?rebuild=true", f.admin, nil,
		justify("the base moved and the fix has to be reapplied")); status != http.StatusOK {
		t.Fatalf("rebuild: %d %v", status, doc)
	}
	if st2.Builds != 1 {
		t.Errorf("rebuild ran %d builds, want 1", st2.Builds)
	}
	_, doc = f.do("GET", "/backends/vllm-fips/build", f.admin, nil, nil)
	if built, _ := doc["built"].(map[string]any); built["digest"] != second {
		t.Errorf("rebuild left %v on record", doc["built"])
	}
}

// A backend with no recipe, and a name that is not a backend at all. Both
// refuse before anything is built, and both refuse as what they are rather
// than as a 500 with the message withheld.
func TestBuildingWhatHasNoRecipeIsRefusedByName(t *testing.T) {
	f := newFixture(t)
	st := api.StubBuild(t, httpDigest)

	status, doc := f.do("POST", "/backends/vllm/build", f.admin, nil, justify("build the built-in"))
	if status != http.StatusUnprocessableEntity {
		t.Errorf("building a built-in answered %d, want 422: %v", status, doc)
	}
	if !strings.Contains(asText(t, doc), "[backend.derive]") {
		t.Errorf("the refusal does not say what a derive is: %v", doc)
	}
	status, doc = f.do("POST", "/backends/nosuch/build", f.admin, nil, justify("build nothing"))
	if status != http.StatusNotFound {
		t.Errorf("building an unknown backend answered %d, want 404: %v", status, doc)
	}
	if st.Builds != 0 {
		t.Errorf("a refused request still built: %d", st.Builds)
	}
}

// 07 §1 gives admin "the catalog and backend registration" as one area. The
// refusal has to arrive before the build, not after half an hour of it.
func TestABuildIsRefusedBeforeItRunsForSomeoneWhoMayNot(t *testing.T) {
	f := newFixture(t)
	f.registerDerive()
	st := api.StubBuild(t, httpDigest)

	status, doc := f.do("POST", "/backends/vllm-fips/build", tokenForRole(t, f, "opal", identity.RoleOperator), nil,
		justify("an operator trying to build"))
	if status != http.StatusForbidden {
		t.Fatalf("status = %d, want 403: %v", status, doc)
	}
	if st.Builds != 0 {
		t.Errorf("the build ran before the refusal: %d", st.Builds)
	}
}
