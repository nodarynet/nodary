package derive

import (
	"context"
	"crypto/tls"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/nodarynet/nodary/internal/backend"
)

// fakeRuntime stands in for nerdctl: it records the argv it was handed, which
// is what the build actually decides, and can be told to fail one verb.
type fakeRuntime struct {
	calls []string
	fail  string
	out   string
	// reach is a URL a `run` step fetches through the proxy it was handed,
	// which is what a step reaching somewhere actually looks like: the build
	// gives it HTTPS_PROXY and the step uses it.
	reach string
	// unresolvable makes the store answer `images` with nothing useful.
	unresolvable bool
}

func (f *fakeRuntime) run(_ context.Context, name string, args ...string) ([]byte, error) {
	f.calls = append(f.calls, name+" "+strings.Join(args, " "))
	if f.reach != "" && len(args) > 0 && args[0] == "run" {
		f.through(strings.Join(args, " "))
	}
	if f.fail != "" && len(args) > 0 && args[0] == f.fail {
		return []byte(f.out), errors.New("exit status 1")
	}
	// The store answering what a reference resolves to, which is where the
	// digest in the record comes from.
	if len(args) > 0 && args[0] == "images" {
		if f.unresolvable {
			return []byte("<none>\n"), nil
		}
		return []byte("sha256:" + strings.Repeat("c", 64) + "\n"), nil
	}
	return nil, nil
}

// through finds the proxy the build handed this step and makes a request by it,
// ignoring the outcome: what is under test is the build's verdict afterwards,
// not this request's.
func (f *fakeRuntime) through(argv string) {
	const key = "HTTPS_PROXY="
	i := strings.Index(argv, key)
	if i < 0 {
		return
	}
	addr := strings.Fields(argv[i+len(key):])[0]
	u, err := url.Parse(addr)
	if err != nil {
		return
	}
	c := &http.Client{Transport: &http.Transport{
		Proxy:           http.ProxyURL(u),
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}}
	if resp, err := c.Get(f.reach); err == nil {
		resp.Body.Close()
	}
}

func (f *fakeRuntime) saw(substr string) bool {
	for _, c := range f.calls {
		if strings.Contains(c, substr) {
			return true
		}
	}
	return false
}

const base = "vllm/vllm-openai@sha256:61fc8a896b0a4fbbbdc063bc4b0dbc25ce98e02b5050c24aeb7830ac02039b14"

func derive(t *testing.T, steps, index string) backend.Descriptor {
	t.Helper()
	src := `
[backend]
name     = "vllm-fips"
inherits = "vllm"

[backend.derive]
from      = "` + base + `"
steps     = [` + steps + `]
` + index + `
timeout_s = 1800
`
	d, err := backend.Parse([]byte(src))
	if err != nil {
		t.Fatalf("fixture does not parse: %v", err)
	}
	return d
}

func build(t *testing.T, d backend.Descriptor, rt *fakeRuntime) (Result, error) {
	t.Helper()
	return Build(context.Background(), Options{
		Descriptor: d, Tag: "nodary/vllm-fips:1", Run: rt.run,
		// No bridge in a test, so the proxy binds loopback instead of 10.88.0.1.
		listen: "127.0.0.1:0",
	})
}

// The shape of a build: pull the pinned base, run each step as a container on
// the isolated network, commit, tag.
func TestABuildRunsEachStepOnTheIsolatedNetwork(t *testing.T) {
	rt := &fakeRuntime{}
	d := derive(t, `"pip install --no-cache-dir opencv-python-headless==4.12.0.88", "python -c pass"`,
		`index_url = "https://pypi.internal/simple"`)

	res, err := build(t, d, rt)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if res.Steps != 2 || res.Image != "nodary/vllm-fips:1" {
		t.Fatalf("result = %+v", res)
	}

	if !rt.saw("pull --quiet " + base) {
		t.Error("the digest-pinned base was not pulled")
	}
	// **The control that matters.** A step on any other network — or on the
	// host's — would reach whatever the control plane can.
	for _, c := range rt.calls {
		if strings.HasPrefix(c, "nerdctl run ") && !strings.Contains(c, "--network "+Network) {
			t.Errorf("a step ran off the isolated network: %s", c)
		}
	}
	if !rt.saw("commit nodary-derive-vllm-fips-0") || !rt.saw("commit nodary-derive-vllm-fips-1") {
		t.Error("steps were not committed in order")
	}
	if !rt.saw("tag ") {
		t.Error("the result was not tagged")
	}
	if len(res.Reached) != 1 || res.Reached[0] != "pypi.internal:443" {
		t.Errorf("reached = %v", res.Reached)
	}
}

// Every step is handed the proxy, in both spellings, with no bypass. A step
// that missed it reaches nothing at all rather than reaching out — but it would
// fail confusingly, and a bypass list would quietly re-open the private ranges
// this is keeping a build away from.
func TestEveryStepIsPointedAtTheProxyWithNoBypass(t *testing.T) {
	rt := &fakeRuntime{}
	d := derive(t, `"pip install a", "pip install b"`, `index_url = "https://pypi.internal/simple"`)
	if _, err := build(t, d, rt); err != nil {
		t.Fatal(err)
	}
	var steps int
	for _, c := range rt.calls {
		if !strings.HasPrefix(c, "nerdctl run ") {
			continue
		}
		steps++
		for _, want := range []string{"https_proxy=http://", "HTTPS_PROXY=http://",
			"http_proxy=http://", "HTTP_PROXY=http://", "no_proxy= ", "NO_PROXY= "} {
			if !strings.Contains(c+" ", want) {
				t.Errorf("step is missing %q: %s", want, c)
			}
		}
	}
	if steps != 2 {
		t.Errorf("ran %d steps", steps)
	}
}

// A recipe that names no index gets no allowlist, so its build reaches nothing.
// Steps needing no network still run.
func TestNoIndexUrlBuildsWithNoAllowlist(t *testing.T) {
	rt := &fakeRuntime{}
	d := derive(t, `"python -c pass"`, "")
	res, err := build(t, d, rt)
	if err != nil {
		t.Fatalf("a build that needs no network failed: %v", err)
	}
	if len(res.Reached) != 0 {
		t.Errorf("reached = %v, want nothing", res.Reached)
	}
}

// **Nothing is committed from a step that failed.** A recipe whose second
// command fails must leave no image, rather than one carrying half its
// corrections — which would run, serve, and be missing the fix it exists for.
func TestAFailedStepLeavesNoImage(t *testing.T) {
	rt := &fakeRuntime{fail: "run", out: "ERROR: could not install"}
	d := derive(t, `"pip install a"`, `index_url = "https://pypi.internal/simple"`)

	if _, err := build(t, d, rt); err == nil {
		t.Fatal("a failed step produced a build")
	}
	if rt.saw("commit ") {
		t.Error("a failed step was committed")
	}
	if rt.saw("tag ") {
		t.Error("a failed build was tagged")
	}
}

// R6-09's `done:` line: a build that reaches outside its index **fails** rather
// than silently succeeding with an unexpected dependency. The step may well
// exit zero — pip can fall back, or a step can ignore a failed fetch — so the
// refusal is checked independently of the exit status.
func TestABuildThatReachedOutsideItsIndexFailsEvenIfTheStepSucceeded(t *testing.T) {
	elsewhere := index(t, "a dependency nobody asked for")
	// The step exits zero, and reaches somewhere its recipe does not name.
	rt := &fakeRuntime{reach: elsewhere.URL + "/evil.whl"}
	d := derive(t, `"pip install a"`, `index_url = "https://pypi.internal/simple"`)

	_, err := build(t, d, rt)
	if err == nil {
		t.Fatal("a build that reached outside its index succeeded")
	}
	if !errors.Is(err, ErrRefused) {
		t.Fatalf("error = %v, want ErrRefused", err)
	}
}

// A derive is built with nerdctl. A control plane without one is told so rather
// than failing inside an exec.
func TestABuildWithNoRuntimeSaysSo(t *testing.T) {
	d := derive(t, `"pip install a"`, "")
	_, err := Build(context.Background(), Options{Descriptor: d, Tag: "x", listen: "127.0.0.1:0"})
	if !errors.Is(err, ErrNoRuntime) {
		t.Fatalf("error = %v, want ErrNoRuntime", err)
	}
}

// An ordinary backend is not a derive, and building one is a caller bug rather
// than an empty build.
func TestBuildingSomethingThatIsNotADeriveIsRefused(t *testing.T) {
	vllm, err := backend.Get("vllm")
	if err != nil {
		t.Fatal(err)
	}
	rt := &fakeRuntime{}
	if _, err := build(t, vllm, rt); !errors.Is(err, backend.ErrInvalid) {
		t.Fatalf("error = %v, want ErrInvalid", err)
	}
	if len(rt.calls) != 0 {
		t.Errorf("it started building anyway: %v", rt.calls)
	}
}

// §5 requires the record to carry the digest of the image the build produced.
// A tag alone would not do it: a tag is a name for whatever is behind it, and
// the provenance record exists precisely to say what that was.
func TestABuildReportsWhatItProduced(t *testing.T) {
	f := &fakeRuntime{}
	got, err := Build(context.Background(), Options{
		Descriptor: derive(t, `"pip install x==1"`, `index_url = "https://pypi.internal/simple"`),
		Tag:        "nodary/vllm-fips:abc123", Run: f.run, listen: "127.0.0.1:0",
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.Digest != "sha256:"+strings.Repeat("c", 64) {
		t.Errorf("digest = %q, want what the store said it is", got.Digest)
	}
	if got.Image != "nodary/vllm-fips:abc123" {
		t.Errorf("image = %q", got.Image)
	}
	// An intermediate must stay a parseable reference: a tag that already
	// carries a `:` makes "<tag>:step-1" two colons and no image.
	if f.saw("commit nodary-derive-vllm-fips-0 nodary/vllm-fips:abc123:step-1") {
		t.Error("an intermediate was named by appending to a tag that already had one")
	}
}

// An unexpected line recorded as provenance is worse than a build that says it
// could not tell.
func TestAStoreThatDoesNotSayWhatItBuiltFailsTheBuild(t *testing.T) {
	f := &fakeRuntime{unresolvable: true}
	_, err := Build(context.Background(), Options{
		Descriptor: derive(t, `"pip install x==1"`, `index_url = "https://pypi.internal/simple"`),
		Tag:        "nodary/vllm-fips:abc123", Run: f.run, listen: "127.0.0.1:0",
	})
	if err == nil {
		t.Fatal("a build whose output could not be identified succeeded")
	}
	if !strings.Contains(err.Error(), "does not say what") {
		t.Errorf("the failure does not say what went wrong: %v", err)
	}
}
