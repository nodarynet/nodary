package derive

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// client is a real HTTP client forced through the proxy, which is the only way
// to test a CONNECT proxy that means anything: what is under test is whether a
// program that wants to reach somewhere can.
func client(proxy *httptest.Server) *http.Client {
	u, _ := url.Parse(proxy.URL)
	return &http.Client{Transport: &http.Transport{
		Proxy:           http.ProxyURL(u),
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}}
}

// index stands in for the package index: a TLS server whose host:port is what
// the recipe named.
func index(t *testing.T, body string) *httptest.Server {
	t.Helper()
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, body)
	}))
	t.Cleanup(s.Close)
	return s
}

func hostPort(t *testing.T, srv *httptest.Server) string {
	t.Helper()
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	return u.Host
}

// The hole: a build reaches the one host its recipe named, and the bytes are
// end to end — the proxy tunnels and does not read them.
func TestTheBuildReachesTheIndexItNamed(t *testing.T) {
	idx := index(t, "opencv-python-headless-4.12.0.88.whl")
	p := NewProxy(hostPort(t, idx))
	// Loopback, because these drive the proxy from the test process rather
	// than from a container on the build subnet. The peer restriction has its
	// own test; here it would refuse every case before the host is read.
	p.OnlyFrom = nil
	front := httptest.NewServer(p)
	defer front.Close()

	resp, err := client(front).Get(idx.URL + "/simple/")
	if err != nil {
		t.Fatalf("the build could not reach its own index: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "opencv") {
		t.Errorf("the tunnel did not carry the index's answer: %q", body)
	}
	if p.Allowed() != 1 {
		t.Errorf("tunnels opened = %d", p.Allowed())
	}
	if err := p.RefusalError(); err != nil {
		t.Errorf("a clean build reported a refusal: %v", err)
	}
}

// §5's actual claim, and R6-09's `done:` line: a build that reaches outside its
// index **fails** rather than quietly succeeding with an unexpected dependency.
func TestReachingAnywhereElseIsRefusedAndRecorded(t *testing.T) {
	idx := index(t, "index")
	other := index(t, "somewhere else entirely")
	p := NewProxy(hostPort(t, idx))
	// Loopback, because these drive the proxy from the test process rather
	// than from a container on the build subnet. The peer restriction has its
	// own test; here it would refuse every case before the host is read.
	p.OnlyFrom = nil
	front := httptest.NewServer(p)
	defer front.Close()

	if _, err := client(front).Get(other.URL + "/evil.whl"); err == nil {
		t.Fatal("a build reached a host its recipe does not name")
	}

	// Recorded, not merely blocked. A build that fails has to be able to say
	// where it went, or the operator reads a network fault.
	refused := p.Refused()
	if len(refused) != 1 || refused[0] != hostPort(t, other) {
		t.Fatalf("refusals = %v, want %s", refused, hostPort(t, other))
	}
	err := p.RefusalError()
	if !errors.Is(err, ErrRefused) {
		t.Fatalf("RefusalError = %v", err)
	}
	if !strings.Contains(err.Error(), hostPort(t, other)) {
		t.Errorf("the failure does not name where it went: %v", err)
	}
}

// A 403, not a 502. The build was not permitted to reach somewhere; it did not
// fail to. An operator reading pip's output should see a refusal rather than
// something that reads like a flaky network and invites a retry.
func TestARefusalLooksLikeARefusal(t *testing.T) {
	p := NewProxy("index.internal:443")
	// Loopback, because these drive the proxy from the test process rather
	// than from a container on the build subnet. The peer restriction has its
	// own test; here it would refuse every case before the host is read.
	p.OnlyFrom = nil
	front := httptest.NewServer(p)
	defer front.Close()

	conn, err := net.Dial("tcp", strings.TrimPrefix(front.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	fmt.Fprintf(conn, "CONNECT files.pythonhosted.org:443 HTTP/1.1\r\nHost: files.pythonhosted.org:443\r\n\r\n")
	buf := make([]byte, 256)
	n, _ := conn.Read(buf)
	if !strings.Contains(string(buf[:n]), "403") {
		t.Errorf("a refused host got %q, want 403", string(buf[:n]))
	}
	if !strings.Contains(string(buf[:n]), "Forbidden") {
		t.Errorf("status line does not read as a refusal: %q", string(buf[:n]))
	}
}

// Plain HTTP through the proxy is refused rather than forwarded. Forwarding it
// would put nodary in the middle of the bytes a build installs, immediately
// before recording the digest of what they produced.
func TestPlainHTTPIsNotForwarded(t *testing.T) {
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "should never be reached")
	}))
	defer plain.Close()

	p := NewProxy(hostPort(t, plain))
	// Loopback, because these drive the proxy from the test process rather
	// than from a container on the build subnet. The peer restriction has its
	// own test; here it would refuse every case before the host is read.
	p.OnlyFrom = nil
	front := httptest.NewServer(p)
	defer front.Close()

	resp, err := client(front).Get(plain.URL + "/x")
	if err != nil {
		return // refused at the transport, which is also a refusal
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		t.Fatal("plain HTTP was forwarded through the build proxy")
	}
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", resp.StatusCode)
	}

	// **The host here is the allowed one**, so this must not be reported as
	// reaching outside the index. Measured on hardware: busybox `wget` sends
	// an absolute-URI GET even for an https URL, so a step that used it
	// against its own index failed with a message telling the operator to add
	// a host that was already named — which is a fix that cannot work.
	if refused := p.Refused(); len(refused) != 0 {
		t.Errorf("an allowed host was recorded as reached outside the index: %v", refused)
	}
	if un := p.Untunneled(); len(un) != 1 {
		t.Errorf("untunneled = %v, want the one request that did not tunnel", un)
	}
	err = p.RefusalError()
	if err == nil {
		t.Fatal("a build whose step never tunnelled was not failed")
	}
	if strings.Contains(err.Error(), "does not name") {
		t.Errorf("the failure blames the allowlist for a client that did not tunnel: %v", err)
	}
	if !strings.Contains(err.Error(), "CONNECT") {
		t.Errorf("the failure does not say what the step has to do instead: %v", err)
	}
}

// The port is part of the allowlist: "the package index" is a service, not a
// machine, and a host that serves an index on 443 has not thereby been allowed
// on every other port it happens to listen on.
func TestAnAllowedHostOnAnotherPortIsStillRefused(t *testing.T) {
	idx := index(t, "index")
	host, _, err := net.SplitHostPort(hostPort(t, idx))
	if err != nil {
		t.Fatal(err)
	}
	p := NewProxy(net.JoinHostPort(host, "9999"))
	// Loopback, because these drive the proxy from the test process rather
	// than from a container on the build subnet. The peer restriction has its
	// own test; here it would refuse every case before the host is read.
	p.OnlyFrom = nil
	front := httptest.NewServer(p)
	defer front.Close()

	if _, err := client(front).Get(idx.URL + "/simple/"); err == nil {
		t.Fatal("an allowed host was reachable on a port nobody allowed")
	}
	if len(p.Refused()) != 1 {
		t.Errorf("refusals = %v", p.Refused())
	}
}

// A derive with no index_url gets no allowlist, so its build reaches nothing.
// Steps that need no network still run; a `pip install` fails, which is the
// honest outcome for a recipe that named no index.
func TestNoIndexMeansNoEgressAtAll(t *testing.T) {
	idx := index(t, "index")
	p := NewProxy()
	// Loopback, because these drive the proxy from the test process rather
	// than from a container on the build subnet. The peer restriction has its
	// own test; here it would refuse every case before the host is read.
	p.OnlyFrom = nil
	front := httptest.NewServer(p)
	defer front.Close()

	if _, err := client(front).Get(idx.URL + "/simple/"); err == nil {
		t.Fatal("a build with no index reached one")
	}
}

func TestAllowedFromReadsTheIndexURL(t *testing.T) {
	for in, want := range map[string]string{
		"https://pypi.internal/simple":      "pypi.internal:443",
		"https://pypi.internal:8443/simple": "pypi.internal:8443",
		"https://pypi.org/simple":           "pypi.org:443",
	} {
		got, err := AllowedFrom(in)
		if err != nil {
			t.Errorf("%s: %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("%s -> %q, want %q", in, got, want)
		}
	}

	// Cleartext is refused here as well as at parse time, because this is the
	// function that decides what the tunnel will open.
	for _, bad := range []string{"http://pypi.internal/simple", "pypi.internal", "https://"} {
		if _, err := AllowedFrom(bad); err == nil {
			t.Errorf("%q was accepted as an index", bad)
		}
	}
}

// **The bridge does not exist until a container attaches to it**, and the first
// container to attach is the step that needs this proxy's address before it
// starts. So the listener cannot be bound to the bridge's own address on a
// control plane that is not also a node — which §5 makes the ordinary case,
// since the point of building here is to keep builds off the nodes.
//
// The restriction that replaces the bind is this one, so it is the one that has
// to hold: a peer outside the build's subnet is refused before it can name a
// host, which is what stops a wildcard listener being an open proxy.
func TestTheProxyAnswersOnlyTheBuildsOwnSubnet(t *testing.T) {
	p := NewProxy("pypi.internal:443")
	if p.OnlyFrom == nil {
		t.Fatal("a proxy behind a wildcard listener defaulted to answering anybody")
	}

	// Driven at the handler, because the two outcomes have to be told apart:
	// a refused peer is 403 before any host is named, where an allowed peer
	// asking for a host that does not resolve is 502. A transport error at a
	// client looks identical for both, which is how this went untested.
	connect := func(remote string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodConnect, "//pypi.internal:443", nil)
		r.Host = "pypi.internal:443"
		r.RemoteAddr = remote
		w := httptest.NewRecorder()
		p.ServeHTTP(w, r)
		return w
	}

	if w := connect("127.0.0.1:34567"); w.Code != http.StatusForbidden ||
		!strings.Contains(w.Body.String(), "one build's container") {
		t.Errorf("a peer outside the build's subnet got %d %q, want 403 refusing it",
			w.Code, w.Body.String())
	}
	// And it is not recorded against the build: another process reaching this
	// port is not this build's egress, and putting it in the record would make
	// a build fail for something it did not do.
	if p.RefusalError() != nil {
		t.Errorf("somebody else's request was recorded as the build's: %v", p.RefusalError())
	}
	// A peer inside the subnet gets past this check and fails later, on the
	// host — which is what proves the 403 above was the peer and not the host.
	if w := connect("10.88.0.2:34567"); w.Code == http.StatusForbidden {
		t.Errorf("a peer inside the build's subnet was refused as a peer: %q", w.Body.String())
	}

	// The check itself, without a socket: the subnet is what decides.
	for _, tc := range []struct {
		remote string
		want   bool
	}{
		{"10.88.0.2:34567", true},
		{"10.88.0.255:1", true},
		{"127.0.0.1:34567", false},
		{"10.89.0.2:34567", false},
		{"192.168.1.10:80", false},
		{"not-an-address", false},
	} {
		if got := p.fromAllowedPeer(tc.remote); got != tc.want {
			t.Errorf("fromAllowedPeer(%q) = %v, want %v", tc.remote, got, tc.want)
		}
	}
}
