// Package derive builds the corrected images of docs/specs/04-backends.md §5.
//
// **The egress allowlist is the point of this package**, not a detail of it.
// §5 requires a build to reach "the package index and nothing else", and the
// mechanism is the one internal/agent/network.go already measured into
// existence: a container on `nodary-isolated` has no default route and no NAT,
// so it reaches nowhere at all. This adds exactly one hole —
// a CONNECT proxy on the host that will open a tunnel to one host and refuse
// every other — and the container has no second route to anything, including to
// the proxy's refusal.
//
// The shape matters. An IP allowlist in nftables would have to let DNS out for
// the container to resolve the index, and R4d measured DNS as the channel that
// survives a route check: `<data>.attacker.example` is an exfiltration path
// that passes every connectivity test. Here nothing the container does resolves
// — the proxy resolves on its behalf — so it never needs a resolver and an
// allowlist never has to let one through.
//
// Measured rather than assumed, and the measurement corrected the wording: the
// container *is* handed the host's nameserver in resolv.conf, because nerdctl
// copies it when CNI names none. Every lookup still failed, with "Network
// unreachable", since that address is off-link and there is no route. The
// control is the absent route and the drop rule in internal/agent/network.go,
// not an empty resolv.conf.
package derive

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// ErrRefused is a build reaching somewhere its recipe did not name.
var ErrRefused = errors.New("the build reached outside its index")

// dialTimeout bounds a tunnel's setup. A build has its own ceiling; this stops
// one unreachable host holding a connection open inside it.
const dialTimeout = 30 * time.Second

// Proxy is an allow-listed HTTP CONNECT proxy.
//
// **CONNECT only.** A plain-HTTP request through a proxy puts the proxy in the
// middle of the bytes a build installs, which is a position nothing in nodary
// should hold over an artifact it is about to record the digest of. Refusing it
// is also why `index_url` is https-only: the refusal belongs at parse time,
// where an operator is reading their own file, rather than an hour into a build.
type Proxy struct {
	// allowed is host:port, exactly. A port that was not named is not allowed:
	// "the package index" is a service, not a machine.
	allowed map[string]bool

	// OnlyFrom is the network a client must come from, nil for any.
	//
	// **It is here rather than in the bind address, and that is not a
	// preference.** The natural socket-level answer is to listen on the
	// bridge's own address, which nothing outside `nodary-isolated` can
	// reach — but CNI does not create `nodary0` until a container attaches to
	// it, and the first container to attach is the build step that needs this
	// proxy's address in its environment before it starts. On a control plane
	// that is not also a node — which §5 makes the ordinary case, since the
	// whole reason builds live here is to keep them off the nodes — that
	// address does not exist yet and the bind fails.
	//
	// So the listener takes any address and the restriction moves one layer
	// up, where it can be applied without waiting for an interface. It is the
	// same restriction: a peer outside the subnet is refused before it can
	// name a host.
	OnlyFrom *net.IPNet

	mu sync.Mutex
	// refused records what was reached for, in order, so a failed build can say
	// what it wanted rather than only that it failed. §5's whole claim is that
	// a build reaching outside its index fails instead of quietly succeeding
	// with something unexpected — which is unreadable without this.
	refused []string
	// untunneled is a client that spoke plain HTTP to the proxy instead of
	// CONNECT, whatever host it named.
	//
	// **A separate list, because it is a separate failure.** Measured on real
	// hardware: busybox `wget` does not tunnel — it sends an absolute-URI GET
	// even for an https URL — so it lands here rather than on the host check.
	// Folding the two together made a step that used a non-tunneling client
	// against its *own* index fail with "which its recipe does not name",
	// sending an operator to add a host that is already there.
	untunneled []string
	allowedN   int
}

// fromAllowedPeer reports whether a client may use this proxy at all.
func (p *Proxy) fromAllowedPeer(remote string) bool {
	if p.OnlyFrom == nil {
		return true
	}
	host, _, err := net.SplitHostPort(remote)
	if err != nil {
		host = remote
	}
	ip := net.ParseIP(host)
	return ip != nil && p.OnlyFrom.Contains(ip)
}

// NewProxy allows exactly the hosts named, each as host:port.
//
// OnlyFrom defaults to the build subnet rather than to nil, because the
// listener it sits behind is bound to a wildcard address and a proxy that
// forgot to set this would be one anything on the network could use. A caller
// that wants no restriction has to say so.
func NewProxy(hosts ...string) *Proxy {
	p := &Proxy{allowed: make(map[string]bool, len(hosts)), OnlyFrom: Subnet()}
	for _, h := range hosts {
		if h = strings.TrimSpace(h); h != "" {
			p.allowed[h] = true
		}
	}
	return p
}

// AllowedFrom is the allowlist an index URL implies: that host, on its port.
//
// **Only what was named.** Against a public index this is usually not enough —
// `https://pypi.org/simple` serves the index and `files.pythonhosted.org`
// serves the wheels, so a build against it is refused at the second host. That
// is the specified behavior rather than a bug, and the refusal names the host
// so it reads as an allowlist decision instead of a network fault. §5's example
// and R6-11's requirement are both an internal index, which serves both from
// one host.
func AllowedFrom(indexURL string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(indexURL))
	if err != nil {
		return "", fmt.Errorf("index_url %q is not a URL: %w", indexURL, err)
	}
	if u.Scheme != "https" {
		return "", fmt.Errorf("index_url %q is not https; a build reaches its index through a "+
			"CONNECT tunnel, and cleartext would put this proxy in the middle of what the "+
			"build installs", indexURL)
	}
	if u.Hostname() == "" {
		return "", fmt.Errorf("index_url %q names no host", indexURL)
	}
	port := u.Port()
	if port == "" {
		port = "443"
	}
	return net.JoinHostPort(u.Hostname(), port), nil
}

// Untunneled is what spoke plain HTTP to this proxy, in order.
func (p *Proxy) Untunneled() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.untunneled...)
}

// Refused is what this build reached for and was not allowed, in order.
func (p *Proxy) Refused() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.refused...)
}

// Allowed is how many tunnels were opened, so a build that installed nothing is
// distinguishable from one that installed something unexpected.
func (p *Proxy) Allowed() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.allowedN
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !p.fromAllowedPeer(r.RemoteAddr) {
		// Not noted as a refusal: this is not the build reaching somewhere, it
		// is somebody else reaching the build's proxy, and recording it as the
		// build's own egress would put another process's traffic in this
		// build's record.
		http.Error(w, "this proxy serves one build's container", http.StatusForbidden)
		return
	}
	if r.Method != http.MethodConnect {
		// An absolute-URI request is plain HTTP through the proxy. Refused
		// rather than forwarded: see the type comment.
		p.noteUntunneled(r.Host)
		http.Error(w, "this proxy tunnels https to the build's index and forwards nothing",
			http.StatusMethodNotAllowed)
		return
	}
	target := r.Host
	if !p.allowed[target] {
		p.note(target)
		// 403 and not 502: the build did not fail to reach somewhere, it was
		// not permitted to. An operator reading pip's output should see a
		// refusal rather than something that reads like a flaky network.
		http.Error(w, fmt.Sprintf("%s is not this build's index", target), http.StatusForbidden)
		return
	}

	upstream, err := net.DialTimeout("tcp", target, dialTimeout)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer upstream.Close()

	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "cannot tunnel", http.StatusInternalServerError)
		return
	}
	client, _, err := hj.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer client.Close()

	p.mu.Lock()
	p.allowedN++
	p.mu.Unlock()

	if _, err := io.WriteString(client, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}
	// Both directions, and the tunnel ends when either does. TLS is end to end
	// through this: the proxy moves bytes and cannot read or alter them, which
	// is what keeps it out of the path of what the build installs.
	done := make(chan struct{}, 2)
	go func() { io.Copy(upstream, client); done <- struct{}{} }()
	go func() { io.Copy(client, upstream); done <- struct{}{} }()
	<-done
}

func (p *Proxy) noteUntunneled(host string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.untunneled = append(p.untunneled, host)
}

func (p *Proxy) note(host string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if host == "" {
		host = "(no host)"
	}
	for _, seen := range p.refused {
		if seen == host {
			return
		}
	}
	p.refused = append(p.refused, host)
}

// RefusalError turns what was refused into the failure §5 asks for: a build
// that reached outside its index fails, and says where it went.
func (p *Proxy) RefusalError() error {
	if refused := p.Refused(); len(refused) > 0 {
		return fmt.Errorf("%w: it reached %s, which its recipe does not name. A derive may "+
			"reach its index_url and nothing else; add the host to index_url if it is part "+
			"of the index", ErrRefused, strings.Join(refused, ", "))
	}
	// Reported second and worded differently, because the fix is a different
	// one: the host may well be the index, and what is wrong is the client.
	if un := p.Untunneled(); len(un) > 0 {
		return fmt.Errorf("%w: it asked this proxy to fetch %s in cleartext instead of "+
			"tunnelling to it. A build reaches its index over a tunnel that nodary cannot "+
			"read, so a step has to use a client that speaks CONNECT — busybox wget does "+
			"not, where apk, pip and curl do", ErrRefused, strings.Join(un, ", "))
	}
	return nil
}
