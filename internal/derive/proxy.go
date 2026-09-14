// Package derive builds the corrected images of docs/specs/04-backends.md §5.
//
// **The egress allowlist is the point of this package**, not a detail of it.
// §5 requires a build to reach "the package index and nothing else", and the
// mechanism is the one internal/agent/network.go already measured into
// existence: a container on `nodary-isolated` has no default route, no NAT and
// an empty resolver, so it reaches nowhere at all. This adds exactly one hole —
// a CONNECT proxy on the host that will open a tunnel to one host and refuse
// every other — and the container has no second route to anything, including to
// the proxy's refusal.
//
// The shape matters. An IP allowlist in nftables would have to let DNS out for
// the container to resolve the index, and R4d measured DNS as the channel that
// survives a route check: `<data>.attacker.example` is an exfiltration path
// that passes every connectivity test. Here the container resolves nothing —
// the proxy resolves on its behalf — so there is no resolver to talk to.
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

	mu sync.Mutex
	// refused records what was reached for, in order, so a failed build can say
	// what it wanted rather than only that it failed. §5's whole claim is that
	// a build reaching outside its index fails instead of quietly succeeding
	// with something unexpected — which is unreadable without this.
	refused  []string
	allowedN int
}

// NewProxy allows exactly the hosts named, each as host:port.
func NewProxy(hosts ...string) *Proxy {
	p := &Proxy{allowed: make(map[string]bool, len(hosts))}
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
	if r.Method != http.MethodConnect {
		// An absolute-URI request is plain HTTP through the proxy. Refused
		// rather than forwarded: see the type comment.
		p.note(r.Host)
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
	refused := p.Refused()
	if len(refused) == 0 {
		return nil
	}
	return fmt.Errorf("%w: it reached %s, which its recipe does not name. A derive may reach "+
		"its index_url and nothing else; add the host to index_url if it is part of the index",
		ErrRefused, strings.Join(refused, ", "))
}
