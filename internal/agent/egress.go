package agent

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// The three assertions of dev/specs/03-agent.md §5: a route off-box, a DNS
// lookup, and a connection to a known-external address must all fail.
//
// They are not redundant, and that was measured rather than assumed. On a
// container with its default route removed, TCP to an external address was
// refused and a DNS lookup **resolved, with live answers** — docker injects a
// resolver at 127.0.0.11 on the container's own loopback, which needs no route
// to reach and proxies queries out through the daemon. A compromised model
// server does not need to connect anywhere: `<data>.attacker.example` is a
// channel out of a container that passes a route check.
//
// dev/plans/R4d-egress-isolation.md carries the measurement.
const (
	CheckRoute   = "route"
	CheckDNS     = "dns"
	CheckConnect = "connect"
)

// What the DNS and connect checks reach for.
//
// Both are chosen to succeed from anywhere with egress at all, because both
// checks establish isolation by *failing* — and a target that fails everywhere
// makes the check pass everywhere, including where it should not.
//
// That is not hypothetical: this started as `nodary-egress-probe.example.com`,
// and running it on this host reported DNS isolated. A name that does not exist
// returns NXDOMAIN from a working resolver just as readily as from no resolver
// at all, so the check would have passed on a host with DNS — and, worse, would
// have passed inside the very container whose injected resolver this check
// exists to catch.
//
// example.com is IANA-reserved and permanent; 1.1.1.1:443 answers from anywhere
// with a route off-box, and 2606:4700:4700::1111 is the same resolver over IPv6.
//
// Both families, because R4-39 made the isolated bridge refuse IPv6 —
// disable_ipv6, accept_ra=0, and a drop rule keyed on the interface rather than
// on an address family — and nothing verified any of it. The exposure that
// change exists for is a container autoconfiguring a *global* v6 address from a
// router advertisement, which is egress that an IPv4-only probe reports as
// isolation.
var (
	probeName  = "example.com"
	probeAddr  = "1.1.1.1:443"
	probeAddr6 = "[2606:4700:4700::1111]:443"
)

// egressTimeout bounds each check. Short, because three checks run after every
// deployment start and a slow assertion is one somebody turns off.
const egressTimeout = 4 * time.Second

// Check is one assertion and what it observed.
type Check struct {
	Name string `json:"name"`
	// Isolated is true when the check found what isolation requires — that is,
	// when the operation *failed*. The field is named for the property rather
	// than the outcome, because "passed: false" for a successful DNS lookup
	// reads backwards in a report an assessor sees.
	Isolated bool   `json:"isolated"`
	Detail   string `json:"detail"`
}

// EgressProbe is the result of running all three in one namespace.
type EgressProbe struct {
	Checks []Check `json:"checks"`
}

// Isolated reports whether every check found isolation.
func (p EgressProbe) Isolated() bool {
	if len(p.Checks) == 0 {
		return false
	}
	for _, c := range p.Checks {
		if !c.Isolated {
			return false
		}
	}
	return true
}

// RunProbe performs the three checks in the current network namespace.
//
// It is the whole of what runs inside a deployment: `nodary node verify-egress`
// enters the namespace with nsenter and invokes this. Nothing here needs a tool
// the model's image happens to contain, which is the point — no vLLM image
// promises `ip` or `nc`.
func RunEgressProbe(ctx context.Context) EgressProbe {
	return EgressProbe{Checks: []Check{
		checkDefaultRoute(),
		checkDNS(ctx),
		checkConnect(ctx),
	}}
}

// checkDefaultRoute reads the kernel's tables rather than shelling out to `ip`.
//
// Reading /proc directly means the probe has no dependency on iproute2 being
// present in whatever namespace it lands in — no vLLM image promises it.
//
// **Both families, in one check rather than two.** The report's shape does not
// move, and "is there a way off this box" is one question: a namespace with a
// v6 default route and no v4 one has egress, and answering that with two checks
// where one says `isolated` invites reading the wrong one.
func checkDefaultRoute() Check {
	return routeCheck("/proc/net/route", "/proc/net/ipv6_route")
}

// routeCheck is checkDefaultRoute against named tables, so a test can drive the
// whole check — including which family its message names — from a fixture
// rather than from whatever the machine running the test happens to be plugged
// into.
func routeCheck(v4Path, v6Path string) Check {
	c := Check{Name: CheckRoute}
	v4, err := defaultRoute4From(v4Path)
	if err != nil {
		// Not isolated: the check could not run, and a check that could not run
		// must never report the property it was meant to establish.
		c.Detail = err.Error()
		return c
	}
	v6, err := defaultRoute6From(v6Path)
	if err != nil {
		c.Detail = err.Error()
		return c
	}

	switch {
	case v4 != "" && v6 != "":
		c.Detail = fmt.Sprintf("default routes exist: IPv4 via %s, IPv6 via %s", v4, v6)
	case v4 != "":
		c.Detail = "an IPv4 default route exists via " + v4
	case v6 != "":
		c.Detail = "an IPv6 default route exists via " + v6
	default:
		c.Isolated, c.Detail = true, "no default route, IPv4 or IPv6"
	}
	return c
}

// defaultRoute4From returns what a 0.0.0.0/0 route points at, or "" for none.
//
// A table that cannot be read is an error, not "no route": there is no Linux
// namespace without IPv4 routing, so failing to read it means the check could
// not run — and a check that could not run must never report the property it
// was meant to establish.
func defaultRoute4From(path string) (string, error) {
	return scanRoutes(path, defaultRoute4)
}

// defaultRoute6From is the same for ::/0.
//
// A *missing* table is not an error here: /proc/net/ipv6_route is absent when
// the namespace has no IPv6 stack at all, and that is the property rather than
// a failure to look for it. R4-39 sets disable_ipv6 on the isolated bridge, so
// this is the ordinary case on a correctly configured node.
func defaultRoute6From(path string) (string, error) {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return "", nil
	}
	return scanRoutes(path, defaultRoute6)
}

// scanRoutes reads one of the kernel's route tables with the matcher for its
// format, and returns the first match.
func scanRoutes(path string, match func([]string) string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("cannot read %s: %w", path, err)
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if via := match(strings.Fields(sc.Text())); via != "" {
			return via, nil
		}
	}
	if err := sc.Err(); err != nil {
		return "", fmt.Errorf("reading %s: %w", path, err)
	}
	return "", nil
}

// defaultRoute4 matches a line of /proc/net/route: iface, destination, gateway.
// A destination of 00000000 is 0.0.0.0/0. The header line has no such column
// and falls out on its own.
func defaultRoute4(fields []string) string {
	if len(fields) < 3 || fields[1] != "00000000" {
		return ""
	}
	return fields[0]
}

// zeroAddr6 is ::/0's destination column.
const zeroAddr6 = "00000000000000000000000000000000"

// Route flags and metrics that mean a ::/0 entry carries nothing.
//
// **Measured, not assumed.** A host with no IPv6 egress at all carries two
// ::/0 entries on `lo`, flags 00200200 and metric ffffffff — RTF_REJECT with an
// infinite metric, which is how the kernel spells `unreachable default`. Taking
// any ::/0 line as egress would have made this check report non-isolated on
// every ordinary host, which is the same defect as a check that passes
// everywhere, inverted. `ip -6 route` hides these, which is exactly why reading
// /proc means reading it properly.
const (
	rtfReject      = 0x0200
	metricInfinite = 0xffffffff
)

// defaultRoute6 matches a line of /proc/net/ipv6_route: destination, prefix
// length, source, source prefix, next hop, metric, refcount, use, flags, device.
func defaultRoute6(fields []string) string {
	if len(fields) < 10 || fields[0] != zeroAddr6 || fields[1] != "00" {
		return ""
	}
	if metric, err := strconv.ParseUint(fields[5], 16, 64); err == nil && metric == metricInfinite {
		return ""
	}
	if flags, err := strconv.ParseUint(fields[8], 16, 64); err == nil && flags&rtfReject != 0 {
		return ""
	}
	return fields[9]
}

// checkDNS must fail. See the note at the top of this file: this is the check
// that catches an injected in-namespace resolver, and it is the reason the
// three assertions are not one.
func checkDNS(ctx context.Context) Check {
	c := Check{Name: CheckDNS}
	ctx, cancel := context.WithTimeout(ctx, egressTimeout)
	defer cancel()

	addrs, err := net.DefaultResolver.LookupHost(ctx, probeName)
	if err != nil {
		c.Isolated, c.Detail = true, "cannot resolve "+probeName+": "+errSummary(err)
		return c
	}
	c.Detail = fmt.Sprintf("%s resolved to %s — something in this namespace answers DNS",
		probeName, strings.Join(addrs, ", "))
	return c
}

// checkConnect must fail, over both families.
//
// The two dials run together rather than in sequence. egressTimeout is short
// because this runs after every deployment start and a slow assertion is one
// somebody turns off; doing them one after the other would have doubled the
// worst case for the same answer.
func checkConnect(ctx context.Context) Check {
	c := Check{Name: CheckConnect}
	ctx, cancel := context.WithTimeout(ctx, egressTimeout)
	defer cancel()

	targets := []string{probeAddr, probeAddr6}
	// Indexed rather than appended to from the goroutines: the report then
	// carries the targets in the order they are declared, and does not reshuffle
	// itself between runs because two dials finished in a different order.
	// An empty entry is a target that was reached.
	failed := make([]string, len(targets))
	var wg sync.WaitGroup
	for i, addr := range targets {
		wg.Add(1)
		go func() {
			defer wg.Done()
			var d net.Dialer
			conn, err := d.DialContext(ctx, "tcp", addr)
			if err != nil {
				failed[i] = addr + ": " + errSummary(err)
				return
			}
			conn.Close()
		}()
	}
	wg.Wait()

	var reached, refused []string
	for i, addr := range targets {
		if failed[i] == "" {
			reached = append(reached, addr)
		} else {
			refused = append(refused, failed[i])
		}
	}
	if len(reached) > 0 {
		c.Detail = "connected to " + strings.Join(reached, " and ")
		return c
	}
	c.Isolated, c.Detail = true, "cannot reach "+strings.Join(refused, "; ")
	return c
}

// EgressVerdict is one deployment's compliance, with the control run that makes it
// mean something.
type EgressVerdict struct {
	Deployment string `json:"deployment"`
	// State is `compliant`, `non-compliant`, or `inconclusive`.
	State  string      `json:"state"`
	Reason string      `json:"reason"`
	Inside EgressProbe `json:"inside"`
	Host   EgressProbe `json:"host"`
}

// Compliance states.
const (
	Compliant    = "compliant"
	NonCompliant = "non-compliant"
	Inconclusive = "inconclusive"
)

// Judge compares a probe run inside a deployment against one run on the host.
//
// The control run is what stops this assertion quietly meaning nothing. Every
// check here passes by failing, so on a host with no egress at all — a genuinely
// air-gapped site, which is a customer this product is aimed at — the
// in-namespace probe fails for reasons unrelated to the isolation and would
// report compliant. The isolation may well be correct; the point is that the
// check did not establish it, and saying so is the honest answer
// (dev/plans/R4d-egress-isolation.md §3).
func Judge(deployment string, inside, host EgressProbe) EgressVerdict {
	v := EgressVerdict{Deployment: deployment, Inside: inside, Host: host}

	if !inside.Isolated() {
		v.State = NonCompliant
		var broken []string
		for _, c := range inside.Checks {
			if !c.Isolated {
				broken = append(broken, c.Name+": "+c.Detail)
			}
		}
		v.Reason = strings.Join(broken, "; ")
		return v
	}

	// The host reaching nothing means the in-namespace result proves nothing.
	if host.Isolated() {
		v.State = Inconclusive
		v.Reason = "this host has no egress of its own, so the isolation inside the deployment " +
			"cannot be distinguished from the host's own lack of reach"
		return v
	}

	v.State, v.Reason = Compliant, "no default route, no DNS, no reachable external address"
	return v
}

// errSummary keeps a network error to its useful part. Go's dial errors carry
// the whole address and operation, which is noise in a report that already
// names what was attempted.
func errSummary(err error) string {
	s := err.Error()
	if i := strings.LastIndex(s, ": "); i >= 0 && i < len(s)-2 {
		return s[i+2:]
	}
	return s
}

// VerifyEgress runs the probe inside a deployment's namespace and judges it.
//
// nsenter, because the agent is already root on the node — it drives systemctl
// — so entering the namespace costs nothing and needs no image. The
// alternatives all drag in a dependency the isolated network is specifically
// meant not to have: `nerdctl exec` needs the model's own image to contain
// `ip`, `nc` and a resolver tool, and a probe container is one more artifact to
// pin, distribute and stage onto an air-gapped node.
//
// The host control run is not optional. Every check here establishes isolation
// by failing, so on a host with no egress the in-namespace probe would report
// compliant without having established anything — see Judge.
func VerifyEgress(ctx context.Context, h Host, deployment, self string) (EgressVerdict, error) {
	pid, err := h.containerPID(ctx, deployment)
	if err != nil {
		return EgressVerdict{Deployment: deployment}, err
	}

	inside, err := h.probeIn(ctx, pid, self)
	if err != nil {
		return EgressVerdict{Deployment: deployment}, err
	}
	// On the host, in this process: the control run needs no namespace entry.
	return Judge(deployment, inside, RunEgressProbe(ctx)), nil
}

// containerPID finds the process whose network namespace the deployment runs in.
func (h Host) containerPID(ctx context.Context, deployment string) (string, error) {
	out, err := h.Run(ctx, "nerdctl", "inspect", "--format", "{{.State.Pid}}", "nodary-"+deployment)
	if err != nil {
		return "", fmt.Errorf("finding the container for %s: %w: %s", deployment, err, tail(out))
	}
	pid := strings.TrimSpace(string(out))
	if pid == "" || pid == "0" {
		return "", fmt.Errorf("deployment %s is not running, so there is no namespace to check", deployment)
	}
	return pid, nil
}

// probeIn runs this binary's own probe inside the namespace of pid.
func (h Host) probeIn(ctx context.Context, pid, self string) (EgressProbe, error) {
	var p EgressProbe
	out, err := h.Run(ctx, "nsenter", "--target", pid, "--net", "--",
		self, "agent", "egress-probe", "--format", "json")
	// Exit 1 means "not isolated", which is a result and not a failure to run.
	if err != nil && !json.Valid(jsonSpan(out)) {
		return p, fmt.Errorf("running the probe in the namespace of pid %s: %w: %s", pid, err, tail(out))
	}
	if err := json.Unmarshal(jsonSpan(out), &p); err != nil {
		return p, fmt.Errorf("reading the probe's output: %w: %s", err, tail(out))
	}
	return p, nil
}

// jsonSpan takes the JSON object out of command output that may carry a warning
// line before it.
func jsonSpan(out []byte) []byte {
	i := bytes.IndexByte(out, '{')
	j := bytes.LastIndexByte(out, '}')
	if i < 0 || j <= i {
		return out
	}
	return out[i : j+1]
}
