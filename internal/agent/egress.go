package agent

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"
	"time"
)

// The three assertions of docs/specs/03-agent.md §5: a route off-box, a DNS
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
// docs/plans/R4d-egress-isolation.md carries the measurement.
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
// with a route off-box.
var (
	probeName = "example.com"
	probeAddr = "1.1.1.1:443"
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

// checkDefaultRoute reads the kernel's table rather than shelling out to `ip`.
//
// /proc/net/route lists a default route as destination 00000000 with the
// RTF_GATEWAY flag. Reading it directly means the probe has no dependency on
// iproute2 being present in whatever namespace it lands in.
func checkDefaultRoute() Check {
	c := Check{Name: CheckRoute}
	f, err := os.Open("/proc/net/route")
	if err != nil {
		// Not isolated: the check could not run, and a check that could not run
		// must never report the property it was meant to establish.
		c.Detail = "cannot read /proc/net/route: " + err.Error()
		return c
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	sc.Scan() // the header
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 3 {
			continue
		}
		if fields[1] == "00000000" {
			c.Detail = fmt.Sprintf("a default route exists via %s", fields[0])
			return c
		}
	}
	if err := sc.Err(); err != nil {
		c.Detail = "reading /proc/net/route: " + err.Error()
		return c
	}
	c.Isolated, c.Detail = true, "no default route"
	return c
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

// checkConnect must fail.
func checkConnect(ctx context.Context) Check {
	c := Check{Name: CheckConnect}
	ctx, cancel := context.WithTimeout(ctx, egressTimeout)
	defer cancel()

	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", probeAddr)
	if err != nil {
		c.Isolated, c.Detail = true, "cannot reach "+probeAddr+": "+errSummary(err)
		return c
	}
	conn.Close()
	c.Detail = "connected to " + probeAddr
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
// (docs/plans/R4d-egress-isolation.md §3).
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
