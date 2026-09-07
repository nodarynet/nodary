package agent

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// probeInside runs the probe in a fresh, empty network namespace.
//
// `unshare --net` gives a namespace with nothing but a down loopback: no
// default route, no resolver, nothing reachable. That is the shape the isolated
// network aims at, and it needs no root — so this assertion runs everywhere,
// not only where docker happens to be installed.
func probeInside(t *testing.T) EgressProbe {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := exec.LookPath("unshare"); err != nil {
		t.Skip("unshare is not installed")
	}
	cmd := exec.Command("unshare", "--user", "--net", "--map-root-user",
		self, "-test.run", "TestProbeHelper")
	cmd.Env = append(os.Environ(), "NODARY_PROBE_HELPER=1")
	out, err := cmd.Output()
	if err != nil {
		t.Skipf("cannot create a network namespace here: %v", err)
	}
	var p EgressProbe
	if err := json.Unmarshal(probeJSON(t, out), &p); err != nil {
		t.Fatalf("probe output: %v\n%s", err, out)
	}
	return p
}

// TestProbeHelper is the child process probeInside runs. It is a test rather
// than a separate binary so there is nothing extra to build.
func TestProbeHelper(t *testing.T) {
	if os.Getenv("NODARY_PROBE_HELPER") != "1" {
		t.Skip("helper")
	}
	raw, err := json.Marshal(RunEgressProbe(context.Background()))
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout.WriteString("PROBE" + string(raw) + "PROBE\n")
}

func probeJSON(t *testing.T, out []byte) []byte {
	t.Helper()
	s := string(out)
	i, j := strings.Index(s, "PROBE"), strings.LastIndex(s, "PROBE")
	if i < 0 || j <= i {
		t.Fatalf("no probe output in:\n%s", s)
	}
	return []byte(s[i+5 : j])
}

// An empty namespace is what isolation looks like: all three checks find it.
func TestTheProbeFindsIsolationInAnEmptyNamespace(t *testing.T) {
	p := probeInside(t)
	if !p.Isolated() {
		t.Errorf("an empty network namespace was not reported isolated: %+v", p.Checks)
	}
	if len(p.Checks) != 3 {
		t.Fatalf("checks = %d, want route, dns and connect", len(p.Checks))
	}
	for _, c := range p.Checks {
		if c.Detail == "" {
			t.Errorf("%s reported no detail; a verdict an assessor reads has to say what it saw", c.Name)
		}
	}
}

// And the host is not isolated, which is what makes the control run in Judge
// able to tell a real result from a vacuous one.
func TestTheProbeFindsTheHostNotIsolated(t *testing.T) {
	p := RunEgressProbe(context.Background())
	if p.Isolated() {
		t.Skip("this host has no egress of its own, so it cannot serve as a control")
	}
	var reached []string
	for _, c := range p.Checks {
		if !c.Isolated {
			reached = append(reached, c.Name)
		}
	}
	if len(reached) == 0 {
		t.Error("the host reported isolated on every check")
	}
}

// The verdict, including the case that stops this assertion quietly meaning
// nothing.
func TestJudge(t *testing.T) {
	isolated := EgressProbe{Checks: []Check{
		{Name: CheckRoute, Isolated: true, Detail: "no default route"},
		{Name: CheckDNS, Isolated: true, Detail: "name resolution failed"},
		{Name: CheckConnect, Isolated: true, Detail: "cannot reach 1.1.1.1:443"},
	}}
	open := EgressProbe{Checks: []Check{
		{Name: CheckRoute, Isolated: false, Detail: "a default route exists via 0100000A"},
		{Name: CheckDNS, Isolated: false, Detail: "resolved"},
		{Name: CheckConnect, Isolated: false, Detail: "connected"},
	}}
	// The measured case: no route, no connection, and DNS answering anyway.
	dnsOnly := EgressProbe{Checks: []Check{
		{Name: CheckRoute, Isolated: true, Detail: "no default route"},
		{Name: CheckDNS, Isolated: false, Detail: "resolved to 93.184.215.14"},
		{Name: CheckConnect, Isolated: true, Detail: "cannot reach 1.1.1.1:443"},
	}}

	for _, tc := range []struct {
		what         string
		inside, host EgressProbe
		want         string
	}{
		{"isolated, on a host with egress", isolated, open, Compliant},
		{"not isolated at all", open, open, NonCompliant},
		// The whole reason the three checks are not one.
		{"a route check that passes while DNS answers", dnsOnly, open, NonCompliant},
		// The air-gapped site: the isolation may be perfect, and this check did
		// not establish it.
		{"isolated, on a host with no egress either", isolated, isolated, Inconclusive},
	} {
		got := Judge("dep_one", tc.inside, tc.host)
		if got.State != tc.want {
			t.Errorf("%s: state = %q, want %q (%s)", tc.what, got.State, tc.want, got.Reason)
		}
		if got.Reason == "" {
			t.Errorf("%s: no reason given", tc.what)
		}
	}

	// A verdict with nothing in it is not compliance.
	if got := Judge("dep_one", EgressProbe{}, open); got.State != NonCompliant {
		t.Errorf("an empty probe = %q, want non-compliant", got.State)
	}
}

// The CNI configuration is data, and the three properties that make it the
// control are worth asserting rather than reading.
func TestTheIsolatedNetworkConfigurationDeniesWhatItMust(t *testing.T) {
	body, err := RenderIsolatedConf()
	if err != nil {
		t.Fatal(err)
	}
	var conf struct {
		Name    string `json:"name"`
		Plugins []struct {
			Type      string          `json:"type"`
			IsGateway *bool           `json:"isGateway"`
			IPMasq    *bool           `json:"ipMasq"`
			DNS       *map[string]any `json:"dns"`
			IPAM      struct {
				Routes []any `json:"routes"`
			} `json:"ipam"`
		} `json:"plugins"`
	}
	if err := json.Unmarshal(body, &conf); err != nil {
		t.Fatalf("the configuration is not JSON: %v\n%s", err, body)
	}
	if conf.Name != "nodary-isolated" {
		t.Errorf("name = %q", conf.Name)
	}

	bridge := conf.Plugins[0]
	if bridge.Type != "bridge" {
		t.Fatalf("first plugin = %q, want bridge", bridge.Type)
	}
	if bridge.IsGateway == nil || *bridge.IsGateway {
		t.Error("isGateway is not false; the container would get a default route")
	}
	if bridge.IPMasq == nil || *bridge.IPMasq {
		t.Error("ipMasq is not false; a route added by hand inside the container would reach out")
	}
	if len(bridge.IPAM.Routes) != 0 {
		t.Errorf("ipam.routes = %v, want none — a listed route is the route this control removes",
			bridge.IPAM.Routes)
	}
	// The measured one. A container with no default route still resolved names
	// through an injected in-namespace resolver, so the absence of a resolver
	// has to be configured rather than inferred.
	if bridge.DNS == nil || len(*bridge.DNS) != 0 {
		t.Errorf("dns = %v, want empty: no route does not imply no DNS", bridge.DNS)
	}

	// And the half that isolation configurations silently break.
	var hasPortmap bool
	for _, p := range conf.Plugins {
		if p.Type == "portmap" {
			hasPortmap = true
		}
	}
	if !hasPortmap {
		t.Error("no portmap plugin: the gateway could not reach a deployment at all")
	}
}

// Writing the configuration is idempotent, and the host commands are what a
// test can only check the shape of — creating the network needs root.
func TestEnsureIsolatedNetworkIsIdempotent(t *testing.T) {
	dir := t.TempDir()
	var calls []string
	h := Host{Run: func(_ context.Context, name string, args ...string) ([]byte, error) {
		calls = append(calls, name+" "+strings.Join(args, " "))
		return nil, nil
	}}

	changed, err := EnsureIsolatedNetwork(context.Background(), h, dir)
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Error("the first call reported no change")
	}
	again, err := EnsureIsolatedNetwork(context.Background(), h, dir)
	if err != nil {
		t.Fatal(err)
	}
	if again {
		t.Error("the second call rewrote the configuration")
	}

	joined := strings.Join(calls, "\n")
	// nodary's own table, so uninstall removes exactly what it added and
	// nothing here edits a rule somebody else wrote.
	if !strings.Contains(joined, "nft add table inet nodary") {
		t.Errorf("no nodary table was created:\n%s", joined)
	}
	if !strings.Contains(joined, IsolatedSubnet+" drop") {
		t.Errorf("nothing drops forwarded traffic from %s:\n%s", IsolatedSubnet, joined)
	}
	if strings.Contains(joined, "nft add rule inet filter") {
		t.Error("nodary appended to a chain it does not own")
	}
}
