package agent

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Real lines, copied from a running kernel rather than invented.
//
// The first two are what a host with **no IPv6 egress at all** carries: two
// ::/0 entries on `lo`, flags 00200200 and metric ffffffff — RTF_REJECT with an
// infinite metric, which is how the kernel spells `unreachable default`. They
// are the reason this cannot be "is there a ::/0 line": that reading would
// report every ordinary host non-isolated, which is a check that fails
// everywhere — the same defect as one that passes everywhere, inverted. `ip -6
// route` hides them, so reading /proc means reading it properly.
const (
	unreachableDefault6 = "" +
		"fe800000000000000000000000000000 40 00000000000000000000000000000000 00 00000000000000000000000000000000 00000100 00000001 00000000 00000001     eth0\n" +
		"00000000000000000000000000000000 00 00000000000000000000000000000000 00 00000000000000000000000000000000 ffffffff 00000001 00000000 00200200       lo\n" +
		"00000000000000000000000000000001 80 00000000000000000000000000000000 00 00000000000000000000000000000000 00000000 00000013 00000000 80200001       lo\n"

	// What a router advertisement installs: ::/0 via a link-local next hop on a
	// real interface, ordinary metric, RTF_UP|RTF_GATEWAY|RTF_ADDRCONF. This is
	// the exposure R4-39's accept_ra=0 exists for, and what nothing verified.
	announcedDefault6 = "" +
		"fe800000000000000000000000000000 40 00000000000000000000000000000000 00 00000000000000000000000000000000 00000100 00000001 00000000 00000001   nodary0\n" +
		"00000000000000000000000000000000 00 00000000000000000000000000000000 00 fe800000000000000042b0fffe1a2b3c 00000400 00000000 00000000 00040003   nodary0\n"
)

func writeTable(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ipv6_route")
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestAnUnreachableDefaultIsNotAnIPv6Route(t *testing.T) {
	via, err := defaultRoute6From(writeTable(t, unreachableDefault6))
	if err != nil {
		t.Fatal(err)
	}
	if via != "" {
		t.Errorf("read an unreachable default as egress via %q", via)
	}
}

func TestARouterAdvertisedDefaultIsAnIPv6Route(t *testing.T) {
	via, err := defaultRoute6From(writeTable(t, announcedDefault6))
	if err != nil {
		t.Fatal(err)
	}
	if via != "nodary0" {
		t.Errorf("via = %q, want the interface the advertisement arrived on", via)
	}
}

// The absence of /proc/net/ipv6_route means the namespace has no IPv6 stack, so
// no IPv6 route is possible — not that the check could not run. R4-39 sets
// disable_ipv6 on the isolated bridge, so this is the ordinary case on a
// correctly configured node, and treating it as a failure would make every such
// node report non-isolated.
func TestNoIPv6StackIsNotAFailedCheck(t *testing.T) {
	via, err := defaultRoute6From(filepath.Join(t.TempDir(), "ipv6_route"))
	if err != nil || via != "" {
		t.Errorf("via = %q, err = %v; a missing table is no route, not an error", via, err)
	}
}

// A missing /proc/net/route is a different thing: there is no Linux namespace
// without IPv4 routing, so it means the check could not run.
func TestAnUnreadableIPv4TableIsNotIsolation(t *testing.T) {
	if _, err := defaultRoute4From(filepath.Join(t.TempDir(), "route")); err == nil {
		t.Error("a missing /proc/net/route was read as no route rather than as a failed check")
	}
}

// The whole check, over both families. The IPv4 table below is a header and one
// non-default route, which is what an isolated namespace's looks like.
const noDefaultRoute4 = "" +
	"Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n" +
	"nodary0\t0000A8C0\t00000000\t0001\t0\t0\t0\t00FFFFFF\t0\t0\t0\n"

const announcedDefault4 = "" +
	"Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n" +
	"eth0\t00000000\t0100A8C0\t0003\t0\t0\t0\t00000000\t0\t0\t0\n"

func TestTheRouteCheckCoversBothFamilies(t *testing.T) {
	for _, tc := range []struct {
		what           string
		v4, v6         string
		isolated       bool
		detailMentions []string
	}{
		{"neither family has a way out", noDefaultRoute4, unreachableDefault6, true,
			[]string{"no default route"}},
		// The exposure R4-39 exists for, and what an IPv4-only probe reported as
		// isolation: a container that autoconfigured a global address and a
		// default route from a router advertisement.
		{"IPv6 only, from an advertisement", noDefaultRoute4, announcedDefault6, false,
			[]string{"IPv6", "nodary0"}},
		{"IPv4 only", announcedDefault4, unreachableDefault6, false,
			[]string{"IPv4", "eth0"}},
		{"both", announcedDefault4, announcedDefault6, false,
			[]string{"IPv4", "IPv6", "eth0", "nodary0"}},
	} {
		c := routeCheck(writeTable(t, tc.v4), writeTable(t, tc.v6))
		if c.Isolated != tc.isolated {
			t.Errorf("%s: isolated = %v, want %v (%s)", tc.what, c.Isolated, tc.isolated, c.Detail)
		}
		// The message has to name which family is open, or it sends an operator
		// looking in the wrong table.
		for _, want := range tc.detailMentions {
			if !strings.Contains(c.Detail, want) {
				t.Errorf("%s: detail %q does not mention %q", tc.what, c.Detail, want)
			}
		}
	}
}

// The connect check reaches for both families, so a namespace with IPv6-only
// egress is not reported isolated by a probe that only ever dialed 1.1.1.1.
func TestTheConnectCheckReachesForBothFamilies(t *testing.T) {
	if !strings.HasPrefix(probeAddr6, "[") {
		t.Errorf("probeAddr6 = %q, want a bracketed IPv6 literal", probeAddr6)
	}
	if probeAddr == probeAddr6 {
		t.Error("both targets are the same address")
	}
}
