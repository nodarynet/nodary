package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/nodarynet/nodary/internal/api"
)

// IsolatedSubnet is the host-local range nodary-isolated hands out.
//
// 10.88.0.0/24 rather than something in 172.17: docker's default bridge lives
// there, and a node that also runs docker must not have the two collide.
const IsolatedSubnet = "10.88.0.0/24"

// CNIConfigDir is where CNI looks for network configurations.
const CNIConfigDir = "/etc/cni/net.d"

// IsolatedConfName sorts after nothing else nodary writes and is prefixed so an
// operator can see whose it is.
const IsolatedConfName = "10-nodary-isolated.conflist"

// isolatedConf is docs/specs/03-agent.md §5's mechanism as CNI data.
//
// Three properties, and each is doing work:
//
//   - no `routes` entry and `isDefaultGateway: false` — the container gets an
//     address on the bridge and **no default route**. This is the control.
//   - `ipMasq: false` — nothing NATs this subnet out, so even a route added by
//     hand inside the container reaches nowhere.
//   - an empty `dns` — the container's resolv.conf names no resolver.
//
// The third is not belt and braces. Measured on this machine: a container with
// its default route removed still resolved names with live answers, because
// docker injects a resolver at 127.0.0.11 on the container's own loopback,
// which needs no route. Under CNI the bridge plugin fills resolv.conf from this
// block instead, so leaving it empty is what makes the DNS assertion in
// internal/agent/egress.go something the configuration actually delivers rather
// than something it happens to get away with.
// docs/plans/R4d-egress-isolation.md
func isolatedConf() map[string]any {
	return map[string]any{
		"cniVersion": "1.0.0",
		"name":       api.IsolatedNetwork,
		"plugins": []any{
			map[string]any{
				"type":   "bridge",
				"bridge": "nodary0",
				// The bridge holds an address, so the host has a route into the
				// subnet. **Without one, portmap's DNAT rewrites the destination
				// to an address the host cannot reach**, and the published port
				// is installed and silently dead — which is the exact trap this
				// network exists to avoid, arrived at from the other direction.
				//
				// It does not weaken the control. `isDefaultGateway` stays false
				// and no route is listed, so the container can address the host
				// on its own subnet and nothing beyond it. That reachability is
				// inherent: the gateway has to reach the model.
				//
				// It is also what the two mitigations below were always for. The
				// bridge plugin turns on IPv4 forwarding when it holds a gateway
				// address, so EnsureIsolatedNetwork turns forwarding off for this
				// interface and drops forwarded traffic from the subnet in
				// nftables. With `isGateway: false` those two guarded nothing.
				"isGateway":        true,
				"isDefaultGateway": false,
				"forceAddress":     false,
				"ipMasq":           false,
				"hairpinMode":      false,
				"ipam": map[string]any{
					"type":   "host-local",
					"ranges": []any{[]any{map[string]any{"subnet": IsolatedSubnet}}},
					// No "routes". The host-local plugin adds a default route
					// only when one is listed here, so its absence is the
					// absence of the route.
				},
				"dns": map[string]any{},
			},
			// portmap publishes the deployment's port. It is what makes the
			// gateway able to reach a model that can reach nothing, and it is
			// the half that docker's `--internal` silently discards — the trap
			// the spike found and R4-26 exists to assert against.
			//
			// No `externalSetMarkChain`. It names a chain for portmap to jump to
			// instead of creating its own, and `KUBE-MARK-MASQ` — which this
			// carried, copied from a Kubernetes example — is kube-proxy's. On a
			// host that is not a Kubernetes node it does not exist, and portmap
			// fails the whole attach:
			//
			//	plugin type="portmap" failed (add): unable to setup DNAT:
			//	Chain 'KUBE-MARK-MASQ' does not exist
			//
			// Omitted, portmap creates CNI-HOSTPORT-SETMARK itself, which is
			// what a standalone host needs.
			map[string]any{
				"type":         "portmap",
				"capabilities": map[string]any{"portMappings": true},
			},
		},
	}
}

// RenderIsolatedConf is the file written to /etc/cni/net.d.
func RenderIsolatedConf() ([]byte, error) {
	body, err := json.MarshalIndent(isolatedConf(), "", "  ")
	if err != nil {
		return nil, err
	}
	return append(body, '\n'), nil
}

// EnsureIsolatedNetwork creates docs/specs/03-agent.md §5's network.
//
// Everything here needs root, which the agent has because it drives systemctl.
// It is idempotent: the configuration is compared before it is written, and
// both host commands are `add`-style operations that are no-ops when the state
// is already right.
func EnsureIsolatedNetwork(ctx context.Context, h Host, cniDir string) (changed bool, err error) {
	want, err := RenderIsolatedConf()
	if err != nil {
		return false, err
	}
	path := filepath.Join(cniDir, IsolatedConfName)

	switch existing, err := os.ReadFile(path); {
	case err == nil && bytes.Equal(existing, want):
	case err != nil && !os.IsNotExist(err):
		return false, err
	default:
		if err := os.MkdirAll(cniDir, 0o755); err != nil {
			return false, err
		}
		if err := os.WriteFile(path, want, 0o644); err != nil {
			return false, fmt.Errorf("writing %s: %w", path, err)
		}
		changed = true
	}

	// IP forwarding off for this bridge. The kernel forwards between interfaces
	// when the global switch is on, and a node that also runs docker has it on;
	// this is the per-interface switch, so nodary turns off its own bridge
	// without touching anybody else's.
	//
	// IPv6 is disabled on the same interface rather than filtered. The CNI
	// configuration declares no v6 subnet, so nodary hands out no v6 address —
	// but on a dual-stack host whose router advertisements reach the bridge, a
	// container can autoconfigure a global address and a default route that has
	// nothing to do with us. Refusing the address is cheaper than policing what
	// is done with it, and a serving deployment needs no outbound path of either
	// family.
	for _, key := range []string{
		"net.ipv4.conf.nodary0.forwarding=0",
		"net.ipv6.conf.nodary0.disable_ipv6=1",
		"net.ipv6.conf.nodary0.accept_ra=0",
	} {
		if out, err := h.Run(ctx, "sysctl", "-w", key); err != nil {
			// Not fatal: the bridge does not exist until the first container
			// attaches, and the sysctl nodes appear with it. The nftables rules
			// below are what hold either way.
			_ = out
		}
	}

	// And the rule that drops forwarded traffic from the subnet, which holds
	// regardless of what any sysctl says later.
	if err := ensureDropRule(ctx, h); err != nil {
		return changed, err
	}
	return changed, nil
}

// nodaryTable and nodaryChain are nodary's own, so nothing here edits a rule
// somebody else wrote. Removing the table removes exactly what nodary added.
const (
	nodaryTable = "nodary"
	nodaryChain = "isolate"
)

// ensureDropRule installs the nftables rule of docs/specs/03-agent.md §5.
//
// A dedicated table rather than a rule appended to `filter`: a node is rarely
// only a nodary node, and appending to a chain somebody else owns makes
// uninstall a question of finding our rule among theirs.
func ensureDropRule(ctx context.Context, h Host) error {
	// `add` is idempotent for a table and a chain; the rule is flushed first so
	// running this twice does not stack duplicates.
	for _, args := range [][]string{
		{"add", "table", "inet", nodaryTable},
		{"add", "chain", "inet", nodaryTable, nodaryChain,
			"{ type filter hook forward priority -10 ; policy accept ; }"},
		{"flush", "chain", "inet", nodaryTable, nodaryChain},
		{"add", "rule", "inet", nodaryTable, nodaryChain,
			"ip", "saddr", IsolatedSubnet, "drop"},
		// By interface as well as by source, which is what covers IPv6.
		//
		// The rule above matches an IPv4 source address, and there is no v6
		// counterpart to write because nodary allocates no v6 subnet — so a
		// container that autoconfigured a global v6 address off a router
		// advertisement was forwarded without ever meeting a rule. Matching the
		// bridge catches every family, including one nobody has thought of.
		//
		// It does not cost the published port. portmap's DNAT arrives on
		// another interface, and container-to-host traffic is delivered locally
		// rather than forwarded, so neither passes this hook.
		{"add", "rule", "inet", nodaryTable, nodaryChain,
			"iifname", "nodary0", "drop"},
	} {
		if out, err := h.Run(ctx, "nft", args...); err != nil {
			return fmt.Errorf("nft %v: %w: %s", args, err, tail(out))
		}
	}
	return nil
}
