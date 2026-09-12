package cli

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/nodarynet/nodary/internal/agent"
)

// nodeVerbs that this release does not implement. They are listed rather than
// falling through to "unknown", because docs/specs/10-cli.md names them and an
// operator reading the specification should be told the difference between a
// verb that does not exist and one that is not built yet.
var nodeVerbs = map[string]string{
	"install":   "the full node install: preflight, components, the isolated network, then enroll",
	"policy":    "the node's local guardrails",
	"uninstall": "removing nodary from a node",
}

func cmdNode(e env, args []string) int {
	if len(args) == 0 {
		fmt.Fprintf(e.stderr,
			"nodary node: expected a subcommand (list, show, install, enroll, approve, drain, revoke, leave, verify-egress)\n")
		return ExitUsage
	}
	switch args[0] {
	case "list":
		return cmdNodeList(e, args[1:])
	case "show":
		return cmdNodeShow(e, args[1:])
	case "install":
		return cmdNodeInstall(e, args[1:])
	case "enroll":
		return cmdNodeEnroll(e, args[1:])
	case "verify-egress":
		return cmdNodeVerifyEgress(e, args[1:])
	case "approve":
		return cmdNodeTransition(e, args[1:], "approve", "approved")
	case "drain":
		return cmdNodeTransition(e, args[1:], "drain", "draining")
	case "revoke":
		return cmdNodeTransition(e, args[1:], "revoke", "departed")
	case "leave":
		return cmdNodeLeave(e, args[1:])
	}
	if what, ok := nodeVerbs[args[0]]; ok {
		fmt.Fprintf(e.stderr, "nodary node %s: %s is not implemented in this release (%s)\n",
			args[0], what, versionString())
		return ExitFailure
	}
	fmt.Fprintf(e.stderr,
		"nodary node: unknown subcommand %q (want list, show, install, enroll, approve, drain, revoke, leave or verify-egress)\n",
		args[0])
	return ExitUsage
}

// cmdNodeEnroll is step 4 of docs/specs/01-install.md §5, runnable on its own.
//
// It is separate from `node install` because docs/specs/02-enrollment.md §3
// requires a node offline past certificate expiry to re-enroll, and that is not
// a reinstall: the components, the isolated network and the units are all still
// in place and only the identity has lapsed.
func cmdNodeEnroll(e env, args []string) int {
	fs := newFlagSet(e, "node enroll")
	server := fs.String("server", "", "control plane URL, https://host:8443")
	token := fs.String("token", "", "join token from nodary token join")
	fingerprint := fs.String("ca-fingerprint", "", "the control plane certificate to pin, sha256:…")
	name := fs.String("name", "", "this node's name in the fleet (default: hostname)")
	confPath := fs.String("config", "", "agent.toml path")
	modelsDir := fs.String("models-dir", "", "where weights are staged")
	// docs/specs/12-node-guardrails.md §2 puts these on `node install`, which is
	// R5. Until it exists they belong here, because the file they write is what
	// the control plane is told this machine offers — and an operator who has
	// to hand-write TOML before enrolling will enrol offering everything.
	gpus := fs.String("gpus", "", "GPU indices to offer, comma-separated (default: all present)")
	maxDeployments := fs.Int("max-deployments", 0, "deployment ceiling (default: one per offered GPU)")
	maintenance := fs.String("maintenance", "", `maintenance window, e.g. "sat 02:00-06:00 UTC"`)
	format := formatFlag(fs)
	if code := parseFlags(e, fs, args); code >= 0 {
		return code
	}
	if !checkFormat(e, *format) {
		return ExitUsage
	}
	for _, req := range []struct{ flag, value string }{
		{"--server", *server}, {"--token", *token}, {"--ca-fingerprint", *fingerprint},
	} {
		if req.value == "" {
			fmt.Fprintf(e.stderr, "nodary node enroll: %s is required\n", req.flag)
			// The fingerprint is the one an operator is most likely to skip,
			// and skipping it is the one that matters
			// (docs/specs/02-enrollment.md §5).
			if req.flag == "--ca-fingerprint" {
				fmt.Fprintf(e.stderr,
					"  `nodary server install` prints it. Carry it to this host out of band —\n"+
						"  reading it off the network it protects proves nothing.\n")
			}
			return ExitUsage
		}
	}

	conf := *confPath
	if conf == "" {
		conf = agent.ConfigPath()
	}
	dir := filepath.Dir(conf)
	pki := filepath.Join(dir, "pki")
	nodeConf := filepath.Join(dir, "node.toml")

	if *gpus != "" || *maxDeployments > 0 || *maintenance != "" {
		if code := writeNodeConfig(e, nodeConf, *gpus, *maxDeployments, *maintenance); code != ExitOK {
			return code
		}
	}

	res, err := agent.Enroll(context.Background(), agent.EnrollOptions{
		Server: *server, Token: *token, CAFingerprint: *fingerprint,
		Name: *name, Dir: pki, NodeConfig: nodeConf,
	})
	if err != nil {
		fmt.Fprintf(e.stderr, "nodary node enroll: %v\n", err)
		return exitFor(err)
	}

	c := agent.Config{
		Server: *server, Name: res.Node, CAFingerprint: *fingerprint,
		Certificate: res.CertPath, Key: res.KeyPath,
		ModelsDir: orElse(*modelsDir, agent.DefaultModelsDir()),
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		fmt.Fprintf(e.stderr, "nodary node enroll: %v\n", err)
		return ExitFailure
	}
	if err := os.WriteFile(conf, agent.RenderConfig(c), 0o644); err != nil {
		fmt.Fprintf(e.stderr, "nodary node enroll: %v\n", err)
		return ExitFailure
	}

	if *format == "json" {
		return writeJSON(e, "node enroll", map[string]any{
			"node": res.Node, "state": res.State, "config": conf,
			"certificate": res.CertPath, "expires_at": res.ExpiresAt,
		})
	}
	fmt.Fprintln(e.stdout, res.Node)
	fmt.Fprintf(e.stderr, "Enrolled as %s. Wrote %s; the certificate expires %s.\n",
		res.Node, conf, res.ExpiresAt)
	if res.State == "pending" {
		// Said plainly, because a node that is up, healthy and idle is
		// otherwise indistinguishable from one that is broken.
		fmt.Fprintf(e.stderr,
			"\nThis node is pending and will receive no work until an administrator runs\n"+
				"  nodary node approve %s\n", res.Node)
	}
	return ExitOK
}

// writeNodeConfig places node.toml from the flags, refusing rather than
// overwriting: the file is edited by root on the node
// (docs/specs/12-node-guardrails.md §2), and silently replacing an operator's
// limits during a re-enrollment would widen what the machine offers without
// anybody asking.
func writeNodeConfig(e env, path, gpus string, maxDeployments int, maintenance string) int {
	if _, err := os.Stat(path); err == nil {
		fmt.Fprintf(e.stderr,
			"nodary node enroll: %s already exists; edit it rather than passing --gpus, --max-deployments or --maintenance\n",
			path)
		return ExitUsage
	}
	var c agent.NodeConfig
	for _, raw := range splitComma(gpus) {
		if raw == "" {
			continue
		}
		n, err := strconv.Atoi(strings.TrimSpace(raw))
		if err != nil {
			fmt.Fprintf(e.stderr, "nodary node enroll: --gpus %q is not a list of indices\n", gpus)
			return ExitUsage
		}
		c.Limits.GPUIndices = append(c.Limits.GPUIndices, n)
	}
	if maxDeployments > 0 {
		c.Limits.MaxDeployments = &maxDeployments
	}
	c.Window.Maintenance = maintenance
	if err := c.Validate(path); err != nil {
		fmt.Fprintf(e.stderr, "nodary node enroll: %v\n", err)
		return ExitUsage
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		fmt.Fprintf(e.stderr, "nodary node enroll: %v\n", err)
		return ExitFailure
	}
	if err := os.WriteFile(path, agent.RenderNodeConfig(c), 0o644); err != nil {
		fmt.Fprintf(e.stderr, "nodary node enroll: %v\n", err)
		return ExitFailure
	}
	return ExitOK
}

func orElse(s, d string) string {
	if s == "" {
		return d
	}
	return s
}

// cmdNodeVerifyEgress is docs/specs/03-agent.md §5's mandatory verification.
//
// It runs on the node, against a live deployment. Given how easy this mechanism
// is to get subtly wrong — twice measured, once for a network that silently
// discarded its published port and once for a resolver that survived route
// removal — an assertion that runs continuously is worth more than any amount
// of configuration review.
func cmdNodeVerifyEgress(e env, args []string) int {
	fs := newFlagSet(e, "node verify-egress")
	format := formatFlag(fs)
	if code := parseFlags(e, fs, args); code >= 0 {
		return code
	}
	if !checkFormat(e, *format) {
		return ExitUsage
	}
	rest := fs.Args()
	if len(rest) != 1 {
		fmt.Fprintf(e.stderr, "nodary node verify-egress: expected one deployment id\n")
		return ExitUsage
	}

	self, err := os.Executable()
	if err != nil {
		fmt.Fprintf(e.stderr, "nodary node verify-egress: %v\n", err)
		return ExitFailure
	}
	host := agent.RealHost("", "")
	v, err := agent.VerifyEgress(context.Background(), host, rest[0], self)
	if err != nil {
		fmt.Fprintf(e.stderr, "nodary node verify-egress: %v\n", err)
		return ExitFailure
	}

	if *format == "json" {
		if code := writeJSON(e, "node verify-egress", v); code != ExitOK {
			return code
		}
	} else {
		fmt.Fprintf(e.stdout, "%s %s\n", v.Deployment, v.State)
		for _, c := range v.Inside.Checks {
			state := "REACHABLE"
			if c.Isolated {
				state = "isolated"
			}
			fmt.Fprintf(e.stdout, "  %-8s %-10s %s\n", c.Name, state, c.Detail)
		}
		fmt.Fprintf(e.stderr, "%s\n", v.Reason)
	}

	switch v.State {
	case agent.Compliant:
		return ExitOK
	case agent.Inconclusive:
		// Not a failure and not a pass. Exit 2 so a script can tell the three
		// apart, and so nobody reads "did not establish it" as "established it".
		return ExitUsage
	}
	return ExitFailure
}
