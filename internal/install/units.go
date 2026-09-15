// Package install performs the privileged half of dev/specs/01-install.md:
// placing component binaries, writing systemd units, creating the service user
// and setting the filesystem layout.
//
// Every step here is idempotent and reports what it did, because 01 §4 requires
// the install to be re-runnable and because a step that cannot say whether it
// changed anything is a step nobody can safely repeat.
//
// Nothing in this package decides *whether* to install. Preflight does that,
// and it runs first.
package install

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/nodarynet/nodary/internal/paths"
)

// Runner executes a command. Injected for the same reason internal/agent's Host
// injects one: the whole boundary between decidable and undecidable here is
// "run a program", and a test needs to drive a host it is not on.
type Runner func(ctx context.Context, name string, args ...string) ([]byte, error)

// Exec is the real runner.
func Exec(ctx context.Context, name string, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, name, args...).CombinedOutput()
}

// Step is one thing the install did, or found already done.
type Step struct {
	Name    string `json:"name"`
	Changed bool   `json:"changed"`
	Detail  string `json:"detail"`
}

// Options are what the privileged steps need.
type Options struct {
	// Root prefixes every path, so a test can install into a temporary tree and
	// a real install passes "".
	Root string
	// BinDir is where component binaries are placed, normally /usr/local/bin.
	BinDir string
	// UnitDir is where systemd units go, normally /etc/systemd/system.
	UnitDir string
	// Binary is the nodary executable the units invoke.
	Binary string
	// User is the service account. Empty means run as root, which is what a
	// single-box `--with-node` install does because the agent needs it anyway.
	User string
	Run  Runner
}

// The defaults setDefaults applies, named so an uninstall removes from the same
// places an install wrote to rather than repeating two string literals that can
// drift apart.
const (
	DefaultBinDir  = "/usr/local/bin"
	DefaultUnitDir = "/etc/systemd/system"
)

func (o *Options) setDefaults() {
	if o.Run == nil {
		o.Run = Exec
	}
	if o.BinDir == "" {
		o.BinDir = DefaultBinDir
	}
	if o.UnitDir == "" {
		o.UnitDir = DefaultUnitDir
	}
	if o.Binary == "" {
		// The stable path, not wherever this process happens to be: the units
		// carry PrivateTmp and ProtectHome, and a binary under /tmp or /home is
		// invisible to the service. See EnsureBinary.
		o.Binary = paths.Binary()
	}
}

// path applies the root prefix.
func (o Options) path(p string) string {
	if o.Root == "" {
		return p
	}
	return filepath.Join(o.Root, p)
}

// serverUnit is nodary-server: the control plane.
//
// The hardening here is what a service that holds an audit chain and a sealing
// key should carry, and each line is doing work rather than being a copied
// template. `ProtectSystem=strict` with an explicit `ReadWritePaths` is what
// makes "nodary writes to three directories" a property of the process rather
// than a claim about the code.
const serverUnit = `# Written by nodary. Edits are overwritten.
[Unit]
Description=nodary control plane
After=network-online.target
Wants=network-online.target

[Service]
Type=exec
ExecStart=%[1]s server start
Restart=always
RestartSec=5s
%[2]s
# The sealing key is 01 §12's 0400 root:root and this unit is not root, so it
# arrives through systemd: read as root, placed in a tmpfs owned by the service
# account, exported as $CREDENTIALS_DIRECTORY. Chowning the key to the service
# account instead would work and would mean the account running the
# network-facing process can read the key that decrypts every TOTP seed and the
# agent CA. See resolveKey in internal/cli/session.go.
LoadCredential=secret.key:/etc/nodary/secret.key
# The control plane reads /etc/nodary and writes its database and audit mirror.
# Nothing else on the filesystem is writable, so a compromise of this process is
# not a compromise of the host.
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
NoNewPrivileges=true
ReadWritePaths=/var/lib/nodary /var/log/nodary
# The sealing key is read at startup and never written.
ReadOnlyPaths=/etc/nodary

[Install]
WantedBy=multi-user.target
`

// gatewayUnit is nodary-gateway: the inference API.
//
// It holds prompts in memory and writes nothing but usage rows, so it gets the
// same treatment and one line more: it has no business reading /etc/nodary's
// PKI at all.
//
// The master key reaches it through EnvironmentFile= and never through
// ExecStart=. Interpolating it into the command line published the one
// credential LiteLLM accepts to every local account via /proc/<pid>/cmdline.
const gatewayUnit = `# Written by nodary. Edits are overwritten.
[Unit]
Description=nodary inference gateway
After=nodary-server.service
Wants=nodary-server.service

[Service]
Type=exec
ExecStart=%[1]s gateway start
EnvironmentFile=/etc/nodary/gateway.env
Restart=always
RestartSec=5s
%[2]s
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
NoNewPrivileges=true
ReadWritePaths=/var/lib/nodary
ReadOnlyPaths=/etc/nodary

[Install]
WantedBy=multi-user.target
`

// agentUnit is nodary-agent.
//
// Root, and not the service user: it drives systemctl, enters network
// namespaces with nsenter to assert egress, and writes unit environment files.
// A service account with enough privilege to do all three is root with extra
// steps, and pretending otherwise would be the kind of security theatre this
// codebase argues against elsewhere.
const agentUnit = `# Written by nodary. Edits are overwritten.
[Unit]
Description=nodary node agent
After=network-online.target containerd.service
Wants=network-online.target

[Service]
Type=exec
ExecStart=%[1]s agent run
Restart=always
RestartSec=10s
# Root: the agent drives systemctl, writes unit environment files, and enters a
# deployment's network namespace to assert egress isolation. See the note in
# internal/install/units.go.

[Install]
WantedBy=multi-user.target
`

// containerdUnit starts the runtime the model units depend on.
//
// **The containerd release tarball ships no systemd unit** — it is `bin/ctr`,
// `bin/containerd`, `bin/containerd-shim-runc-v2` and nothing else. Upstream
// publishes one separately and expects a packager to place it, so nodary is the
// packager here. Without it `nodary-model@.service`'s `Requires=containerd.service`
// resolves to nothing and every deployment fails at start with "Unit
// containerd.service not found" — which is what a privileged run of
// scripts/verify-privileged.sh reported before this existed.
//
// The contents are upstream's own, with the delegation and OOM settings that
// matter: Delegate=yes so containerd manages its children's cgroups (which is
// the whole reason dev/specs/03-agent.md §5 says the model is parented outside
// the unit), and KillMode=process so stopping containerd does not take running
// containers with it.
const containerdUnit = `# Written by nodary. Edits are overwritten.
#
# containerd publishes no unit in its release tarball; this is upstream's, placed
# by nodary. See internal/install/units.go.
[Unit]
Description=containerd container runtime
Documentation=https://containerd.io
After=network.target local-fs.target

[Service]
ExecStartPre=-/sbin/modprobe overlay
ExecStart=/usr/local/bin/containerd
Type=notify
Delegate=yes
KillMode=process
Restart=always
RestartSec=5
LimitNPROC=infinity
LimitCORE=infinity
TasksMax=infinity
OOMScoreAdjust=-999

[Install]
WantedBy=multi-user.target
`

// litellmUnit runs the OpenAI-compatible data plane.
//
// [00 §7](../specs/00-overview.md#7-why-litellm-stays): nodary owns identity,
// quota, metering and audit; LiteLLM owns OpenAI compatibility, routing,
// retries and fallbacks. It runs stateless behind one master key and needs no
// database, which is why this unit mounts a configuration and nothing else.
//
// **`--network host`, and that is not laziness.** A deployment publishes its
// port on the host's loopback (03 §5, `-p 127.0.0.1:…`), and a container on a
// bridge cannot reach the host's 127.0.0.1. Sharing the host namespace is what
// lets the data plane reach the models; it binds 127.0.0.1:4000 itself, so
// nothing it serves is reachable off-box either.
//
// The image comes from an environment file rather than being written into the
// unit, for the reason a deployment's image does: an upgrade rewrites one value
// instead of rewriting a unit systemd has to be told about.
const litellmUnit = `# Written by nodary. Edits are overwritten.
[Unit]
Description=LiteLLM, the OpenAI-compatible data plane for nodary
After=containerd.service
Requires=containerd.service

[Service]
Type=exec
EnvironmentFile=/etc/nodary/litellm.env
ExecStartPre=-/usr/local/bin/nerdctl rm -f nodary-litellm
ExecStart=/usr/local/bin/nerdctl run --rm --name nodary-litellm     --network host     -v /etc/nodary/litellm.yaml:/etc/litellm/config.yaml:ro     ${NODARY_LITELLM_IMAGE}     --config /etc/litellm/config.yaml --host 127.0.0.1 --port 4000
ExecStop=/usr/local/bin/nerdctl stop --time 30 nodary-litellm
Restart=always
RestartSec=10s

[Install]
WantedBy=multi-user.target
`

// pruneUnit applies dev/specs/08-data-model.md §3's retention windows once.
//
// Type=oneshot and triggered by pruneTimer, never enabled on its own: the work
// finishes, so a Restart= policy would run it in a loop.
//
// `--yes` skips the confirmation prompt and nothing else. Justification still
// applies and is supplied here; TOTP re-authentication does not, because
// attest.NeedsTOTP exempts a local act and this one runs on the appliance as
// the service account. That exemption is recorded in the record itself as
// `totp_exempt: local` rather than assumed, which is core.go's rule.
//
// Same confinement as the server, and for the same reason: it holds the
// database open and has no business writing anywhere else.
const pruneUnit = `# Written by nodary. Edits are overwritten.
[Unit]
Description=nodary retention pass
After=nodary-server.service

[Service]
Type=oneshot
ExecStart=%[1]s prune --yes --justify "scheduled retention pass"
%[2]s
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
NoNewPrivileges=true
ReadWritePaths=/var/lib/nodary
ReadOnlyPaths=/etc/nodary
`

// pruneTimer is the "periodic task" in dev/specs/08-data-model.md §3.
//
// A timer rather than a goroutine inside nodary-server, because a prune writes
// an audit record and a record needs an actor, a justification and an intent to
// bind. See cmdPrune, where that argument is made in full.
//
// Persistent=true: an appliance that was powered off over a weekend runs the
// pass it missed on the next boot. Without it, retention silently depends on
// uptime, and the tables that grow fastest are the ones on machines that get
// turned off.
const pruneTimer = `# Written by nodary. Edits are overwritten.
[Unit]
Description=nodary retention pass

[Timer]
OnCalendar=daily
Persistent=true

[Install]
WantedBy=timers.target
`

// gatewaySyncUnit re-renders the data plane from what the fleet currently
// reports, so route membership follows readiness without somebody running a
// command (R3-14).
//
// **It runs as root, and that is the whole reason it is a separate unit.**
// `gateway sync` writes /etc/nodary/litellm.yaml and restarts
// nodary-litellm.service. nodary-server holds the routes and deliberately
// cannot do either — `ProtectSystem=strict` with `ReadOnlyPaths=/etc/nodary` —
// because widening the network-facing process until it could rewrite the data
// plane's configuration and restart services is exactly the capability worth
// withholding. So the process that knows asks nobody, and a small periodic act
// that knows nothing does the writing.
//
// `ProtectSystem=full` rather than strict: /usr and /boot stay read-only and
// /etc does not, because /etc/nodary is what this writes.
//
// It is cheap when nothing moved. `gateway sync` compares the rendered file
// against what the running LiteLLM was started with and restarts only when they
// differ, so the ordinary tick writes nothing and restarts nothing.
const gatewaySyncUnit = `# Written by nodary. Edits are overwritten.
[Unit]
Description=nodary data plane sync
After=nodary-server.service

[Service]
Type=oneshot
ExecStart=%[1]s gateway sync
ProtectHome=true
PrivateTmp=true
NoNewPrivileges=true
ProtectSystem=full
`

// gatewaySyncTimer is how often membership catches up with readiness.
//
// A minute, and the latency is deliberate rather than a limitation to apologize
// for. A model takes minutes to load, so a deployment joining its route within
// sixty seconds of reporting ready is not the constraint on anything; and the
// case that has to be fast — a replica that stops answering mid-request — is
// handled on the request path by the router's own cooldown (see
// internal/gateway's router_settings), which needs no restart at all. Polling
// faster would buy latency nobody is waiting on and pay for it in data-plane
// restarts, which drop live requests.
//
// No Persistent=: this catches up with the present rather than running a pass
// it missed, and a boot starts LiteLLM from the current file anyway.
const gatewaySyncTimer = `# Written by nodary. Edits are overwritten.
[Unit]
Description=nodary data plane sync

[Timer]
OnBootSec=1min
OnUnitActiveSec=1min

[Install]
WantedBy=timers.target
`

// Units are what an install writes, by role.
func Units(role string) map[string]string {
	switch role {
	case "server":
		return map[string]string{
			// containerd here too: the control plane runs LiteLLM as a
			// container, so the runtime is not a node-only concern. Its unit is
			// upstream's, placed by nodary, because the release tarball ships
			// none — see containerdUnit.
			"containerd.service":          containerdUnit,
			"nodary-server.service":       serverUnit,
			"nodary-gateway.service":      gatewayUnit,
			"nodary-litellm.service":      litellmUnit,
			"nodary-prune.service":        pruneUnit,
			"nodary-prune.timer":          pruneTimer,
			"nodary-gateway-sync.service": gatewaySyncUnit,
			"nodary-gateway-sync.timer":   gatewaySyncTimer,
		}
	case "node":
		return map[string]string{
			"containerd.service":   containerdUnit,
			"nodary-agent.service": agentUnit,
		}
	}
	return nil
}

// WriteUnits places the units for a role and reports whether systemd needs a
// reload.
func WriteUnits(ctx context.Context, role string, o Options) ([]Step, error) {
	o.setDefaults()
	dir := o.path(o.UnitDir)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}

	// The user lines, or nothing when running as root.
	userLines := ""
	if o.User != "" {
		userLines = fmt.Sprintf("User=%s\nGroup=%s", o.User, o.User)
	}

	var steps []Step
	var changed bool
	for name, tmpl := range Units(role) {
		// containerd's unit is upstream's text and takes no substitutions;
		// running it through Sprintf would be a no-op today and a corruption the
		// moment upstream's file contains a percent sign.
		body := []byte(tmpl)
		if strings.Contains(tmpl, "%[1]s") {
			body = []byte(fmt.Sprintf(tmpl, o.Binary, userLines))
		}
		path := filepath.Join(dir, name)
		step := Step{Name: "unit: " + name, Detail: path}

		if existing, err := os.ReadFile(path); err == nil && bytes.Equal(existing, body) {
			steps = append(steps, step)
			continue
		}
		if err := os.WriteFile(path, body, 0o644); err != nil {
			return steps, fmt.Errorf("writing %s: %w", path, err)
		}
		step.Changed, changed = true, true
		steps = append(steps, step)
	}

	if changed && o.Root == "" {
		if out, err := o.Run(ctx, "systemctl", "daemon-reload"); err != nil {
			return steps, fmt.Errorf("daemon-reload: %w: %s", err, strings.TrimSpace(string(out)))
		}
		steps = append(steps, Step{Name: "systemd", Changed: true, Detail: "daemon-reload"})
	}
	return steps, nil
}
