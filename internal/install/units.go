// Package install performs the privileged half of docs/specs/01-install.md:
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

func (o *Options) setDefaults() {
	if o.Run == nil {
		o.Run = Exec
	}
	if o.BinDir == "" {
		o.BinDir = "/usr/local/bin"
	}
	if o.UnitDir == "" {
		o.UnitDir = "/etc/systemd/system"
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
const gatewayUnit = `# Written by nodary. Edits are overwritten.
[Unit]
Description=nodary inference gateway
After=nodary-server.service
Wants=nodary-server.service

[Service]
Type=exec
ExecStart=%[1]s gateway start --master-key ${NODARY_MASTER_KEY}
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
// the whole reason docs/specs/03-agent.md §5 says the model is parented outside
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

// Units are what an install writes, by role.
func Units(role string) map[string]string {
	switch role {
	case "server":
		return map[string]string{
			"nodary-server.service":  serverUnit,
			"nodary-gateway.service": gatewayUnit,
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
