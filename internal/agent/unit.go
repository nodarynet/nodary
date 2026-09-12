package agent

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
)

// UnitTemplate is docs/specs/03-agent.md §6, verbatim.
//
// One templated unit, one instance per deployment, `%i` the deployment id. The
// agent writes only the environment file and calls systemctl; systemd owns
// restart, backoff and process lifetime, and this file is the whole of the
// contract between them.
//
// The variable names here and the ones internal/agent/plan.go renders are one
// contract in two places. A template edited by hand that no longer reads
// NODARY_ARGS produces a model server started with no arguments at all, so the
// agent rewrites this when it drifts rather than trusting what it finds.
//
// **NODARY_ARGS is unbraced and every other variable is braced, and the
// difference is load-bearing.** systemd splits `$FOO` at whitespace into
// separate arguments and passes `${FOO}` as one argument, never split. The
// argument list has to be split; an image reference must not be. Measured on
// systemd 255: with `${NODARY_ARGS}` the whole argv arrives as a single string
// and the model server exits on an unrecognized argument, which is a failure
// that surfaces on a GPU host as a container that will not start. This
// corrects docs/specs/03-agent.md §6, which had it braced.
const unitTemplate = `# Written by nodary. Edits are overwritten; see docs/specs/03-agent.md §6.
[Unit]
Description=nodary model deployment %%i
After=containerd.service
Requires=containerd.service

# docs/specs/11-failure-modes.md §2: a crash-looping deployment is "marked
# failed after N restarts in a window". systemd implements exactly that, and
# the window has to be set explicitly — its default is 10s, which RestartSec
# below can never fit five restarts into, so the default limit is unreachable
# and a crash-loop restarts forever without anything ever calling it failed.
# Five in five minutes: a transient crash costs one and recovers, and a model
# server that cannot start burns the budget and stops, visibly.
StartLimitIntervalSec=300
StartLimitBurst=5

[Service]
Type=exec
EnvironmentFile=%[1]s/deployments/%%i.env
ExecStartPre=-/usr/local/bin/nerdctl rm -f nodary-%%i
ExecStart=/usr/local/bin/nerdctl run --rm --name nodary-%%i \
    --gpus ${NODARY_GPUS} \
    $NODARY_ENV \
    --network ${NODARY_NETWORK} \
    -v ${NODARY_MODELS_DIR}:${NODARY_MOUNT_PATH}:ro \
    -p 127.0.0.1:${NODARY_PORT}:${NODARY_CONTAINER_PORT} \
    ${NODARY_IMAGE} $NODARY_ARGS
ExecStop=/usr/local/bin/nerdctl stop --time 30 nodary-%%i
Restart=always
RestartSec=10s

# Defense in depth only. NOT the egress control.
#
# The container is parented outside this unit's cgroup — containerd's shim
# reparents it — so this filter attaches to the nerdctl client and not to the
# model. And a user-session manager is delegated cpu, memory and pids with no
# network controller at all, so in a user unit it has nothing to attach to.
# Both were measured; see docs/spike-fips-and-manifest.md §5.
#
# The control is the network namespace with no route off-box
# (docs/specs/03-agent.md §5), asserted by 'nodary node verify-egress'.
IPAddressDeny=any
IPAddressAllow=localhost

[Install]
WantedBy=multi-user.target
`

// RenderUnitTemplate fills in the configuration directory.
//
// The directory is a parameter for one reason: a test has to be able to drive
// real systemd against a temporary tree. In production it is always
// paths.ConfigDir, and nothing in the product passes anything else.
func RenderUnitTemplate(configDir string) string {
	return fmt.Sprintf(unitTemplate, configDir)
}

// UnitName is the instance for one deployment.
func UnitName(deployment string) string { return "nodary-model@" + deployment + ".service" }

// TemplateName is the unit file the instances come from.
const TemplateName = "nodary-model@.service"

// EnsureUnitTemplate writes the template if it is absent or has drifted, and
// reports whether it changed — which is what tells the caller to reload.
//
// The port publication is here rather than optional: docs/specs/03-agent.md §5
// requires a deployment's port on 127.0.0.1 only, so the container is reachable
// by the gateway and by nothing off-host (R4-27).
func EnsureUnitTemplate(unitDir, configDir string) (changed bool, err error) {
	path := filepath.Join(unitDir, TemplateName)
	want := []byte(RenderUnitTemplate(configDir))
	switch existing, err := os.ReadFile(path); {
	case err == nil && bytes.Equal(existing, want):
		return false, nil
	case err != nil && !os.IsNotExist(err):
		return false, err
	}
	if err := os.MkdirAll(unitDir, 0o755); err != nil {
		return false, err
	}
	if err := os.WriteFile(path, want, 0o644); err != nil {
		return false, fmt.Errorf("writing %s: %w", path, err)
	}
	return true, nil
}
