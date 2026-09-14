package agent

import (
	"context"
	"os/exec"
	"strconv"
	"strings"

	"github.com/nodarynet/nodary/internal/preflight"
)

// GPU is one card as `nvidia-smi` reports it.
type GPU struct {
	Index     int    `json:"index"`
	Name      string `json:"name"`
	MemoryMiB int    `json:"memory_mib"`
	UUID      string `json:"uuid"`
}

// probeGPUs asks the driver, not the filesystem.
//
// A device-node test would be wrong in both directions: it passes vacuously on
// a native Linux host where /dev/nvidia0 exists for reasons unrelated to a
// working driver, and it fails on every WSL2 node, where the only device is
// /dev/dxg and `nvidia-smi` still reports the card correctly
// (docs/spike-fips-and-manifest.md §5). The driver is the thing that knows.
//
// No GPU is not an error here. A control-plane-only host has none, an operator
// enrolling before installing a driver should be told by preflight (R5) rather
// than by an enrollment that will not complete, and a node with an empty
// inventory is visible as exactly that.
func probeGPUs(ctx context.Context) ([]GPU, string) {
	// **Resolved, not looked up on PATH.** On WSL2 the NVIDIA tools live in
	// /usr/lib/wsl/lib, which the login profile adds to PATH and which sudo's
	// `secure_path` and a systemd unit's PATH both drop. preflight learned this
	// the hard way and this call did not: the agent found no GPU, enrolled
	// advertising an empty offer, and every deployment was refused with "GPU 0
	// is not on this node's offer" — on a host whose own `nodary doctor`
	// reported an RTX 5090, because doctor resolves and this did not.
	out, err := exec.CommandContext(ctx, preflight.Resolve("nvidia-smi"),
		"--query-gpu=index,name,memory.total,uuid,driver_version",
		"--format=csv,noheader,nounits").Output()
	if err != nil {
		return nil, ""
	}
	var gpus []GPU
	var driver string
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		f := strings.Split(line, ",")
		if len(f) < 5 {
			continue
		}
		for i := range f {
			f[i] = strings.TrimSpace(f[i])
		}
		index, err := strconv.Atoi(f[0])
		if err != nil {
			continue
		}
		mem, _ := strconv.Atoi(f[2])
		gpus = append(gpus, GPU{Index: index, Name: f[1], MemoryMiB: mem, UUID: f[3]})
		driver = f[4]
	}
	return gpus, driver
}

// isWSL and RebootPolicy are internal/preflight's, so preflight's check and the
// offer this node makes at enrollment cannot disagree about the same machine.
func isWSL() bool { return preflight.IsWSL() }

// RebootPolicy is what this host reports at enrollment (docs/specs/03-agent.md §7).
func RebootPolicy() string { return preflight.RebootPolicy() }

// CDIDevices are the device names the host's CDI specification declares.
//
// Asked of nvidia-ctk rather than parsed out of /etc/cdi/*.yaml: the toolkit
// owns where those files live and how they compose, and it already answers the
// question in one line. An empty result means it could not be asked, which the
// caller must not read as "no devices" — see gpuFlag.
func CDIDevices(ctx context.Context) []string {
	out, err := exec.CommandContext(ctx, preflight.Resolve("nvidia-ctk"), "cdi", "list").
		CombinedOutput()
	if err != nil {
		return nil
	}
	var names []string
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		// The listing carries a log line first; a device name is the only
		// thing on its line and always carries the vendor prefix.
		if strings.HasPrefix(line, "nvidia.com/") {
			names = append(names, line)
		}
	}
	return names
}
