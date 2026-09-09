package agent

import (
	"context"
	"os"
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

// RebootPolicy is which kind of machine this is.
//
// docs/specs/03-agent.md §7: nodary never initiates a reboot under any of these,
// so this records what an operator would have to do rather than granting
// permission. WSL2 is detected because `reboot` inside the distribution does not
// restart the Windows host, and the host's lifecycle is not nodary's to drive.
//
// `manual-console` is the default and the safe answer. Detecting an encrypted
// root without a network unlock path is R4-24 and preflight's job; until it
// exists, assuming a human is needed is the assumption that cannot strand a
// machine.
func RebootPolicy() string {
	if isWSL() {
		return "host-managed"
	}
	return "manual-console"
}

func isWSL() bool {
	if os.Getenv("WSL_DISTRO_NAME") != "" {
		return true
	}
	b, err := os.ReadFile("/proc/sys/kernel/osrelease")
	return err == nil && strings.Contains(strings.ToLower(string(b)), "microsoft")
}
