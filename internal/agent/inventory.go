package agent

import (
	"context"
	"os/exec"
	"strconv"
	"strings"

	"github.com/nodarynet/nodary/internal/preflight"
)

// Vendors, as they are written into an offer.
const (
	// internal/preflight's, so one machine cannot be described two ways.
	VendorNVIDIA = preflight.VendorNVIDIA
	VendorAMD    = preflight.VendorAMD
	VendorIntel  = preflight.VendorIntel
)

// GPU is one card, as whichever source could see it reports it.
type GPU struct {
	Index     int    `json:"index"`
	Name      string `json:"name"`
	MemoryMiB int    `json:"memory_mib"`
	UUID      string `json:"uuid"`
	// Vendor decides how the card is reached: CDI and `--gpus` on NVIDIA, a
	// device node on everything else (docs/plans/R6a-a-second-gpu-vendor.md §2).
	// Absent means nvidia — see VendorName.
	Vendor string `json:"vendor,omitempty"`
	// Render is the /dev/dri node this card is reached through, on the vendors
	// that are reached that way.
	//
	// **Never serialized, so never in an offer.** The vendor belongs in the
	// offer because an administrator approves the silicon a deployment may be
	// placed on ([R6a §4](../../docs/plans/R6a-a-second-gpu-vendor.md)); a
	// device path is not a thing to approve, it is a fact about this boot of
	// this machine. Putting it in the offer would freeze it there —
	// docs/specs/02-enrollment.md §3 gates restating an offer behind
	// certificate expiry — so a card that moved would be reached at the path it
	// had a year ago. The node reads its own sysfs each reconcile instead,
	// which is exactly what CDIDevices already does for NVIDIA.
	Render string `json:"-"`
}

// VendorName is the vendor an offer names, with the default that keeps an
// already-enrolled fleet working.
//
// **An absent vendor is nvidia, not unknown.** docs/specs/02-enrollment.md §3
// gates restating an offer behind certificate expiry, so every node enrolled
// before this field existed keeps the offer it made, forever, with no vendor in
// it. Reading that as "unknown" would strand a working fleet on the release
// that added the field; reading it as nvidia says what was true when they
// enrolled, because nvidia was the only thing this build could enumerate.
func (g GPU) VendorName() string {
	if g.Vendor == "" {
		return VendorNVIDIA
	}
	return g.Vendor
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
		gpus = append(gpus, GPU{Index: index, Name: f[1], MemoryMiB: mem, UUID: f[3],
			Vendor: VendorNVIDIA})
		driver = f[4]
	}
	return gpus, driver
}

// probeDRM enumerates the cards nvidia-smi cannot see, numbering them after it.
//
// The enumeration itself is internal/preflight's (DRMCards), so preflight's own
// GPU checks and the offer this node makes cannot disagree about which cards a
// machine has or whose they are — the same reason isWSL and RebootPolicy are
// borrowed rather than reimplemented. What stays here is the numbering, which
// is an agent concern: the index is the one handle a node has on a card.
func probeDRM(from int) []GPU {
	var gpus []GPU
	for i, c := range preflight.DRMCards() {
		gpus = append(gpus, GPU{
			Index: from + i, Vendor: c.Vendor, Name: c.Name, MemoryMiB: c.MemoryMiB,
			Render: c.Render,
		})
	}
	return gpus
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
