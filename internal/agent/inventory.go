package agent

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/nodarynet/nodary/internal/preflight"
)

// Vendors, as they are written into an offer.
const (
	VendorNVIDIA = "nvidia"
	VendorAMD    = "amd"
	VendorIntel  = "intel"
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

// drmRoot is where the kernel exposes cards no vendor tool has to be installed
// to see. A variable so a test can point it at a fixture.
var drmRoot = "/sys/class/drm"

// pciVendors are the PCI vendor ids this build knows how to enumerate from
// sysfs. NVIDIA (0x10de) is deliberately absent: probeGPUs already asked its
// driver, which is the only thing that answers on WSL2, and a card counted from
// both sources would be offered twice.
var pciVendors = map[string]string{"0x1002": VendorAMD, "0x8086": VendorIntel}

// probeDRM enumerates the cards nvidia-smi cannot see, numbering them after it.
//
// **Second, never instead.** /sys/class/drm holds no cards at all on WSL2 — the
// only device there is /dev/dxg — so a sysfs enumerator that replaced the
// driver query would report an empty offer on the one platform this fleet has
// been proved against (docs/plans/R6a-a-second-gpu-vendor.md §1). It is asked
// for what the driver query structurally cannot answer, and nothing else.
//
// rocm-smi is not asked either: it ships with ROCm, and a node serving Vulkan
// need not have ROCm installed at all.
func probeDRM(from int) []GPU {
	cards, err := filepath.Glob(filepath.Join(drmRoot, "card[0-9]*"))
	if err != nil {
		return nil
	}
	slices.Sort(cards)
	var gpus []GPU
	for _, card := range cards {
		// card0-DP-1 and friends are connectors on a card, not cards. They sit
		// in the same directory and match the same glob.
		if strings.Contains(filepath.Base(card), "-") {
			continue
		}
		dev := filepath.Join(card, "device")
		vendor, known := pciVendors[sysfsField(dev, "vendor")]
		if !known {
			continue
		}
		g := GPU{Index: from + len(gpus), Vendor: vendor, Name: sysfsField(dev, "product_name")}
		if g.Name == "" {
			// amdgpu publishes product_name and i915 does not, and a card with
			// no model string is still a card. The PCI device id is what the
			// kernel does know and is enough to look the part number up.
			g.Name = strings.ToUpper(vendor) + " " + sysfsField(dev, "device")
		}
		// Bytes here, unlike nvidia-smi's MiB.
		if b, err := strconv.ParseInt(sysfsField(dev, "mem_info_vram_total"), 10, 64); err == nil {
			g.MemoryMiB = int(b / (1 << 20))
		}
		gpus = append(gpus, g)
	}
	return gpus
}

// sysfsField reads one attribute, trimmed. Absent reads as empty: these files
// differ by driver and by kernel version, and a missing one is a fact about
// this card rather than an error about this host.
func sysfsField(dir, name string) string {
	b, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
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
