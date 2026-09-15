package preflight

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
)

// Vendor names a GPU vendor. Shared with internal/agent, which imports this
// package for the same reason RebootPolicy lives here: preflight's check and
// the offer a node makes at enrollment must not disagree about one machine.
const (
	VendorNVIDIA = "nvidia"
	VendorAMD    = "amd"
	VendorIntel  = "intel"
)

// DRMRoot is where the kernel exposes cards no vendor tool has to be installed
// to see. A variable so a test can point it at a fixture — exported because
// internal/agent's tests build that fixture too, for the numbering it layers on
// top of this enumeration.
var DRMRoot = "/sys/class/drm"

// pciVendors are the PCI vendor ids this build knows how to enumerate from
// sysfs. NVIDIA (0x10de) is deliberately absent: the driver query answers for
// it, and it is the only thing that answers on WSL2 — a card counted from both
// sources would be enumerated twice.
var pciVendors = map[string]string{"0x1002": VendorAMD, "0x8086": VendorIntel}

// DRMCard is one card the kernel exposes, whatever tooling is installed.
type DRMCard struct {
	Vendor string
	Name   string
	// MemoryMiB is 0 when the driver publishes no total. i915 does not.
	MemoryMiB int
	// Render is the /dev/dri node a container is handed to reach this card,
	// empty when the driver exposes none (a display-only device, and nothing
	// to run a model on).
	//
	// **Read rather than derived.** `renderD(128+index)` is the tempting
	// arithmetic and it is a guess: the numbering is dense only when every DRM
	// device in the machine is a render-capable GPU, and a card with no render
	// node at all shifts every card after it. The kernel already publishes the
	// pairing under the card's own device directory, so the answer costs one
	// glob and cannot be off by one.
	Render string
}

// DRMCards enumerates the cards a vendor tool is not needed to see.
//
// **Second, never instead.** /sys/class/drm holds no cards at all on WSL2 — the
// only device there is /dev/dxg — so a sysfs enumerator that replaced a driver
// query would report nothing on the one platform this fleet has been proved
// against (docs/plans/R6a-a-second-gpu-vendor.md §1). It answers what a driver
// query structurally cannot, and nothing else.
//
// rocm-smi is not asked either: it ships with ROCm, and a node serving Vulkan
// need not have ROCm installed at all.
func DRMCards() []DRMCard {
	cards, err := filepath.Glob(filepath.Join(DRMRoot, "card[0-9]*"))
	if err != nil {
		return nil
	}
	slices.Sort(cards)
	var out []DRMCard
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
		c := DRMCard{Vendor: vendor, Name: sysfsField(dev, "product_name")}
		if c.Name == "" {
			// amdgpu publishes product_name and i915 does not, and a card with
			// no model string is still a card. The PCI device id is what the
			// kernel does know and is enough to look the part number up.
			c.Name = strings.ToUpper(vendor) + " " + sysfsField(dev, "device")
		}
		// Bytes here, unlike nvidia-smi's MiB.
		if b, err := strconv.ParseInt(sysfsField(dev, "mem_info_vram_total"), 10, 64); err == nil {
			c.MemoryMiB = int(b / (1 << 20))
		}
		// /sys/class/drm/card1/device/drm/ holds this card's own nodes —
		// card1 and renderD129 — which is the kernel stating the pairing that
		// arithmetic on the index only assumes.
		if nodes, err := filepath.Glob(filepath.Join(dev, "drm", "renderD*")); err == nil && len(nodes) > 0 {
			slices.Sort(nodes)
			c.Render = filepath.Join("/dev/dri", filepath.Base(nodes[0]))
		}
		out = append(out, c)
	}
	return out
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

// nvidiaAnswers reports whether this host's NVIDIA driver is usable.
//
// The question every GPU check has to ask first, because the answer decides
// whether a failing NVIDIA check is a broken node or simply a node that is not
// NVIDIA (docs/plans/R6a-a-second-gpu-vendor.md §5). Asked once per check
// rather than cached: preflight runs a handful of times, and a cached "no"
// would outlive a driver an operator installed while reading the output.
func nvidiaAnswers(ctx context.Context, o Options) bool {
	// **Defaulted here rather than assumed.** setDefaults runs inside Run, so a
	// check called directly — which every check test does — arrives with a nil
	// runner. checkContainerToolkit shelled out to nothing before this change
	// and so never noticed; adding the question turned a zero Options into a
	// nil dereference, which CI found and `make check` on a host with
	// nvidia-ctk installed did not, because the test that would have caught it
	// skips itself there.
	out, err := o.exec(ctx, "nvidia-smi", "--query-gpu=index", "--format=csv,noheader")
	return err == nil && len(nonEmptyLines(string(out))) > 0
}

// exec runs a command, defaulting the runner.
//
// **setDefaults runs inside Run**, so a check invoked directly — which every
// check test does — arrives with a nil `run` and dereferences it. That was true
// of checkDriver and its neighbours long before R4-42; the only reason it never
// showed is that nothing called them outside Run until a test did.
func (o Options) exec(ctx context.Context, name string, args ...string) ([]byte, error) {
	run := o.run
	if run == nil {
		run = execRun
	}
	return run(ctx, name, args...)
}

// execRun is the real runner, and the default for an Options that names none.
func execRun(ctx context.Context, name string, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, Resolve(name), args...).Output()
}

// otherVendor is the vendor of the cards this host has that NVIDIA's driver
// does not answer for, or empty if there are none.
func otherVendor() string {
	cards := DRMCards()
	if len(cards) == 0 {
		return ""
	}
	return cards[0].Vendor
}

// notNVIDIA is the verdict an NVIDIA-specific check reaches on a host that has
// GPUs of another vendor.
//
// **Skip and not fail.** A check that fails on every AMD host is a check that
// teaches operators to ignore preflight, and two of these are hard failures for
// a node — so an AMD host would be refused enrollment for the absence of a
// driver it is not supposed to have. What a node still needs is named in the
// detail rather than implied by a green tick, because nodary cannot yet *run*
// anything on those cards (R6-13, R6-14).
func notNVIDIA(c *Check, vendor, what string) {
	c.Level = LevelSkip
	c.Detail = fmt.Sprintf("this host's GPUs are %s, which %s does not apply to; "+
		"nodary cannot place a deployment on them yet (R6-13, R6-14)", vendor, what)
}
