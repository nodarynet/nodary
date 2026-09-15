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
	// device node on everything else (dev/plans/R6a-a-second-gpu-vendor.md §2).
	// Absent means nvidia — see VendorName.
	Vendor string `json:"vendor,omitempty"`
	// Render is the /dev/dri node this card is reached through, on the vendors
	// that are reached that way.
	//
	// **Never serialized, so never in an offer.** The vendor belongs in the
	// offer because an administrator approves the silicon a deployment may be
	// placed on ([R6a §4](../../dev/plans/R6a-a-second-gpu-vendor.md)); a
	// device path is not a thing to approve, it is a fact about this boot of
	// this machine. Putting it in the offer would freeze it there —
	// dev/specs/02-enrollment.md §3 gates restating an offer behind
	// certificate expiry — so a card that moved would be reached at the path it
	// had a year ago. The node reads its own sysfs each reconcile instead,
	// which is exactly what CDIDevices already does for NVIDIA.
	Render string `json:"-"`
}

// VendorName is the vendor an offer names, with the default that keeps an
// already-enrolled fleet working.
//
// **An absent vendor is nvidia, not unknown.** dev/specs/02-enrollment.md §3
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
// (dev/spike-fips-and-manifest.md §5). The driver is the thing that knows.
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

// RebootPolicy is what this host reports at enrollment (dev/specs/03-agent.md §7).
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

// Topology is how a node's cards are connected to each other, from
// `nvidia-smi topo -m`.
//
// **It is why an index set is sensible or not.** dev/specs/03-agent.md §7 lets
// an operator assign GPUs by index, and two cards on the same NVLink behave
// nothing like two cards that reach each other across the host bridge — the
// second pair will run a tensor-parallel deployment at a fraction of the speed
// for no visible reason. The offer says which cards exist; this says which of
// them belong together.
type Topology struct {
	// Source names the command, because the vocabulary in Matrix is its and
	// not ours: `NV12`, `PHB`, `SYS` mean what nvidia-smi says they mean, and a
	// reader needs to know whose legend to look up.
	Source string `json:"source"`
	// GPUs are the column headings in order — `GPU0`, `GPU1` — so a matrix
	// entry can be read without assuming the rows are dense or in index order.
	GPUs []string `json:"gpus"`
	// Matrix[i][j] is how GPUs[i] reaches GPUs[j]. Square, with the diagonal
	// carrying whatever nvidia-smi puts there (`X`).
	Matrix [][]string `json:"matrix"`
}

// probeTopology reads the connection matrix, or reports nothing.
//
// Nothing is a legitimate answer and not an error: a single-GPU host, a machine
// with no NVIDIA cards, and WSL2 — where `nvidia-smi topo` is not implemented —
// all reach it, and none of them is a fault. The parse is deliberately narrow:
// it takes the columns whose heading begins `GPU` and ignores the affinity
// columns and the legend, so a future release adding a column changes nothing
// here.
func probeTopology(ctx context.Context) Topology {
	out, err := exec.CommandContext(ctx, preflight.Resolve("nvidia-smi"), "topo", "-m").Output()
	if err != nil {
		return Topology{}
	}
	return parseTopology(out)
}

// parseTopology is the matrix reader, apart from the command so that a test
// can hand it what a real host printed.
func parseTopology(out []byte) Topology {
	var t Topology
	var keep []int
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		// The heading is the first line whose own cells are GPU names; it has
		// no row label, so the cells are the columns.
		if t.GPUs == nil {
			if !isCard(fields[0]) || strings.HasPrefix(line, "GPU") {
				continue
			}
			for i, f := range fields {
				if isCard(f) {
					t.GPUs = append(t.GPUs, f)
					keep = append(keep, i)
				}
			}
			continue
		}
		// A row: its label, then one cell per column. The legend that follows
		// the matrix has no row label beginning GPU, so it falls out here.
		if !isCard(fields[0]) || len(t.Matrix) >= len(t.GPUs) {
			continue
		}
		row := make([]string, 0, len(keep))
		for _, i := range keep {
			if i+1 < len(fields) {
				row = append(row, fields[i+1])
			}
		}
		if len(row) == len(t.GPUs) {
			t.Matrix = append(t.Matrix, row)
		}
	}
	if len(t.Matrix) == 0 {
		return Topology{}
	}
	t.Source = "nvidia-smi topo -m"
	return t
}

// isCard is `GPU` and a number, which is the only heading that names a card.
//
// **Not `strings.HasPrefix(f, "GPU")`,** which is what this was and which the
// test caught: the header row ends `GPU NUMA ID`, so a prefix match counted a
// fourth card on a three-card host, every row then failed its length check,
// and the whole matrix was discarded as unparseable. A parser reading a
// human-facing table has to be told what a column *is*, not what it starts
// with.
func isCard(f string) bool {
	rest, ok := strings.CutPrefix(f, "GPU")
	if !ok || rest == "" {
		return false
	}
	return strings.IndexFunc(rest, func(r rune) bool { return r < '0' || r > '9' }) < 0
}
