// Package preflight is the host checks of docs/specs/01-install.md §11 and the
// diagnostic of docs/specs/10-cli.md §3.
//
// One mechanism seen at two times. Preflight runs what can be answered before
// anything is installed; `doctor` runs those and the ones that need a running
// system. Building them separately would produce two answers to "is the driver
// new enough", and which one an operator got would depend on the verb they
// happened to type.
//
// Two rules govern everything here.
//
// **Every check runs.** 01 §11 opens by requiring that a misconfigured host
// surfaces every problem at once rather than one per run, which is a constraint
// on the control flow and not on the output: an implementation that returned
// early would satisfy the format and miss the point.
//
// **A check that cannot run is not a check that passed.** Where the evidence is
// unreachable — nvidia-smi absent, /proc unreadable — the result says so at its
// own level and never `ok`. Most checks here establish a property by *not*
// finding a problem, which is the shape that quietly stops meaning anything;
// docs/plans/R4d-egress-isolation.md records what that cost when it was learned.
package preflight

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Level is how much a result matters.
type Level string

const (
	// LevelOK is a check that found what it needed.
	LevelOK Level = "ok"
	// LevelWarn does not block an install: 01 §11's "warnings, not failures".
	LevelWarn Level = "warn"
	// LevelFail blocks.
	LevelFail Level = "fail"
	// LevelSkip is a check that does not apply to this role or platform. It is
	// distinct from ok, because "not asked" and "asked and fine" are different
	// things for somebody reading the list.
	LevelSkip Level = "skip"
)

// Check is one line of the report.
type Check struct {
	Name   string `json:"name"`
	Level  Level  `json:"level"`
	Detail string `json:"detail"`
}

// Report is the whole list.
type Report struct {
	Checks []Check `json:"checks"`
}

// OK reports whether anything blocks. Warnings do not.
func (r Report) OK() bool {
	for _, c := range r.Checks {
		if c.Level == LevelFail {
			return false
		}
	}
	return true
}

// Failures are the blocking results, for a caller that wants to print only
// those.
func (r Report) Failures() []Check {
	var out []Check
	for _, c := range r.Checks {
		if c.Level == LevelFail {
			out = append(out, c)
		}
	}
	return out
}

// Role is which half of the product is being installed.
type Role string

const (
	RoleServer Role = "server"
	RoleNode   Role = "node"
)

// Options are what the checks need to know.
type Options struct {
	Role Role
	// ModelsDir and DataDir are checked for free space.
	ModelsDir string
	DataDir   string
	// Ports that must be free (server role).
	Ports []int
	// MinModelsGB and MinDataGB are the floors. Zero uses the defaults below.
	MinModelsGB int
	MinDataGB   int
	// MinDriver is the NVIDIA driver floor, as a major version.
	MinDriver int
	// Now is the clock, so a test can hold it still.
	Now func() time.Time
	// run executes a command. Injected so a test can drive a host that does not
	// have nvidia-smi, or one that does when this one does not.
	run func(ctx context.Context, name string, args ...string) ([]byte, error)
}

// Defaults. The disk floors are what one model and one component set
// realistically need rather than round numbers: a 30B model in fp16 is about
// 60 GB, and the pinned runtime is a little over 100 MB.
const (
	defaultMinModelsGB = 80
	defaultMinDataGB   = 2
	// 525 is the floor for CUDA 12, which every backend image this build knows
	// about is built against.
	defaultMinDriver = 525
)

func (o *Options) setDefaults() {
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.run == nil {
		o.run = func(ctx context.Context, name string, args ...string) ([]byte, error) {
			return exec.CommandContext(ctx, Resolve(name), args...).Output()
		}
	}
	if o.MinModelsGB == 0 {
		o.MinModelsGB = defaultMinModelsGB
	}
	if o.MinDataGB == 0 {
		o.MinDataGB = defaultMinDataGB
	}
	if o.MinDriver == 0 {
		o.MinDriver = defaultMinDriver
	}
}

// Run performs every check that applies and returns them all.
//
// Nothing here returns early. That is the requirement, not a style choice.
func Run(ctx context.Context, o Options) Report {
	o.setDefaults()
	var r Report
	add := func(c Check) { r.Checks = append(r.Checks, c) }

	add(checkPlatform())
	add(checkSystemd(ctx, o))
	add(checkCgroupV2())
	add(checkDriver(ctx, o))
	add(checkGPUs(ctx, o))
	add(checkDisk("disk: models", o.ModelsDir, o.MinModelsGB))
	add(checkDisk("disk: components", o.DataDir, o.MinDataGB))
	add(checkPorts(o))
	add(checkIPTables(o))
	add(checkContainerToolkit(o))

	// Warnings. 01 §11: these do not block.
	add(checkSwap())
	add(checkLSM(ctx, o))
	add(checkRAMPerGPU(ctx, o))
	add(checkEncryptedRoot())
	add(checkNFT(o))

	sort.SliceStable(r.Checks, func(i, j int) bool {
		return levelRank(r.Checks[i].Level) < levelRank(r.Checks[j].Level)
	})
	return r
}

// levelRank puts failures first, so the thing that blocks is the thing an
// operator reads before scrolling.
func levelRank(l Level) int {
	switch l {
	case LevelFail:
		return 0
	case LevelWarn:
		return 1
	case LevelOK:
		return 2
	}
	return 3
}

func checkPlatform() Check {
	c := Check{Name: "platform"}
	if runtime.GOOS != "linux" {
		// docs/specs/01-install.md §8: the server and the agent require systemd
		// and cgroup v2, so they are Linux-only. macOS builds exist for the
		// operator CLI, which does not run this.
		c.Level = LevelFail
		c.Detail = runtime.GOOS + " cannot run the server or the agent; both need systemd and cgroup v2"
		return c
	}
	switch runtime.GOARCH {
	case "amd64", "arm64":
		c.Level, c.Detail = LevelOK, runtime.GOOS+"/"+runtime.GOARCH
	default:
		c.Level = LevelFail
		c.Detail = runtime.GOARCH + " is not a supported architecture"
	}
	return c
}

func checkSystemd(ctx context.Context, o Options) Check {
	c := Check{Name: "systemd"}
	out, err := o.run(ctx, "systemctl", "--version")
	if err != nil {
		c.Level = LevelFail
		c.Detail = "systemctl is not usable: " + err.Error()
		if isWSL() {
			// The WSL2 message R5-03 asks for, given for free because the
			// detection already exists: a missing systemctl on WSL2 is almost
			// always this, and "command not found" sends people the wrong way.
			c.Detail += "\n    on WSL2 this is usually systemd=true missing from /etc/wsl.conf; add it and run `wsl --shutdown`"
		}
		return c
	}
	c.Level, c.Detail = LevelOK, firstLine(string(out))
	return c
}

// checkCgroupV2 looks for the unified hierarchy.
//
// containerd and systemd resource control need it, and a host on the legacy
// hierarchy fails at the first deployment rather than here.
func checkCgroupV2() Check {
	c := Check{Name: "cgroup v2"}
	if _, err := os.Stat("/sys/fs/cgroup/cgroup.controllers"); err != nil {
		c.Level = LevelFail
		c.Detail = "the unified hierarchy is not mounted; containerd and systemd resource control need it"
		return c
	}
	body, err := os.ReadFile("/sys/fs/cgroup/cgroup.controllers")
	if err != nil {
		c.Level, c.Detail = LevelFail, "cannot read the cgroup controllers: "+err.Error()
		return c
	}
	c.Level, c.Detail = LevelOK, "unified, controllers: "+strings.TrimSpace(string(body))
	return c
}

// checkDriver reads the driver version from nvidia-smi.
//
// From the driver, not from a device node: docs/spike-fips-and-manifest.md §5
// measured that a WSL2 host has no /dev/nvidia* at all and nvidia-smi still
// reports the card correctly, so a filesystem test fails wrongly there and
// passes vacuously elsewhere.
func checkDriver(ctx context.Context, o Options) Check {
	c := Check{Name: "nvidia driver"}
	if o.Role == RoleServer {
		c.Level, c.Detail = LevelSkip, "not required for a control plane"
		return c
	}
	out, err := o.run(ctx, "nvidia-smi", "--query-gpu=driver_version", "--format=csv,noheader")
	if err != nil {
		c.Level = LevelFail
		c.Detail = "nvidia-smi is not usable: " + err.Error()
		return c
	}
	version := firstLine(string(out))
	if version == "" {
		c.Level, c.Detail = LevelFail, "nvidia-smi reported no driver version"
		return c
	}
	major, err := strconv.Atoi(strings.SplitN(version, ".", 2)[0])
	if err != nil {
		// Unparseable is not a pass. The floor is the point of the check.
		c.Level, c.Detail = LevelFail, "cannot read the driver version from "+version
		return c
	}
	if major < o.MinDriver {
		c.Level = LevelFail
		c.Detail = fmt.Sprintf("driver %s is below the %d floor CUDA 12 needs", version, o.MinDriver)
		return c
	}
	c.Level, c.Detail = LevelOK, "driver "+version
	return c
}

func checkGPUs(ctx context.Context, o Options) Check {
	c := Check{Name: "gpus"}
	if o.Role == RoleServer {
		c.Level, c.Detail = LevelSkip, "not required for a control plane"
		return c
	}
	out, err := o.run(ctx, "nvidia-smi", "--query-gpu=index,name", "--format=csv,noheader")
	if err != nil {
		c.Level, c.Detail = LevelFail, "nvidia-smi is not usable: "+err.Error()
		return c
	}
	lines := nonEmptyLines(string(out))
	if len(lines) == 0 {
		c.Level = LevelFail
		c.Detail = "nvidia-smi enumerates no GPUs"
		if isWSL() {
			// The signature R5-03 names: a driver installed *inside* the
			// distribution breaks CUDA passthrough, and nvidia-smi then runs
			// and reports nothing.
			c.Detail += "\n    on WSL2 this is the signature of an NVIDIA driver installed inside the distribution, which breaks passthrough"
		}
		return c
	}
	c.Level = LevelOK
	c.Detail = fmt.Sprintf("%d device(s): %s", len(lines), strings.Join(lines, "; "))
	return c
}

// checkDisk reports free space on the filesystem holding dir.
func checkDisk(name, dir string, minGB int) Check {
	c := Check{Name: name}
	if dir == "" {
		c.Level, c.Detail = LevelSkip, "no directory configured"
		return c
	}
	// The nearest existing ancestor: the directory itself may not exist yet on
	// a fresh host, and the filesystem it would live on is what matters.
	probe := dir
	for {
		if _, err := os.Stat(probe); err == nil {
			break
		}
		parent := probe[:strings.LastIndex(probe, "/")+1]
		if parent == "" || parent == "/" {
			probe = "/"
			break
		}
		probe = strings.TrimSuffix(parent, "/")
		if probe == "" {
			probe = "/"
			break
		}
	}

	var st syscall.Statfs_t
	if err := syscall.Statfs(probe, &st); err != nil {
		c.Level, c.Detail = LevelFail, "cannot measure free space on "+probe+": "+err.Error()
		return c
	}
	freeGB := int(uint64(st.Bavail) * uint64(st.Bsize) / (1 << 30))
	if freeGB < minGB {
		c.Level = LevelFail
		c.Detail = fmt.Sprintf("%s has %d GB free, below the %d GB floor", probe, freeGB, minGB)
		return c
	}
	c.Level, c.Detail = LevelOK, fmt.Sprintf("%s: %d GB free", probe, freeGB)
	return c
}

// checkPorts reports a port already in use.
func checkPorts(o Options) Check {
	c := Check{Name: "ports"}
	if o.Role != RoleServer || len(o.Ports) == 0 {
		c.Level, c.Detail = LevelSkip, "no ports to check"
		return c
	}
	var busy []string
	for _, p := range o.Ports {
		if inUse(p) {
			busy = append(busy, strconv.Itoa(p))
		}
	}
	if len(busy) > 0 {
		c.Level = LevelFail
		c.Detail = "already in use: " + strings.Join(busy, ", ")
		return c
	}
	c.Level, c.Detail = LevelOK, fmt.Sprintf("%d port(s) free", len(o.Ports))
	return c
}

// --- warnings -----------------------------------------------------------------

func checkSwap() Check {
	c := Check{Name: "swap"}
	body, err := os.ReadFile("/proc/swaps")
	if err != nil {
		c.Level, c.Detail = LevelWarn, "cannot read /proc/swaps: "+err.Error()
		return c
	}
	// The first line is a header; anything after it is a swap device.
	if len(nonEmptyLines(string(body))) <= 1 {
		c.Level = LevelWarn
		c.Detail = "no swap configured; a model server that briefly overcommits will be killed rather than slowed"
		return c
	}
	c.Level, c.Detail = LevelOK, "configured"
	return c
}

// checkLSM reports SELinux or AppArmor enforcing.
//
// A warning and not a failure: both can be configured to permit what nodary
// does, and telling an operator their hardened host is unsupported would be
// both wrong and insulting. It is worth saying because a container that will
// not start is otherwise a long afternoon.
func checkLSM(ctx context.Context, o Options) Check {
	c := Check{Name: "lsm"}
	if out, err := o.run(ctx, "getenforce"); err == nil {
		if strings.EqualFold(firstLine(string(out)), "Enforcing") {
			c.Level = LevelWarn
			c.Detail = "SELinux is enforcing; containerd and the isolated network may need policy"
			return c
		}
	}
	if body, err := os.ReadFile("/sys/kernel/security/apparmor/profiles"); err == nil {
		if strings.Contains(string(body), "(enforce)") {
			c.Level = LevelWarn
			c.Detail = "AppArmor has enforcing profiles; containerd may need one"
			return c
		}
	}
	c.Level, c.Detail = LevelOK, "no enforcing LSM detected"
	return c
}

// checkRAMPerGPU warns when host memory is thin for the cards present.
//
// Weights are loaded through host memory, and a host with less RAM than VRAM
// swaps or is killed partway through loading a model — which looks like a
// backend crash and is not.
func checkRAMPerGPU(ctx context.Context, o Options) Check {
	c := Check{Name: "ram per gpu"}
	if o.Role == RoleServer {
		c.Level, c.Detail = LevelSkip, "not required for a control plane"
		return c
	}
	out, err := o.run(ctx, "nvidia-smi", "--query-gpu=memory.total", "--format=csv,noheader,nounits")
	if err != nil {
		c.Level, c.Detail = LevelWarn, "cannot enumerate GPUs to compare"
		return c
	}
	gpus := nonEmptyLines(string(out))
	if len(gpus) == 0 {
		c.Level, c.Detail = LevelWarn, "no GPUs to compare against"
		return c
	}
	var vramMiB int
	for _, g := range gpus {
		n, err := strconv.Atoi(strings.TrimSpace(g))
		if err != nil {
			c.Level, c.Detail = LevelWarn, "cannot read GPU memory"
			return c
		}
		vramMiB += n
	}
	ramMiB, err := totalRAMMiB()
	if err != nil {
		c.Level, c.Detail = LevelWarn, err.Error()
		return c
	}
	if ramMiB < vramMiB {
		c.Level = LevelWarn
		c.Detail = fmt.Sprintf("%d MiB RAM against %d MiB VRAM; loading weights may be killed partway",
			ramMiB, vramMiB)
		return c
	}
	c.Level = LevelOK
	c.Detail = fmt.Sprintf("%d MiB RAM, %d MiB VRAM across %d device(s)", ramMiB, vramMiB, len(gpus))
	return c
}

// checkEncryptedRoot warns about a host that needs a human at the console.
//
// docs/specs/03-agent.md §7: a host whose root is encrypted with no automatic
// unlock path needs somebody physically present to come back up, and the agent
// refuses to initiate a reboot on one. This is where an operator finds out
// before that matters rather than after.
func checkEncryptedRoot() Check {
	c := Check{Name: "reboot policy"}
	body, err := os.ReadFile("/etc/crypttab")
	if err != nil || len(nonComment(string(body))) == 0 {
		if isWSL() {
			c.Level = LevelWarn
			c.Detail = "host-managed: `reboot` inside WSL2 does not restart the Windows host, and its lifecycle is not nodary's to drive"
			return c
		}
		c.Level, c.Detail = LevelOK, "unattended: no encrypted root"
		return c
	}
	// A keyfile or an unlock hook means it can come back on its own.
	for _, line := range nonComment(string(body)) {
		fields := strings.Fields(line)
		if len(fields) >= 3 && fields[2] != "none" && fields[2] != "-" {
			c.Level, c.Detail = LevelOK, "unattended: encrypted root with a keyfile"
			return c
		}
	}
	c.Level = LevelWarn
	c.Detail = "manual-console: encrypted root with no automatic unlock; this host needs somebody at the console to reboot"
	return c
}

// --- helpers ------------------------------------------------------------------

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return strings.TrimSpace(s[:i])
	}
	return strings.TrimSpace(s)
}

func nonEmptyLines(s string) []string {
	var out []string
	for _, l := range strings.Split(s, "\n") {
		if l = strings.TrimSpace(l); l != "" {
			out = append(out, l)
		}
	}
	return out
}

func nonComment(s string) []string {
	var out []string
	for _, l := range nonEmptyLines(s) {
		if !strings.HasPrefix(l, "#") {
			out = append(out, l)
		}
	}
	return out
}

func totalRAMMiB() (int, error) {
	body, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0, fmt.Errorf("cannot read /proc/meminfo: %w", err)
	}
	for _, line := range nonEmptyLines(string(body)) {
		if !strings.HasPrefix(line, "MemTotal:") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			break
		}
		kb, err := strconv.Atoi(fields[1])
		if err != nil {
			break
		}
		return kb / 1024, nil
	}
	return 0, fmt.Errorf("cannot read MemTotal from /proc/meminfo")
}

// toolDirs are where a tool may live when it is not on PATH.
//
// **/usr/lib/wsl/lib is why this function exists.** On WSL2 the NVIDIA tools are
// bind-mounted there and put on PATH by the login profile — which `sudo` then
// drops, because its `secure_path` is a fixed list that does not include it. So
// `nvidia-smi` resolves for the operator and not for root, and every check that
// needs it fails on a host with a perfectly good GPU.
//
// That is not a corner case: the agent runs as root, `node install` runs under
// sudo, and WSL2 is a platform docs/specs/01-install.md §8 supports. Found by
// running the privileged verification on a real WSL2 host with an RTX 5090
// attached, where preflight reported no driver at all.
var toolDirs = []string{
	"/usr/lib/wsl/lib", // WSL2's GPU tools; see above
	"/usr/bin",
	"/usr/local/bin",
	"/usr/sbin",
	"/usr/local/nvidia/bin",
	"/opt/nvidia/bin",
}

// Resolve finds a tool by name, falling back to the known locations when PATH
// does not have it.
//
// It returns the bare name when nothing is found, so the caller still gets the
// ordinary "executable file not found in $PATH" rather than a confusing one.
func Resolve(name string) string {
	if p, err := exec.LookPath(name); err == nil {
		return p
	}
	for _, dir := range toolDirs {
		candidate := dir + "/" + name
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() && info.Mode()&0o111 != 0 {
			return candidate
		}
	}
	return name
}

// isWSL is the same detection internal/agent uses for reboot_policy.
func isWSL() bool {
	if os.Getenv("WSL_DISTRO_NAME") != "" {
		return true
	}
	b, err := os.ReadFile("/proc/sys/kernel/osrelease")
	return err == nil && strings.Contains(strings.ToLower(string(b)), "microsoft")
}

// inUse reports whether a TCP port on loopback already has a listener.
func inUse(port int) bool {
	ln, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		return true
	}
	ln.Close()
	return false
}

// found reports whether Resolve located a real executable.
//
// Resolve returns the bare name when it finds nothing, so that a caller who
// goes on to exec it gets the ordinary "not found in $PATH". Here the question
// is the opposite one, and an absolute path is the answer.
func found(path string) bool { return strings.HasPrefix(path, "/") }

// checkIPTables is a node-role hard failure, and it took a privileged run on a
// real host to find it.
//
// The isolated network's second plugin is `portmap`, which is what puts a
// deployment's port on 127.0.0.1 (internal/agent/network.go). portmap is
// implemented entirely in terms of the `iptables` command. On a host without
// it, CNI attach fails *after* the container is created, so the container is
// torn down immediately and the only trace in containerd's journal is a shim
// that connected and disconnected 300ms later — a symptom that names nothing.
//
// So a GPU host with no iptables can run no deployment at all, and until this
// check nothing said so. Measured on a WSL2 host that has neither iptables nor
// nft, where `nerdctl run --network nodary-isolated -p …` failed exactly this
// way.
func checkIPTables(o Options) Check {
	c := Check{Name: "iptables"}
	if o.Role == RoleServer {
		c.Level, c.Detail = LevelSkip, "not required for a control plane"
		return c
	}
	if path := Resolve("iptables"); found(path) {
		c.Level, c.Detail = LevelOK, path
		return c
	}
	c.Level = LevelFail
	c.Detail = "not found; the CNI portmap plugin is pure iptables, " +
		"so no deployment could publish its port. `apt install iptables`"
	return c
}

// checkNFT is a warning, because what it enables is defence in depth.
//
// nodary adds one nftables rule that drops forwarded traffic from the isolated
// subnet. The control that actually isolates a deployment is the absence of a
// route and a gateway, and that holds whether or not the rule is there — which
// is why EnsureIsolatedNetwork writes the CNI configuration before it reaches
// for nft, and why a host without nft still gets an isolated network.
//
// Worth saying, not worth blocking.
func checkNFT(o Options) Check {
	c := Check{Name: "nftables"}
	if o.Role == RoleServer {
		c.Level, c.Detail = LevelSkip, "not required for a control plane"
		return c
	}
	if path := Resolve("nft"); found(path) {
		c.Level, c.Detail = LevelOK, path
		return c
	}
	c.Level = LevelWarn
	c.Detail = "not found; the isolated network's drop rule cannot be added. " +
		"The missing route still isolates a deployment. `apt install nftables`"
	return c
}

// checkContainerToolkit is what lets a container see a GPU at all.
//
// `nodary-model@.service` runs `nerdctl run --gpus …`, and nerdctl resolves that
// through the NVIDIA Container Toolkit — in 2.x by way of a CDI spec that
// `nvidia-ctk cdi generate` writes. Without the toolkit the flag resolves to
// nothing and every deployment starts a container with no device, which surfaces
// as a model server that cannot find CUDA rather than as anything naming the
// toolkit.
//
// **nodary does not install it**, which is the call docs/specs/01-install.md §8
// already makes for the packet filter. Upstream publishes the toolkit only as
// distribution packages — the release assets are a tarball *of `.deb`s and
// `.rpm`s*, not the flat binary archive containerd, runc and nerdctl ship — and
// one of them is a shared library needing a loader path. Unpacking that by hand
// would be nodary reimplementing dpkg. It is also coupled to the driver, which
// 01 §8 already refuses to touch on WSL2 because installing one there breaks the
// passthrough.
//
// So the host provides it, and preflight says so before anything is installed
// rather than after a deployment has failed for a reason naming something else.
func checkContainerToolkit(o Options) Check {
	c := Check{Name: "container toolkit"}
	if o.Role == RoleServer {
		c.Level, c.Detail = LevelSkip, "not required for a control plane"
		return c
	}
	if path := Resolve("nvidia-ctk"); found(path) {
		c.Level, c.Detail = LevelOK, path
		return c
	}
	// The older entry point, for a host carrying libnvidia-container-tools and
	// not the newer package. Reported ok with the name, because what matters is
	// whether a GPU can reach a container, not which generation did it.
	if path := Resolve("nvidia-container-cli"); found(path) {
		c.Level, c.Detail = LevelOK, path+" (no nvidia-ctk; CDI generation unavailable)"
		return c
	}
	c.Level = LevelFail
	c.Detail = "not found; `nerdctl --gpus` cannot pass a GPU into a container without the " +
		"NVIDIA Container Toolkit, and every deployment would start with no device"
	return c
}
