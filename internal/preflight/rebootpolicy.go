package preflight

import (
	"os"
	"path/filepath"
	"strings"
)

// How this host comes back from a restart, which docs/specs/03-agent.md §7
// stores as `reboot_policy` and nothing in this package ever acts on: nodary
// initiates no restart under any of these (R4-25), so the value records what an
// operator would have to do rather than granting anybody permission.
//
// **The safe answer is the one given whenever the question cannot be answered.**
// `unattended` is claimed only where the root filesystem is positively
// established as coming back without a person; anything unreadable, unresolvable
// or merely unfamiliar is `manual-console`. Getting that backwards tells an
// operator a machine in a locked rack will come back, and it does not.
//
// Before this, every host that was not WSL2 was `manual-console` — the safe
// default, and a false alarm on every ordinary server, which is how a warning
// stops being read.
const (
	PolicyManualConsole = "manual-console"
	PolicyHostManaged   = "host-managed"
	PolicyUnattended    = "unattended"
)

// hostFS is the tree the detection reads. Empty is the running host; a test
// points it at a directory holding the same three files.
type hostFS struct{ root string }

func (h hostFS) path(p string) string {
	if h.root == "" {
		return p
	}
	return filepath.Join(h.root, p)
}

// RebootPolicy is which kind of machine this is.
//
// It lives here rather than in internal/agent because docs/specs/03-agent.md §7
// makes this preflight's detection and the agent's report of it, and both need
// the same answer. They had two: this, and a check here that read /etc/crypttab
// alone — which never looked at the root device at all, so an encrypted data
// disk beside a plain root read as `manual-console`, and an encrypted root
// whose unlock is configured only in the initramfs read as `unattended`. The
// second is the direction that strands a machine. internal/agent imports this
// package already, which is why the code moved this way and not the other.
func RebootPolicy() string { return rebootPolicy(hostFS{}) }

func rebootPolicy(h hostFS) string {
	// WSL2 first, and not because it is cheaper: a restart inside the
	// distribution does not restart the Windows host at all, so what the root
	// filesystem is encrypted with never comes into it. The host's lifecycle is
	// not nodary's to drive.
	if isWSLIn(h) {
		return PolicyHostManaged
	}
	crypts, ok := rootCryptNames(h)
	switch {
	case !ok:
		// The root device could not be resolved. That is a machine this build
		// does not understand, not a machine that is fine.
		return PolicyManualConsole
	case len(crypts) == 0:
		return PolicyUnattended
	case unlocksWithoutAPerson(h, crypts):
		return PolicyUnattended
	}
	return PolicyManualConsole
}

// rootCryptNames returns the device-mapper names of every dm-crypt layer under
// the root filesystem, and whether the root device was resolved at all.
//
// **By device number, not by the path in /proc/mounts.** That path is
// `/dev/mapper/vg-root` on one host and `/dev/dm-0` on the next and a
// `/dev/disk/by-uuid/...` symlink on a third; `/proc/self/mountinfo` carries
// the major:minor directly, and /sys/dev/block is indexed by exactly that.
//
// **The stack is walked, not sampled.** LVM-on-LUKS is the ordinary encrypted
// install — root is an LVM volume whose physical volume sits on a crypt device —
// so looking only at the device mounted on / finds `LVM-…` and concludes the
// disk is in the clear. The crypt layer is one or more `slaves` further down.
func rootCryptNames(h hostFS) ([]string, bool) {
	devno, ok := rootDeviceNumber(h)
	if !ok {
		return nil, false
	}
	start := h.path("/sys/dev/block/" + devno)
	if _, err := os.Stat(start); err != nil {
		return nil, false
	}

	var crypts []string
	seen := map[string]bool{}
	queue := []string{start}
	// Bounded: a slaves graph is a handful of nodes, and a cycle in sysfs would
	// otherwise hang the agent's first heartbeat.
	for i := 0; i < 64 && len(queue) > 0; i++ {
		dir := queue[0]
		queue = queue[1:]
		if seen[dir] {
			continue
		}
		seen[dir] = true

		if uuid, err := os.ReadFile(filepath.Join(dir, "dm", "uuid")); err == nil {
			if strings.HasPrefix(strings.TrimSpace(string(uuid)), "CRYPT-") {
				if name, err := os.ReadFile(filepath.Join(dir, "dm", "name")); err == nil {
					crypts = append(crypts, strings.TrimSpace(string(name)))
				}
			}
		}
		entries, err := os.ReadDir(filepath.Join(dir, "slaves"))
		if err != nil {
			continue
		}
		for _, e := range entries {
			queue = append(queue, h.path("/sys/class/block/"+e.Name()))
		}
	}
	return crypts, true
}

// rootDeviceNumber reads the major:minor of whatever is mounted on /.
func rootDeviceNumber(h hostFS) (string, bool) {
	b, err := os.ReadFile(h.path("/proc/self/mountinfo"))
	if err != nil {
		return "", false
	}
	for _, line := range strings.Split(string(b), "\n") {
		// 36 25 253:0 / / rw,relatime - ext4 /dev/mapper/vg-root rw
		f := strings.Fields(line)
		if len(f) < 5 || f[4] != "/" {
			continue
		}
		if _, _, found := strings.Cut(f[2], ":"); !found {
			continue
		}
		return f[2], true
	}
	return "", false
}

// unlocksWithoutAPerson reports whether every crypt layer under the root has a
// key source that needs nobody present.
//
// **Every one, not any.** A host with a TPM-sealed root and a second encrypted
// volume that prompts still stops at a prompt, and answering `unattended`
// because one of the two is automatic is the wrong half to report.
//
// The two signals are read out of /etc/crypttab and are deliberately narrow: a
// third field naming a key file, and `tpm2-device=` in the options. A key
// source this build does not recognise is a key source this build cannot
// promise anything about, so it reads as needing a person — which is the
// direction that cannot strand a machine.
func unlocksWithoutAPerson(h hostFS, crypts []string) bool {
	b, err := os.ReadFile(h.path("/etc/crypttab"))
	if err != nil {
		return false
	}
	automatic := map[string]bool{}
	for _, line := range strings.Split(string(b), "\n") {
		if line = strings.TrimSpace(line); line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		key := ""
		if len(f) >= 3 {
			key = f[2]
		}
		opts := ""
		if len(f) >= 4 {
			opts = f[3]
		}
		// "none" and "-" are crypttab's spellings of "ask at the console".
		byKeyFile := key != "" && key != "none" && key != "-"
		byTPM := strings.Contains(opts, "tpm2-device=")
		if byKeyFile || byTPM {
			automatic[f[0]] = true
		}
	}
	for _, name := range crypts {
		if !automatic[name] {
			return false
		}
	}
	return true
}

// isWSLIn is isWSL read through the tree being described.
//
// The environment variable is a property of *this process*, so it answers for
// the running host and says nothing about a tree a test points at — which is
// why it is consulted only there. /proc/sys/kernel/osrelease is the machine's
// own answer and is read either way.
func isWSLIn(h hostFS) bool {
	if h.root == "" && os.Getenv("WSL_DISTRO_NAME") != "" {
		return true
	}
	b, err := os.ReadFile(h.path("/proc/sys/kernel/osrelease"))
	return err == nil && strings.Contains(strings.ToLower(string(b)), "microsoft")
}
