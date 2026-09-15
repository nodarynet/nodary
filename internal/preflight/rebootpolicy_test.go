package preflight

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeHostFS builds the three files the detection reads.
//
// Real files rather than an interface: what is being tested is the reading of a
// particular shape of sysfs, and a fake that answered questions directly would
// be testing the questions rather than the answers.
type fakeHostFS struct {
	t    *testing.T
	root string
}

func newFakeHostFS(t *testing.T) *fakeHostFS {
	t.Helper()
	return &fakeHostFS{t: t, root: t.TempDir()}
}

func (f *fakeHostFS) write(path, body string) {
	f.t.Helper()
	full := filepath.Join(f.root, path)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		f.t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(body), 0o644); err != nil {
		f.t.Fatal(err)
	}
}

// rootOn declares what is mounted on /, by device number.
func (f *fakeHostFS) rootOn(devno string) {
	f.write("/proc/self/mountinfo",
		"22 28 0:21 / /proc rw,nosuid - proc proc rw\n"+
			"36 25 "+devno+" / / rw,relatime - ext4 /dev/mapper/root rw\n")
}

// plain declares a block device that is not device-mapper at all: a partition
// or a whole disk. It has a sysfs directory and no dm/ inside it.
func (f *fakeHostFS) plain(kernel string, slaves ...string) {
	f.t.Helper()
	f.write("/sys/class/block/"+kernel+"/uevent", "DEVNAME="+kernel+"\n")
	f.slaves(kernel, slaves...)
}

// mapped declares a device-mapper node.
//
// **The kernel name and the dm name are different strings**, which is the whole
// reason dm/name exists: the node is `dm-0` and the name cryptsetup opened it
// under — the one /etc/crypttab's first field carries — is `cryptroot`. A fake
// that wrote the kernel name into dm/name would make a crypttab lookup appear
// to work by never matching anything.
func (f *fakeHostFS) mapped(kernel, uuid, dmName string, slaves ...string) {
	f.t.Helper()
	f.write("/sys/class/block/"+kernel+"/dm/uuid", uuid+"\n")
	f.write("/sys/class/block/"+kernel+"/dm/name", dmName+"\n")
	f.slaves(kernel, slaves...)
}

func (f *fakeHostFS) slaves(kernel string, slaves ...string) {
	f.t.Helper()
	for _, s := range slaves {
		f.write("/sys/class/block/"+kernel+"/slaves/"+s+"/.keep", "")
	}
}

// at makes /sys/dev/block/<devno> the same directory as a named block device,
// which is what the symlink is on a running host.
func (f *fakeHostFS) at(devno, name string) {
	f.t.Helper()
	if err := os.MkdirAll(filepath.Join(f.root, "/sys/dev/block"), 0o755); err != nil {
		f.t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(f.root, "/sys/class/block/"+name),
		filepath.Join(f.root, "/sys/dev/block/"+devno)); err != nil {
		f.t.Fatal(err)
	}
}

func (f *fakeHostFS) policy() string { return rebootPolicy(hostFS{root: f.root}) }

// An ordinary server comes back on its own, and saying otherwise about every
// one of them is how a warning stops being read.
//
// This is the case the blanket default got wrong: before detection, every host
// that was not WSL2 was reported as needing somebody at a physical console.
func TestAnUnencryptedRootIsUnattended(t *testing.T) {
	f := newFakeHostFS(t)
	f.rootOn("8:2")
	f.plain("sda2") // a plain partition: no dm directory at all
	f.at("8:2", "sda2")

	if got := f.policy(); got != PolicyUnattended {
		t.Errorf("policy = %q, want %q", got, PolicyUnattended)
	}
}

// The encrypted root dev/specs/03-agent.md §7 is about: a person at the
// physical console, in a locked rack, before the machine is back.
func TestAnEncryptedRootThatPromptsNeedsAConsole(t *testing.T) {
	f := newFakeHostFS(t)
	f.rootOn("253:0")
	f.mapped("dm-0", "CRYPT-LUKS2-9f8e7d-cryptroot", "cryptroot", "sda2")
	f.plain("sda2")
	f.at("253:0", "dm-0")
	f.write("/etc/crypttab", "cryptroot UUID=9f8e7d none luks\n")

	if got := f.policy(); got != PolicyManualConsole {
		t.Errorf("policy = %q, want %q", got, PolicyManualConsole)
	}
}

// LVM on LUKS is the ordinary encrypted install, and it is the case a check
// that looked only at the device mounted on / gets wrong: that device is an LVM
// volume, reports `LVM-…`, and the crypt layer is a slave below it.
func TestLVMOnLUKSIsFoundThroughTheStack(t *testing.T) {
	f := newFakeHostFS(t)
	f.rootOn("253:1")
	f.mapped("dm-1", "LVM-abc123", "root", "dm-0")
	f.mapped("dm-0", "CRYPT-LUKS2-9f8e7d-cryptroot", "cryptroot", "nvme0n1p3")
	f.plain("nvme0n1p3")
	f.at("253:1", "dm-1")
	f.write("/etc/crypttab", "cryptroot UUID=9f8e7d none luks\n")

	if got := f.policy(); got != PolicyManualConsole {
		t.Errorf("policy = %q, want %q — the crypt layer under LVM was not found",
			got, PolicyManualConsole)
	}
}

// An encrypted root that unlocks without anybody present is not a machine
// somebody has to drive to.
func TestAnEncryptedRootWithAnAutomaticKeyIsUnattended(t *testing.T) {
	for _, c := range []struct{ what, crypttab string }{
		{"a key file", "cryptroot UUID=9f8e7d /etc/keys/root.key luks\n"},
		{"a TPM", "cryptroot UUID=9f8e7d none luks,tpm2-device=auto\n"},
	} {
		f := newFakeHostFS(t)
		f.rootOn("253:0")
		f.mapped("dm-0", "CRYPT-LUKS2-9f8e7d-cryptroot", "cryptroot", "sda2")
		f.plain("sda2")
		f.at("253:0", "dm-0")
		f.write("/etc/crypttab", c.crypttab)

		if got := f.policy(); got != PolicyUnattended {
			t.Errorf("%s: policy = %q, want %q", c.what, got, PolicyUnattended)
		}
	}
}

// Every crypt layer, not any of them. A host whose root unlocks from a TPM and
// whose second volume prompts still stops at a prompt, and reporting the
// automatic half is reporting the wrong half.
func TestOneLayerThatPromptsIsEnoughToNeedAConsole(t *testing.T) {
	f := newFakeHostFS(t)
	f.rootOn("253:2")
	f.mapped("dm-2", "LVM-abc123", "root", "dm-0", "dm-1")
	f.mapped("dm-0", "CRYPT-LUKS2-aaa-cryptroot", "cryptroot", "sda2")
	f.mapped("dm-1", "CRYPT-LUKS2-bbb-cryptdata", "cryptdata", "sdb1")
	f.plain("sda2")
	f.plain("sdb1")
	f.at("253:2", "dm-2")
	f.write("/etc/crypttab",
		"cryptroot UUID=aaa none luks,tpm2-device=auto\ncryptdata UUID=bbb none luks\n")

	if got := f.policy(); got != PolicyManualConsole {
		t.Errorf("policy = %q, want %q", got, PolicyManualConsole)
	}
}

// A machine this build cannot read is a machine it cannot vouch for. Claiming
// `unattended` on a guess tells an operator a host in a locked rack will come
// back, and it will not.
func TestAHostThatCannotBeReadNeedsAConsole(t *testing.T) {
	for _, c := range []struct {
		what  string
		build func(*fakeHostFS)
	}{
		{"no mountinfo", func(f *fakeHostFS) {}},
		{"a root device sysfs does not have", func(f *fakeHostFS) { f.rootOn("253:9") }},
		{"a mountinfo with no root line", func(f *fakeHostFS) {
			f.write("/proc/self/mountinfo", "22 28 0:21 / /proc rw - proc proc rw\n")
		}},
		{"a crypt root and no crypttab", func(f *fakeHostFS) {
			f.rootOn("253:0")
			f.mapped("dm-0", "CRYPT-LUKS2-9f8e7d-cryptroot", "cryptroot", "sda2")
			f.plain("sda2")
			f.at("253:0", "dm-0")
		}},
	} {
		f := newFakeHostFS(t)
		c.build(f)
		if got := f.policy(); got != PolicyManualConsole {
			t.Errorf("%s: policy = %q, want %q", c.what, got, PolicyManualConsole)
		}
	}
}

// A cycle in the slaves graph must not hang the agent's first heartbeat.
func TestTheDeviceWalkTerminates(t *testing.T) {
	f := newFakeHostFS(t)
	f.rootOn("253:0")
	f.mapped("dm-0", "LVM-a", "a", "dm-1")
	f.mapped("dm-1", "LVM-b", "b", "dm-0")
	f.at("253:0", "dm-0")

	if got := f.policy(); got != PolicyUnattended {
		t.Errorf("policy = %q, want %q", got, PolicyUnattended)
	}
}

// preflight's check and the value the node puts in its offer are one answer.
//
// They were two, and the one here was the weaker: it read /etc/crypttab and
// never looked at the root device, so an encrypted *data* disk beside a plain
// root reported `manual-console` — a false alarm — and an encrypted root whose
// unlock is configured only in the initramfs reported `unattended`, which is
// the direction that strands a machine in a locked rack.
func TestThePreflightCheckAgreesWithTheReportedPolicy(t *testing.T) {
	// A real host, whatever this one is: the two must not be able to differ.
	got := checkEncryptedRoot()
	policy := RebootPolicy()
	if !strings.HasPrefix(got.Detail, policy+":") {
		t.Errorf("preflight says %q and the node would report %q", got.Detail, policy)
	}
	// Only `unattended` is not worth an operator's attention.
	wantLevel := LevelWarn
	if policy == PolicyUnattended {
		wantLevel = LevelOK
	}
	if got.Level != wantLevel {
		t.Errorf("level = %v for %q, want %v", got.Level, policy, wantLevel)
	}
}
