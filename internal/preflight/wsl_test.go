package preflight

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
)

// wslHost builds a WSL2 tree. The real shape, taken from a working host:
// no /proc/driver/nvidia, and libcuda.so.1 under /usr/lib/wsl/lib.
func wslHost(t *testing.T) *fakeHostFS {
	t.Helper()
	f := newFakeHostFS(t)
	f.write("/proc/sys/kernel/osrelease", "6.6.87.2-microsoft-standard-WSL2\n")
	f.write(wslLibDir+"/"+wslCUDA, "")
	return f
}

// loader stands in for `ldconfig -p`, whose output is what decides which
// libcuda a container actually opens.
func loader(paths ...string) func(context.Context, string, ...string) ([]byte, error) {
	var b strings.Builder
	b.WriteString("1234 libs found in cache `/etc/ld.so.cache'\n")
	for _, p := range paths {
		fmt.Fprintf(&b, "\t%s (libc6,x86-64) => %s\n", wslCUDA, p)
	}
	return func(context.Context, string, ...string) ([]byte, error) {
		return []byte(b.String()), nil
	}
}

func passthrough(t *testing.T, f *fakeHostFS,
	run func(context.Context, string, ...string) ([]byte, error)) Check {
	t.Helper()
	o := Options{run: run}
	return checkWSLPassthrough(context.Background(), o, hostFS{root: f.root})
}

// The measured state of a working host: a distribution NVIDIA userland is
// present *and* passthrough works, because WSL's directory comes first in the
// loader cache. A check for the WSL library's mere presence would pass on the
// broken host too, which is why this reads the order.
func TestAWorkingWSLHostPassesWithADistributionDriverBehindIt(t *testing.T) {
	c := passthrough(t, wslHost(t), loader(
		wslLibDir+"/"+wslCUDA,
		"/lib/x86_64-linux-gnu/"+wslCUDA,
	))
	if c.Level != LevelOK {
		t.Fatalf("a working host failed: %s — %s", c.Level, c.Detail)
	}
}

// The failure R5-03 names: an in-distribution driver gets in front of the
// passthrough library, `nvidia-smi` still answers from the Windows driver, and
// every deployment dies at start with an error about CUDA.
func TestADistributionDriverInFrontOfThePassthroughLibraryFails(t *testing.T) {
	c := passthrough(t, wslHost(t), loader(
		"/lib/x86_64-linux-gnu/"+wslCUDA,
		wslLibDir+"/"+wslCUDA,
	))
	if c.Level != LevelFail {
		t.Fatalf("a shadowed passthrough library passed: %s — %s", c.Level, c.Detail)
	}
	if !strings.Contains(c.Detail, "/lib/x86_64-linux-gnu/"+wslCUDA) {
		t.Errorf("the failure does not name what won: %s", c.Detail)
	}
	if !strings.Contains(c.Detail, "no Linux display driver") {
		t.Errorf("the failure does not say what to do: %s", c.Detail)
	}
}

// The unambiguous one: WSL2 binds the GPU through dxgkrnl, so this file exists
// only where somebody installed a kernel driver that cannot work here.
func TestAnInDistributionKernelDriverFails(t *testing.T) {
	f := wslHost(t)
	f.write(nvidiaKmod, "NVRM version: 550.54.14\n")
	c := passthrough(t, f, loader(wslLibDir+"/"+wslCUDA))
	if c.Level != LevelFail {
		t.Fatalf("an in-distribution kernel driver passed: %s — %s", c.Level, c.Detail)
	}
	if !strings.Contains(c.Detail, nvidiaKmod) {
		t.Errorf("the failure does not name the evidence: %s", c.Detail)
	}
}

func TestAWSLHostWithNoPassthroughLibraryFails(t *testing.T) {
	f := newFakeHostFS(t)
	f.write("/proc/sys/kernel/osrelease", "6.6.87.2-microsoft-standard-WSL2\n")
	c := passthrough(t, f, loader())
	if c.Level != LevelFail {
		t.Fatalf("a host with no passthrough library passed: %s — %s", c.Level, c.Detail)
	}
	if !strings.Contains(c.Detail, "wsl --shutdown") {
		t.Errorf("the failure does not say how to recover: %s", c.Detail)
	}
}

// Every other Linux host skips this, and a skip is not a pass: R5-01 makes that
// distinction, and reporting `ok` here would assert a property about a machine
// nobody looked at.
func TestANonWSLHostIsSkippedRatherThanPassed(t *testing.T) {
	f := newFakeHostFS(t)
	f.write("/proc/sys/kernel/osrelease", "6.8.0-generic\n")
	c := passthrough(t, f, loader())
	if c.Level != LevelSkip {
		t.Fatalf("an ordinary Linux host reported %s: %s", c.Level, c.Detail)
	}
}

// A check that cannot run is not a check that passed. Without ldconfig the
// order is unknown, and unknown is not good news.
func TestAnUnreadableLoaderCacheIsNotAPass(t *testing.T) {
	c := passthrough(t, wslHost(t), func(context.Context, string, ...string) ([]byte, error) {
		return nil, fmt.Errorf("exec: \"ldconfig\": executable file not found in $PATH")
	})
	if c.Level == LevelOK {
		t.Fatalf("an unreadable loader cache reported ok: %s", c.Detail)
	}
}

// firstLoaderPath has to pick the first entry, because that is the one the
// loader picks. Taking the last would report the broken host as healthy and
// the healthy one as broken — exactly inverted.
func TestTheLoaderOrderIsReadInOrder(t *testing.T) {
	listing := "\t" + wslCUDA + " (libc6,x86-64) => /first/" + wslCUDA + "\n" +
		"\t" + wslCUDA + " (libc6,x86-64) => /second/" + wslCUDA + "\n"
	got, ok := firstLoaderPath(listing, wslCUDA)
	if !ok || got != "/first/"+wslCUDA {
		t.Errorf("picked %q (found=%v)", got, ok)
	}
	// A soname that is a prefix of another must not match it.
	if _, ok := firstLoaderPath("\tlibcuda.so.11 (libc6,x86-64) => /x/libcuda.so.11\n",
		wslCUDA); ok {
		t.Error("libcuda.so.11 matched a lookup for libcuda.so.1")
	}
}

// R5-03's first half. `systemctl --version` prints a version from the binary
// and asks PID 1 nothing, so on a WSL2 distribution without `systemd=true` it
// succeeds while PID 1 is /init — and preflight reported systemd `ok` on a host
// where the very next `systemctl enable` fails. install.sh has always tested
// /run/systemd/system; this is the same test on the other side of the same
// install.
func TestSystemdInstalledIsNotSystemdRunning(t *testing.T) {
	previous := runSystemdSystem
	runSystemdSystem = filepath.Join(t.TempDir(), "absent")
	t.Cleanup(func() { runSystemdSystem = previous })

	o := Options{run: func(context.Context, string, ...string) ([]byte, error) {
		return []byte("systemd 255 (255.4-1ubuntu8.17)\n"), nil
	}}
	c := checkSystemd(context.Background(), o)
	if c.Level != LevelFail {
		t.Fatalf("a host where systemd is installed but not init passed: %s — %s", c.Level, c.Detail)
	}
	if !strings.Contains(c.Detail, "not running as init") {
		t.Errorf("the failure does not say what is wrong: %s", c.Detail)
	}
}

// And when it is running, the version is the answer — the check must not start
// failing on every ordinary host.
func TestSystemdRunningAsInitPasses(t *testing.T) {
	dir := t.TempDir()
	previous := runSystemdSystem
	runSystemdSystem = dir
	t.Cleanup(func() { runSystemdSystem = previous })

	o := Options{run: func(context.Context, string, ...string) ([]byte, error) {
		return []byte("systemd 255 (255.4-1ubuntu8.17)\n"), nil
	}}
	if c := checkSystemd(context.Background(), o); c.Level != LevelOK {
		t.Fatalf("a healthy host reported %s: %s", c.Level, c.Detail)
	}
}
