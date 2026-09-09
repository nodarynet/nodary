package preflight

import (
	"context"
	"fmt"
	"net"
	"strings"
	"testing"
)

// fakeRun stands in for the commands a check shells out to, so the checks can
// be driven against a host this one is not: no driver, an old driver, a driver
// that enumerates nothing.
func fakeRun(answers map[string]string, missing ...string) func(context.Context, string, ...string) ([]byte, error) {
	gone := map[string]bool{}
	for _, m := range missing {
		gone[m] = true
	}
	return func(_ context.Context, name string, args ...string) ([]byte, error) {
		if gone[name] {
			return nil, fmt.Errorf("exec: %q: executable file not found in $PATH", name)
		}
		key := name
		if len(args) > 0 {
			key = name + " " + args[0]
		}
		if v, ok := answers[key]; ok {
			return []byte(v), nil
		}
		if v, ok := answers[name]; ok {
			return []byte(v), nil
		}
		return nil, fmt.Errorf("exec: %q: no answer configured", name)
	}
}

func find(t *testing.T, r Report, name string) Check {
	t.Helper()
	for _, c := range r.Checks {
		if c.Name == name {
			return c
		}
	}
	t.Fatalf("no check named %q in %+v", name, r.Checks)
	return Check{}
}

// docs/specs/01-install.md §11 opens with this, and it is a constraint on the
// control flow: an implementation that returned at the first failure would
// satisfy the output format and miss the point entirely.
func TestEveryCheckRunsEvenWhenOneFails(t *testing.T) {
	r := Run(context.Background(), Options{
		Role: RoleNode, ModelsDir: "/", DataDir: "/",
		// A host with nothing: no systemd, no driver.
		run: fakeRun(nil, "systemctl", "nvidia-smi", "getenforce"),
	})

	// Every check still produced a result.
	for _, name := range []string{"platform", "systemd", "cgroup v2", "nvidia driver",
		"gpus", "disk: models", "disk: components", "ports", "swap", "lsm",
		"ram per gpu", "reboot policy"} {
		find(t, r, name)
	}
	if r.OK() {
		t.Error("a host with no systemd and no driver reported OK")
	}
	// And more than one failure is reported, which is the thing an operator on a
	// fresh host needs: all of it at once, not one per install attempt.
	if len(r.Failures()) < 2 {
		t.Errorf("failures = %+v, want every problem at once", r.Failures())
	}
}

// A check that cannot reach its evidence must never report ok.
func TestAnUnrunnableCheckIsNotAPass(t *testing.T) {
	r := Run(context.Background(), Options{
		Role: RoleNode, ModelsDir: "/", DataDir: "/",
		run: fakeRun(nil, "nvidia-smi", "getenforce"),
	})
	for _, name := range []string{"nvidia driver", "gpus"} {
		if got := find(t, r, name); got.Level == LevelOK {
			t.Errorf("%s reported ok with nvidia-smi absent: %+v", name, got)
		}
	}
}

func TestTheDriverFloorIsEnforced(t *testing.T) {
	for _, tc := range []struct {
		what    string
		version string
		want    Level
	}{
		{"below the floor", "470.129.06", LevelFail},
		{"at the floor", "525.60.13", LevelOK},
		{"well above", "610.88", LevelOK},
		// Unparseable is not a pass: the floor is the point of the check.
		{"unparseable", "NVIDIA-SMI has failed", LevelFail},
		{"empty", "", LevelFail},
	} {
		r := Run(context.Background(), Options{
			Role: RoleNode, ModelsDir: "/", DataDir: "/",
			run: fakeRun(map[string]string{
				"nvidia-smi": tc.version + "\n", "systemctl": "systemd 255\n"}, "getenforce"),
		})
		if got := find(t, r, "nvidia driver"); got.Level != tc.want {
			t.Errorf("%s (%q): level = %q, want %q — %s", tc.what, tc.version, got.Level, tc.want, got.Detail)
		}
	}
}

// The signature R5-03 names, and the one this machine would hit: nvidia-smi
// runs and enumerates nothing, which on WSL2 means a driver installed inside
// the distribution.
func TestNoEnumeratedGPUsFailsForANode(t *testing.T) {
	r := Run(context.Background(), Options{
		Role: RoleNode, ModelsDir: "/", DataDir: "/",
		run: fakeRun(map[string]string{
			"nvidia-smi": "\n", "systemctl": "systemd 255\n"}, "getenforce"),
	})
	got := find(t, r, "gpus")
	if got.Level != LevelFail {
		t.Errorf("level = %q, want fail: a node with no GPUs cannot serve", got.Level)
	}
	if !strings.Contains(got.Detail, "enumerates no GPUs") {
		t.Errorf("detail = %q", got.Detail)
	}
}

// A control plane needs no GPU, and telling an operator otherwise would send
// them looking for a driver they do not need.
func TestAControlPlaneSkipsTheGPUChecks(t *testing.T) {
	r := Run(context.Background(), Options{
		Role: RoleServer, ModelsDir: "/", DataDir: "/",
		run: fakeRun(map[string]string{"systemctl": "systemd 255\n"}, "nvidia-smi", "getenforce"),
	})
	for _, name := range []string{"nvidia driver", "gpus", "ram per gpu"} {
		if got := find(t, r, name); got.Level != LevelSkip {
			t.Errorf("%s: level = %q, want skip for a control plane", name, got.Level)
		}
	}
	if !r.OK() {
		t.Errorf("a control plane with no GPU did not pass: %+v", r.Failures())
	}
}

// A port already in use is a hard failure, and it is checked for real rather
// than by parsing `ss`.
func TestAPortInUseFails(t *testing.T) {
	held := listenSomewhere(t)
	r := Run(context.Background(), Options{
		Role: RoleServer, ModelsDir: "/", DataDir: "/", Ports: []int{held},
		run: fakeRun(map[string]string{"systemctl": "systemd 255\n"}, "nvidia-smi", "getenforce"),
	})
	got := find(t, r, "ports")
	if got.Level != LevelFail || !strings.Contains(got.Detail, fmt.Sprint(held)) {
		t.Errorf("check = %+v, want a failure naming %d", got, held)
	}
}

// Warnings never block. An operator with a hardened host and no swap should be
// told, and should still be able to install.
func TestWarningsDoNotBlock(t *testing.T) {
	r := Report{Checks: []Check{
		{Name: "swap", Level: LevelWarn},
		{Name: "lsm", Level: LevelWarn},
		{Name: "platform", Level: LevelOK},
	}}
	if !r.OK() {
		t.Error("warnings blocked")
	}
	if len(r.Failures()) != 0 {
		t.Errorf("failures = %+v", r.Failures())
	}
}

// The failing checks come first, so the thing that blocks is the thing an
// operator reads before scrolling.
func TestFailuresSortFirst(t *testing.T) {
	r := Run(context.Background(), Options{
		Role: RoleNode, ModelsDir: "/", DataDir: "/",
		run: fakeRun(nil, "systemctl", "nvidia-smi", "getenforce"),
	})
	if len(r.Checks) == 0 || r.Checks[0].Level != LevelFail {
		t.Errorf("the first check is %+v, want a failure", r.Checks[0])
	}
	var seenNonFail bool
	for _, c := range r.Checks {
		if c.Level != LevelFail {
			seenNonFail = true
			continue
		}
		if seenNonFail {
			t.Errorf("%s is a failure after a non-failure", c.Name)
		}
	}
}

// listenSomewhere holds a port for the duration of a test.
func listenSomewhere(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	return ln.Addr().(*net.TCPAddr).Port
}

// TestANodeWithoutIPTablesIsRefused is the case a privileged run found.
//
// The isolated network's portmap plugin is pure iptables, so on a host without
// it every deployment fails at CNI attach — the container is created and torn
// down, and containerd's journal shows only a shim that disconnected. Preflight
// is where that has to be said, because it is the only place that says it
// before anything is installed.
//
// nft is the opposite call: its rule is defense in depth, so its absence warns.
func TestANodeWithoutIPTablesIsRefusedAndWithoutNFTIsWarned(t *testing.T) {
	// An empty PATH and a HOME with nothing in it: Resolve still walks toolDirs,
	// so this asserts against the real host. Skipped where iptables exists,
	// because then there is nothing to observe.
	if found(Resolve("iptables")) {
		t.Skip("this host has iptables; the refusal cannot be observed here")
	}
	if c := checkIPTables(Options{Role: RoleNode}); c.Level != LevelFail {
		t.Errorf("iptables missing: level = %q, want %q", c.Level, LevelFail)
	}
	if c := checkIPTables(Options{Role: RoleServer}); c.Level != LevelSkip {
		t.Errorf("a control plane runs no containers: level = %q, want %q", c.Level, LevelSkip)
	}
	if !found(Resolve("nft")) {
		c := checkNFT(Options{Role: RoleNode})
		if c.Level != LevelWarn {
			t.Errorf("nft missing: level = %q, want %q — the missing route is the control", c.Level, LevelWarn)
		}
	}
}

// TestResolveFindsWhatIsThere pins found() to Resolve's contract: a bare name
// means nothing was located, and treating that as a hit would make every
// tool check pass on every host.
func TestResolveFindsWhatIsThere(t *testing.T) {
	if !found(Resolve("sh")) {
		t.Error("sh was not found, so found() disagrees with Resolve")
	}
	if found(Resolve("nodary-no-such-tool")) {
		t.Error("a tool that does not exist was reported as found")
	}
}

// TestANodeWithoutTheContainerToolkitIsRefused is the check that explains why no
// model had ever run.
//
// `nodary-model@.service` runs `nerdctl run --gpus …`. Without the NVIDIA
// Container Toolkit that flag resolves to nothing, the container starts with no
// device, and the failure arrives as a model server that cannot find CUDA — a
// message naming neither the toolkit nor the flag. Found by asking why a control
// plane and a node that both pass every other check still cannot serve anything.
func TestANodeWithoutTheContainerToolkitIsRefused(t *testing.T) {
	if found(Resolve("nvidia-ctk")) || found(Resolve("nvidia-container-cli")) {
		t.Skip("this host has the toolkit; the refusal cannot be observed here")
	}
	if c := checkContainerToolkit(Options{Role: RoleNode}); c.Level != LevelFail {
		t.Errorf("toolkit missing: level = %q, want %q", c.Level, LevelFail)
	}
	// A control plane runs no containers, so it must not be blocked by this.
	if c := checkContainerToolkit(Options{Role: RoleServer}); c.Level != LevelSkip {
		t.Errorf("control plane: level = %q, want %q", c.Level, LevelSkip)
	}
}

// TestFreeVRAMWarnsBeforeADeploymentDiscoversIt is the check that would have
// saved a restart loop.
//
// A model server sizes its cache against free memory at startup and refuses
// rather than shrinking, and vLLM refuses twice over — once when the requested
// fraction exceeds what is free, and again when free memory *moves* while it
// profiles. Both are host conditions a node does not control; what it can do is
// say so before a deployment finds out in a restart loop. Found on a card
// sitting at 412 MiB free of 32607.
func TestFreeVRAMWarnsBeforeADeploymentDiscoversIt(t *testing.T) {
	at := func(csv string) Check {
		return checkFreeVRAM(context.Background(), Options{
			Role: RoleNode,
			run: func(context.Context, string, ...string) ([]byte, error) {
				return []byte(csv), nil
			},
		})
	}

	if c := at("0, 412, 32607\n"); c.Level != LevelWarn {
		t.Errorf("a nearly full card: level = %q, want warn (%s)", c.Level, c.Detail)
	} else if !strings.Contains(c.Detail, "412") {
		t.Errorf("the warning does not say how much is left: %s", c.Detail)
	}
	if c := at("0, 30000, 32607\n"); c.Level != LevelOK {
		t.Errorf("a mostly free card: level = %q, want ok (%s)", c.Level, c.Detail)
	}
	// Warned, never failed: installing beside a workload that will be stopped
	// later is ordinary, and refusing would be nodary deciding what else may
	// run on the machine.
	if c := at("0, 1, 32607\n1, 30000, 32607\n"); c.Level == LevelFail {
		t.Error("a busy GPU blocked the install")
	}
	// A control plane runs no models.
	if c := checkFreeVRAM(context.Background(), Options{Role: RoleServer}); c.Level != LevelSkip {
		t.Errorf("control plane: level = %q, want skip", c.Level)
	}
}
