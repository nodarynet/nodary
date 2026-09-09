package agent

import (
	"context"
	"os"
	"os/exec"
	"testing"

	"github.com/nodarynet/nodary/internal/preflight"
)

// TestTheGPUProbeFindsToolsOffPath is the bug that made a GPU host advertise no
// GPUs.
//
// On WSL2 the NVIDIA tools live in /usr/lib/wsl/lib, which a login profile adds
// to PATH and which **sudo's `secure_path` and a systemd unit's PATH both
// drop**. preflight learned that and this probe had not, so the agent enrolled
// advertising an empty offer and every deployment was refused with "GPU 0 is
// not on this node's offer" — on a host whose own `nodary doctor` reported the
// card, because doctor resolves and this did not.
//
// The test empties PATH, which is the harshest version of what sudo does.
func TestTheGPUProbeFindsToolsOffPath(t *testing.T) {
	if !isAbs(preflight.Resolve("nvidia-smi")) {
		t.Skip("no nvidia-smi anywhere on this host")
	}
	if _, err := exec.LookPath("nvidia-smi"); err == nil {
		// It is on PATH here, so emptying PATH is what makes this meaningful.
		t.Log("nvidia-smi is on PATH; the probe is exercised with PATH emptied")
	}
	t.Setenv("PATH", "")

	gpus, driver := probeGPUs(context.Background())
	if len(gpus) == 0 {
		t.Fatal("no GPUs found with PATH emptied; the agent would enrol with an empty offer")
	}
	if driver == "" {
		t.Error("no driver version reported")
	}
	t.Logf("found %d GPU(s), driver %s", len(gpus), driver)
}

func isAbs(p string) bool { return len(p) > 0 && os.IsPathSeparator(p[0]) }
