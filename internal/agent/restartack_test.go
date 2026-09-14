package agent

import "testing"

// The node reports a restart done when the deployment is serving again, and not
// before.
//
// This is the half of R4-22's guarantee that lives on the node. The control
// plane offers the next replica of a roll when this one is reported done, so
// reporting on the cycle rather than on readiness would let two nodes have
// their copy down at once — the outage the roll exists to avoid, reached by the
// mechanism meant to prevent it.
func TestARestartIsReportedDoneOnlyWhenTheDeploymentIsServing(t *testing.T) {
	restarting := map[string]bool{"dep_a": true}

	for _, state := range []string{"starting", "stopped", "failed", "unhealthy"} {
		if restartFinished(restarting, "dep_a", state) {
			t.Errorf("a deployment in %q was reported as a finished restart", state)
		}
		if !restarting["dep_a"] {
			t.Fatalf("%q forgot a restart that has not finished", state)
		}
	}

	if !restartFinished(restarting, "dep_a", "ready") {
		t.Error("a deployment serving again was not reported as a finished restart")
	}
	// Reported once. A second report would clear the next replica's row on the
	// control plane a cycle early.
	if restartFinished(restarting, "dep_a", "ready") {
		t.Error("the same restart was reported done twice")
	}

	// A deployment nobody restarted is never reported, however healthy it is.
	if restartFinished(restarting, "dep_b", "ready") {
		t.Error("a deployment nobody restarted was reported as a finished restart")
	}
}
