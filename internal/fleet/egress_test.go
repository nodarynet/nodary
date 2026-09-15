package fleet_test

import (
	"testing"

	"github.com/nodarynet/nodary/internal/agent"
	"github.com/nodarynet/nodary/internal/fleet"
)

// The vocabulary is produced by internal/agent's Judge and restated in
// internal/fleet, which cannot import it — internal/agent imports internal/api,
// which imports internal/fleet. A drift would be silent and total: every stored
// verdict would fall through EgressState's switch and a non-compliant node
// would report the empty verdict, which reads as "nothing has run here".
func TestTheFleetEgressVocabularyIsTheAgents(t *testing.T) {
	for _, pair := range []struct{ fleetWord, agentWord string }{
		{fleet.EgressCompliant, agent.Compliant},
		{fleet.EgressNonCompliant, agent.NonCompliant},
		{fleet.EgressInconclusive, agent.Inconclusive},
	} {
		if pair.fleetWord != pair.agentWord {
			t.Errorf("fleet says %q where the agent writes %q", pair.fleetWord, pair.agentWord)
		}
	}
}

// dev/specs/03-agent.md §5 is a property of a deployment; an operator asks it
// of a node. The rounding in between is where it goes wrong quietly, so each
// direction is pinned.
func TestANodeIsOnlyCompliantWhenEverythingOnItIs(t *testing.T) {
	dep := func(states ...string) []fleet.Deployment {
		out := []fleet.Deployment{}
		for _, s := range states {
			out = append(out, fleet.Deployment{Egress: s})
		}
		return out
	}
	for _, c := range []struct {
		name  string
		given []fleet.Deployment
		want  string
	}{
		{"nothing placed at all", nil, fleet.EgressUnasserted},
		{"placed but never run", dep("", ""), fleet.EgressUnasserted},
		{"every one isolated", dep("compliant", "compliant"), fleet.EgressCompliant},
		// The one that matters: a single leak is the node's verdict, however
		// many compliant deployments surround it.
		{"one of many leaking", dep("compliant", "compliant", "non-compliant"), fleet.EgressNonCompliant},
		{"a leak beside an unknown", dep("", "non-compliant"), fleet.EgressNonCompliant},
		{"one unestablished", dep("compliant", "inconclusive"), fleet.EgressInconclusive},
		// Not compliant: the answer covers some of the node, and saying
		// "compliant" would extend it to a deployment nobody probed.
		{"one never probed", dep("compliant", ""), fleet.EgressInconclusive},
		{"only unestablished", dep("inconclusive"), fleet.EgressInconclusive},
	} {
		if got := fleet.EgressState(c.given); got != c.want {
			t.Errorf("%s: %q, want %q", c.name, got, c.want)
		}
	}
}
