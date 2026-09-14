package gateway

import (
	"strings"
	"testing"
)

// R3-14's live half. nodary takes a deployment out of the file when its node
// stops reporting it ready, which happens on the order of a heartbeat; a replica
// that stops answering mid-request has to leave the rotation in the time it
// takes to notice, and that is the router's job. Doing it in nodary would mean
// restarting the data plane on every health blip, which drops live requests in
// order to route around a replica the router is already routing around.
//
// Pinned explicitly for the reason pinnedOff gives: a setting this product
// depends on must not be whatever a future LiteLLM release defaults it to.
func TestTheRouterSettingsThatMakeMembershipLiveArePinned(t *testing.T) {
	body := string(LiteLLMConfig{MasterKey: "k", Models: []LiteLLMModel{
		{Name: "tiny", Model: "tiny", APIBase: "http://127.0.0.1:8001/v1"},
	}}.Render())

	for _, want := range []string{
		"router_settings:",
		`routing_strategy: "simple-shuffle"`,
		"num_retries: 2",
		"allowed_fails: 3",
		"cooldown_time: 30",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("the rendered configuration does not pin %q:\n%s", want, body)
		}
	}
}

// config.RouteMember has carried a weight since routes existed and nothing
// rendered it, so `nodary route set --add` wrote a number that changed nothing.
// A configuration field an operator can set and the product ignores is worse
// than one that does not exist.
func TestAMembersWeightReachesTheRouter(t *testing.T) {
	weighted := string(LiteLLMConfig{MasterKey: "k", Models: []LiteLLMModel{
		{Name: "tiny", Model: "tiny", APIBase: "http://127.0.0.1:8001/v1", Weight: 3},
	}}.Render())
	if !strings.Contains(weighted, "weight: 3") {
		t.Errorf("the weight did not reach the router:\n%s", weighted)
	}

	// Zero is "not stated", not "no share": writing 0 would take the member out
	// of the rotation entirely, which is not what an unset field means.
	unset := string(LiteLLMConfig{MasterKey: "k", Models: []LiteLLMModel{
		{Name: "tiny", Model: "tiny", APIBase: "http://127.0.0.1:8001/v1"},
	}}.Render())
	if strings.Contains(unset, "weight:") {
		t.Errorf("an unset weight was rendered:\n%s", unset)
	}
}
