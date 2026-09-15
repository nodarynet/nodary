package dataplane

import (
	"fmt"
	"sort"
	"strings"
)

// LiteLLM is the plane every install before dev/plans/R3b-a-second-data-plane.md
// runs, and the one a server.toml with no `data_plane` key means.
//
// dev/specs/00-overview.md §7: it owns OpenAI compatibility, routing, retries
// and fallbacks, stateless behind one master key with no database of its own,
// because identity, quota, metering and audit live in nodary.
var LiteLLM = Plane{
	Name:         "litellm",
	Component:    "litellm",
	Unit:         "nodary-litellm.service",
	UnitBody:     litellmUnit,
	ConfigFile:   "litellm.yaml",
	EnvFile:      "litellm.env",
	ImageVar:     "NODARY_LITELLM_IMAGE",
	AppliedName:  "litellm.applied",
	ServedHeader: litellmModelHeader,
	Render:       renderLiteLLM,
	Assert:       assertLiteLLMLoggingOff,
}

// litellmModelHeader is what LiteLLM returns on every response, carrying the
// model_info.id of the deployment it actually routed to.
//
// Verified against the pinned image rather than assumed — a third-party header
// is a contract nobody promised us, and TestLiteLLMReturnsTheDeploymentIdWeGaveIt
// fails the build if a version bump drops it. When it is absent the usage row
// carries no deployment, which is the honest answer: nothing else in the
// request says which member of a route served it.
const litellmModelHeader = "X-Litellm-Model-Id"

// litellmUnit runs the OpenAI-compatible data plane.
//
// **`--network host`, and that is not laziness.** A deployment publishes its
// port on the host's loopback (03 §5, `-p 127.0.0.1:…`), and a container on a
// bridge cannot reach the host's 127.0.0.1. Sharing the host namespace is what
// lets the data plane reach the models; it binds 127.0.0.1:4000 itself, so
// nothing it serves is reachable off-box either.
//
// The image comes from an environment file rather than being written into the
// unit, for the reason a deployment's image does: an upgrade rewrites one value
// instead of rewriting a unit systemd has to be told about.
const litellmUnit = `# Written by nodary. Edits are overwritten.
[Unit]
Description=LiteLLM, the OpenAI-compatible data plane for nodary
After=containerd.service
Requires=containerd.service

[Service]
Type=exec
EnvironmentFile=/etc/nodary/litellm.env
ExecStartPre=-/usr/local/bin/nerdctl rm -f nodary-litellm
ExecStart=/usr/local/bin/nerdctl run --rm --name nodary-litellm     --network host     -v /etc/nodary/litellm.yaml:/etc/litellm/config.yaml:ro     ${NODARY_LITELLM_IMAGE}     --config /etc/litellm/config.yaml --host 127.0.0.1 --port 4000
ExecStop=/usr/local/bin/nerdctl stop --time 30 nodary-litellm
Restart=always
RestartSec=10s

[Install]
WantedBy=multi-user.target
`

// pinnedOff are the settings that must appear, set to these values, in every
// configuration this renders.
//
// dev/plans/pivot-cmmc.md makes LiteLLM a compliance surface. Inside a CUI
// boundary "LiteLLM began writing request bodies somewhere by default in a
// minor release" is an incident, not a nuisance — and the failure is silent,
// because a configuration that omits a setting inherits whatever the new
// default is.
//
// So each of these is written explicitly even where it is already the default,
// and the assertion checks the rendered output rather than trusting this
// list. That is the same principle as egress verification
// (dev/specs/03-agent.md §5), and it is here for the same reason: a control
// whose failure looks exactly like success.
var pinnedOff = []struct {
	Key    string
	Value  string
	Reason string
}{
	{"store_model_in_db", "false", "no database: identity and accounting live in nodary (00 §7)"},
	{"store_prompts_in_spend_logs", "false", "the setting whose default changing would be the incident"},
	{"turn_off_message_logging", "true", "request and response content never reaches a log"},
	{"redact_user_api_key_info", "true", "a service key is a credential, not telemetry"},
	{"disable_spend_logs", "true", "nodary meters; a second ledger is a second place content can land"},
	{"disable_error_logs", "true", "an error log carries the request that caused it"},
}

// renderLiteLLM writes litellm.yaml.
//
// The proxy is given exactly one credential — the master key — and no database.
// dev/specs/06-gateway.md §1: because identity lives in nodary, LiteLLM runs
// stateless behind a single key that is never exposed to clients.
func renderLiteLLM(c Config) []byte {
	var b strings.Builder
	b.WriteString(`# Written by nodary. Edits are overwritten.
#
# Generated from the routes and deployments in the control plane's
# configuration (dev/specs/06-gateway.md §1). LiteLLM owns OpenAI
# compatibility, routing, retries and fallbacks; nodary owns identity, quota,
# metering and audit, which is why there is no database here and no key but one.

model_list:
`)
	members := append([]Member(nil), c.Members...)
	sort.Slice(members, func(i, j int) bool { return members[i].Name < members[j].Name })
	for _, m := range members {
		fmt.Fprintf(&b, "  - model_name: %q\n", m.Name)
		b.WriteString("    litellm_params:\n")
		fmt.Fprintf(&b, "      model: %q\n", "openai/"+m.Model)
		fmt.Fprintf(&b, "      api_base: %q\n", m.APIBase)
		// The deployments are on loopback behind an isolated network and speak
		// OpenAI without authentication of their own; nodary is what
		// authenticated the caller.
		b.WriteString("      api_key: \"nodary-unused\"\n")
		if m.Weight > 0 {
			fmt.Fprintf(&b, "      weight: %d\n", m.Weight)
		}
		if m.ID != "" {
			b.WriteString("    model_info:\n")
			fmt.Fprintf(&b, "      id: %q\n", m.ID)
		}
	}
	if len(members) == 0 {
		// An empty list rather than an absent key: LiteLLM refuses a
		// configuration with no model_list, and a control plane with no ready
		// deployments is an ordinary state, not a broken one.
		b.WriteString("  []\n")
	}

	// dev/specs/05-catalog.md §5 spreads requests across a route's ready
	// members, and these are what make that happen *between* syncs.
	//
	// **This is the live half of health-driven membership.** nodary removes a
	// deployment from the file when its node stops reporting it ready, which is
	// bookkeeping on the order of a heartbeat; a replica that stops answering
	// mid-request has to leave the rotation in the time it takes to notice, and
	// that is the router's job — LiteLLM owns routing, retries and fallbacks
	// (06 §1), and doing it here would mean a data-plane restart per health
	// blip, which drops live requests to fix a replica that is already being
	// routed around.
	//
	// Written explicitly rather than inherited, the same discipline pinnedOff
	// follows: a setting this product depends on must not be whatever a future
	// LiteLLM release defaults it to.
	//
	// `simple-shuffle` is a weighted spread, not a strict rotation — LiteLLM
	// offers no strategy named round-robin — so §5's "round-robin" is honoured
	// as "spread across ready members", with RouteMember.Weight as the share.
	// Naming the discrepancy is cheaper than a rotation nodary would have to
	// implement itself in front of a router that already spreads.
	b.WriteString(`
router_settings:
  routing_strategy: "simple-shuffle"
  num_retries: 2            # a failed member is retried on another, not returned to the client
  allowed_fails: 3          # 03 §7's three consecutive failures, applied on the request path
  cooldown_time: 30         # seconds out of rotation; the next sync decides whether it stays
`)

	b.WriteString("\ngeneral_settings:\n")
	fmt.Fprintf(&b, "  master_key: %q\n", c.MasterKey)
	for _, p := range pinnedOff {
		if isGeneral(p.Key) {
			fmt.Fprintf(&b, "  %s: %s   # %s\n", p.Key, p.Value, p.Reason)
		}
	}

	b.WriteString("\nlitellm_settings:\n")
	for _, p := range pinnedOff {
		if !isGeneral(p.Key) {
			fmt.Fprintf(&b, "  %s: %s   # %s\n", p.Key, p.Value, p.Reason)
		}
	}
	// An empty callback list, written out rather than omitted: a callback is
	// how request content leaves LiteLLM for somewhere else, and the absence of
	// the key inherits whatever a future default is.
	b.WriteString("  success_callback: []\n  failure_callback: []\n  callbacks: []\n")
	return []byte(b.String())
}

// isGeneral says which block a setting belongs in. LiteLLM splits them, and
// putting one in the wrong block means it is silently ignored — which for these
// settings means silently defaulted.
func isGeneral(key string) bool {
	switch key {
	case "store_model_in_db", "store_prompts_in_spend_logs", "disable_spend_logs", "disable_error_logs":
		return true
	}
	return false
}

// ErrLoggingNotPinned is a rendered configuration that would let request
// content reach a log or a database.
var ErrLoggingNotPinned = fmt.Errorf("litellm configuration does not pin request logging off")

// assertLiteLLMLoggingOff checks the rendered bytes, not the renderer.
//
// R3-16 requires this to be asserted continuously rather than configured once.
// The gateway calls it before it uses a configuration, so a change to Render
// that dropped a setting fails at startup rather than at an assessment.
func assertLiteLLMLoggingOff(rendered []byte) error {
	body := string(rendered)
	var missing []string
	for _, p := range pinnedOff {
		if !strings.Contains(body, p.Key+": "+p.Value) {
			missing = append(missing, p.Key)
		}
	}
	for _, cb := range []string{"success_callback: []", "failure_callback: []", "callbacks: []"} {
		if !strings.Contains(body, cb) {
			missing = append(missing, strings.TrimSuffix(cb, ": []"))
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("%w: %s", ErrLoggingNotPinned, strings.Join(missing, ", "))
	}
	return nil
}
