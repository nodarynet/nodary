package gateway

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/nodarynet/nodary/internal/config"
)

// LiteLLMConfig is the file the gateway renders and LiteLLM reads.
//
// It is generated from routes and deployments rather than maintained by hand,
// because the two would drift and the drift would be invisible: a route whose
// deployment moved would keep proxying to an address nothing serves.
type LiteLLMConfig struct {
	Models    []LiteLLMModel
	MasterKey string
}

// LiteLLMModel is one route, pointed at one deployment.
type LiteLLMModel struct {
	Name    string
	APIBase string
	Model   string
}

// pinnedOff are the settings that must appear, set to these values, in every
// configuration this renders.
//
// docs/plans/pivot-cmmc.md makes LiteLLM a compliance surface. Inside a CUI
// boundary "LiteLLM began writing request bodies somewhere by default in a
// minor release" is an incident, not a nuisance — and the failure is silent,
// because a configuration that omits a setting inherits whatever the new
// default is.
//
// So each of these is written explicitly even where it is already the default,
// and AssertLoggingOff checks the rendered output rather than trusting this
// list. That is the same principle as egress verification
// (docs/specs/03-agent.md §5), and it is here for the same reason: a control
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

// Render writes litellm.yaml.
//
// The proxy is given exactly one credential — the master key — and no database.
// docs/specs/06-gateway.md §1: because identity lives in nodary, LiteLLM runs
// stateless behind a single key that is never exposed to clients.
func (c LiteLLMConfig) Render() []byte {
	var b strings.Builder
	b.WriteString(`# Written by nodary. Edits are overwritten.
#
# Generated from the routes and deployments in the control plane's
# configuration (docs/specs/06-gateway.md §1). LiteLLM owns OpenAI
# compatibility, routing, retries and fallbacks; nodary owns identity, quota,
# metering and audit, which is why there is no database here and no key but one.

model_list:
`)
	models := append([]LiteLLMModel(nil), c.Models...)
	sort.Slice(models, func(i, j int) bool { return models[i].Name < models[j].Name })
	for _, m := range models {
		fmt.Fprintf(&b, "  - model_name: %q\n", m.Name)
		b.WriteString("    litellm_params:\n")
		fmt.Fprintf(&b, "      model: %q\n", "openai/"+m.Model)
		fmt.Fprintf(&b, "      api_base: %q\n", m.APIBase)
		// The deployments are on loopback behind an isolated network and speak
		// OpenAI without authentication of their own; nodary is what
		// authenticated the caller.
		b.WriteString("      api_key: \"nodary-unused\"\n")
	}
	if len(models) == 0 {
		// An empty list rather than an absent key: LiteLLM refuses a
		// configuration with no model_list, and a control plane with no ready
		// deployments is an ordinary state, not a broken one.
		b.WriteString("  []\n")
	}

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

// AssertLoggingOff checks the rendered bytes, not the renderer.
//
// R3-16 requires this to be asserted continuously rather than configured once.
// The gateway calls it before it uses a configuration, so a change to Render
// that dropped a setting fails at startup rather than at an assessment.
func AssertLoggingOff(rendered []byte) error {
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

// ConfigFor builds the proxy configuration from the control plane's own.
//
// One entry per route member, addressed on loopback: docs/specs/03-agent.md §5
// publishes a deployment's port on 127.0.0.1 only, so this is the only address
// that can reach one — and a route pointing anywhere else would mean the
// isolation had failed.
func ConfigFor(ctx context.Context, q config.Querier, masterKey string) (LiteLLMConfig, error) {
	snap, err := config.Read(ctx, q)
	if err != nil {
		return LiteLLMConfig{}, err
	}
	byID := map[string]config.Deployment{}
	for _, d := range snap.Deployments {
		byID[d.ID] = d
	}

	c := LiteLLMConfig{MasterKey: masterKey}
	for _, rt := range snap.Routes {
		for _, m := range rt.Members {
			d, ok := byID[m.DeploymentID]
			if !ok || d.Port == 0 {
				// A member whose deployment has no port is one nothing has
				// started. Skipped rather than rendered as an address that
				// refuses: LiteLLM would retry it on every request.
				continue
			}
			c.Models = append(c.Models, LiteLLMModel{
				Name:    rt.Name,
				Model:   d.ModelID,
				APIBase: fmt.Sprintf("http://127.0.0.1:%d/v1", d.Port),
			})
		}
	}
	return c, nil
}
