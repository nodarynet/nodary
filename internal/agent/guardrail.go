package agent

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/nodarynet/nodary/internal/api"
)

// R4-14, [12 §1](../../docs/specs/12-node-guardrails.md#1-where-they-apply):
// the desired-state document evaluated against node.toml before anything is
// reconciled.
//
// **Not everything in 12 §2's table is here, and the absences are deliberate.**
//
//   - `gpu_indices` is enforced already, one layer up. NodeConfig.Advertise
//     narrows the offer and Daemon.reconcile passes that narrowed set as
//     PlanOptions.Present, so unitFor already refuses a deployment binding a
//     card this node withheld. Re-checking it here would be a second answer to
//     a question that already has one.
//   - `allow.prepare_jobs` gates a backend `prepare` step ([04 §4]), and no
//     descriptor in this build has one — R6-02 keeps `[backend.prepare]`
//     unimplemented rather than claiming a backend it cannot run. There is
//     nothing to refuse yet.
//   - `allow.package_install` and `allow.reboot` gate actions no code path
//     performs. nodary never initiates a reboot under either reboot_policy
//     ([03 §7]), and nothing installs host packages after enrollment.
//   - `window.maintenance` confines *disruptive actions* rather than
//     placements, which is a different mechanism: it would have to gate
//     Reconcile's stop, restart and restage on a clock. It is left out on
//     purpose. A closed window that suppressed stops would mean `nodary node
//     drain` did nothing until Saturday, and deciding that is worth a change
//     of its own rather than a line in this one.
//
// So what is evaluated here is the three limits that decide whether a placement
// may run at all: the backend, the VRAM ceiling, and the count.

// deploymentParams is the one part of a deployment's params a guardrail reads.
//
// Unmarshalled into a struct with a single field rather than a map: the params
// are an operator's JSON and this only ever asks one question of them, so the
// narrow type is both the check and the documentation of what is consulted.
type deploymentParams struct {
	GPUMemoryFraction *float64 `json:"gpu_memory_fraction"`
}

// outsideLimits says why node.toml will not have this deployment, or "".
//
// placed is how many deployments this plan has already accepted, which is what
// max_deployments counts against. The document arrives ordered by deployment id
// (internal/config's `ORDER BY id`), so which placements fall outside a cap is
// stable between cycles rather than shuffling with each poll.
func (c NodeConfig) outsideLimits(d api.DesiredDeployment, placed int) string {
	if c.Allow.Backends != nil && !slices.Contains(c.Allow.Backends, d.Backend) {
		// An empty list is a real answer — "no backends" — and is not the same
		// as an absent one, which offers all of them. TOML tells them apart and
		// LoadNodeConfig keeps them apart, so this does too.
		return fmt.Sprintf("node.toml allows backends [%s] and this asks for %q",
			strings.Join(c.Allow.Backends, " "), d.Backend)
	}
	if f := c.Limits.MaxVRAMFraction; f != nil {
		var p deploymentParams
		// A params blob that will not parse is not a guardrail violation: it is
		// unitFor's to refuse, with a message about the params rather than
		// about a limit that may be perfectly satisfied.
		if err := json.Unmarshal(d.Params, &p); err == nil &&
			p.GPUMemoryFraction != nil && *p.GPUMemoryFraction > *f {
			return fmt.Sprintf("node.toml caps max_vram_fraction at %g and this asks for %g",
				*f, *p.GPUMemoryFraction)
		}
	}
	if n := c.Limits.MaxDeployments; n != nil && placed >= *n {
		return fmt.Sprintf("node.toml caps max_deployments at %d", *n)
	}
	return ""
}
