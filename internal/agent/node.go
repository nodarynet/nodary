package agent

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/nodarynet/nodary/internal/paths"
)

// NodeConfig is /etc/nodary/node.toml: dev/specs/12-node-guardrails.md §2.
//
// These are not a consent boundary — you own both ends. They are safety rails
// against your own mistakes and against a control plane being operated by
// someone who has forgotten what else that machine does.
//
// **This slice parses the file and reports it, and enforces none of it.**
// Enforcement is R4-14 – R4-17, which dev/plans/mvp.md §6 lists as a gap with
// those task numbers. Reporting is not deferrable for the reason §4 gives: the
// limits are recorded in the node's approval, so an operator who offered three
// of four GPUs and was approved for four was shown terms they did not set.
//
// Every field is optional, and a file with no [limits] offers the whole machine.
// That is a real default and not an oversight, so the zero value of this struct
// has to mean it.
type NodeConfig struct {
	Limits Limits `toml:"limits"`
	Allow  Allow  `toml:"allow"`
	Window Window `toml:"window"`
}

type Limits struct {
	// GPUIndices is which cards are on offer. Nil means all of them; an empty
	// list means none, and the two are different answers. TOML tells them
	// apart, so this does not collapse them into one.
	GPUIndices      []int    `toml:"gpu_indices"`
	MaxVRAMFraction *float64 `toml:"max_vram_fraction"`
	MaxDeployments  *int     `toml:"max_deployments"`
}

type Allow struct {
	Backends         []string `toml:"backends"`
	PrepareJobs      *bool    `toml:"prepare_jobs"`
	PackageInstall   *bool    `toml:"package_install"`
	Reboot           *bool    `toml:"reboot"`
	AgentAutoUpgrade *bool    `toml:"agent_auto_upgrade"`
}

type Window struct {
	Maintenance string `toml:"maintenance"`
}

// NodeConfigPath is where node.toml lives.
func NodeConfigPath() string { return filepath.Join(paths.ConfigDir, "node.toml") }

// maintenancePattern is "sat 02:00-06:00 UTC" — the one form §2 gives.
//
// Validated at parse rather than at use because the file is edited by root on
// the node and nothing else reads it: a typo that is discovered when a
// maintenance window fails to open is a typo discovered at 2am on a Saturday.
var maintenancePattern = regexp.MustCompile(
	`^(?i)(mon|tue|wed|thu|fri|sat|sun) ([01]\d|2[0-3]):([0-5]\d)-([01]\d|2[0-3]):([0-5]\d) ([A-Z]{2,5})$`)

// LoadNodeConfig reads node.toml. A file that is not there is not an error: it
// means the whole machine is on offer, which §2 makes the right default for a
// dedicated GPU host.
func LoadNodeConfig(path string) (NodeConfig, error) {
	body, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return NodeConfig{}, nil
	}
	if err != nil {
		return NodeConfig{}, err
	}
	var c NodeConfig
	md, err := toml.Decode(string(body), &c)
	if err != nil {
		return NodeConfig{}, fmt.Errorf("%w: %s: %v", ErrBadConfig, path, err)
	}
	if u := md.Undecoded(); len(u) > 0 {
		keys := make([]string, len(u))
		for i, k := range u {
			keys[i] = k.String()
		}
		slices.Sort(keys)
		// Refused rather than ignored, and here that matters more than
		// elsewhere: an operator who misspells `gpu_indices` and is not told
		// believes a GPU is withheld that is in fact on offer.
		return NodeConfig{}, fmt.Errorf("%w: %s: unknown keys %s",
			ErrBadConfig, path, strings.Join(keys, ", "))
	}
	return c, c.Validate(path)
}

// Validate refuses a file whose limits could not be honoured.
func (c NodeConfig) Validate(path string) error {
	seen := map[int]bool{}
	for _, i := range c.Limits.GPUIndices {
		switch {
		case i < 0:
			return fmt.Errorf("%w: %s: gpu_indices holds %d; an index is not negative", ErrBadConfig, path, i)
		case seen[i]:
			return fmt.Errorf("%w: %s: gpu_indices lists %d twice", ErrBadConfig, path, i)
		}
		seen[i] = true
	}
	if f := c.Limits.MaxVRAMFraction; f != nil && (*f <= 0 || *f > 1) {
		return fmt.Errorf("%w: %s: max_vram_fraction %g is not a fraction of one card's memory",
			ErrBadConfig, path, *f)
	}
	if n := c.Limits.MaxDeployments; n != nil && *n < 0 {
		return fmt.Errorf("%w: %s: max_deployments %d is negative", ErrBadConfig, path, *n)
	}
	if w := c.Window.Maintenance; w != "" {
		if err := checkMaintenance(w); err != nil {
			return fmt.Errorf("%w: %s: %w", ErrBadConfig, path, err)
		}
	}
	return nil
}

// checkMaintenance holds a window to more than its shape.
//
// The zone is **resolved here**, not at use, for the reason maintenancePattern
// already gives: a window that silently never opens is a problem discovered at
// 2am on a Saturday. Measured, and the reason this is not merely defensive:
// Go's zone database resolves "EST", "CET" and "MST" and does not resolve
// "PST" or "AEST" -- so half the abbreviations an operator would reach for
// first are not zones at all, and without this they would parse, validate,
// advertise, and never match a single minute.
//
// A host with no zone database resolves "UTC" and nothing else, which is the
// right failure: the refusal names the problem instead of the window quietly
// never arriving.
func checkMaintenance(w string) error {
	m := maintenancePattern.FindStringSubmatch(w)
	if m == nil {
		return fmt.Errorf(`maintenance %q is not "sat 02:00-06:00 UTC"`, w)
	}
	if _, err := time.LoadLocation(strings.ToUpper(m[6])); err != nil {
		return fmt.Errorf("maintenance %q: %s is not a time zone this host knows; "+
			"UTC always resolves, and an abbreviation like PST does not", w, m[6])
	}
	if m[2]+m[3] == m[4]+m[5] {
		return fmt.Errorf("maintenance %q opens and closes at the same minute", w)
	}
	return nil
}

// MaintenanceOpen reports whether now falls inside the declared window.
//
// dev/specs/12-node-guardrails.md §3: a deployment a node.toml edit
// invalidated keeps serving and waits "for the control plane to withdraw it,
// **or for the next maintenance window**". This is that clock, and it is the
// whole of what the window does -- it never suppresses an action an operator
// asked for.
//
// **An absent window is never open**, which is exactly today's behavior: an
// out-of-policy deployment then waits for the control plane and nothing else.
// A node that declares no window has not asked for anything to be stopped on
// a schedule, and reading "no window" as "any time" would turn the safest
// configuration into the most disruptive one.
//
// A window whose end is before its start **wraps past midnight**: "sat
// 22:00-02:00" is Saturday evening and the small hours of Sunday, which is
// what somebody who wrote it means and the hours a maintenance window most
// often occupies.
func (c NodeConfig) MaintenanceOpen(now time.Time) bool {
	m := maintenancePattern.FindStringSubmatch(c.Window.Maintenance)
	if m == nil {
		return false
	}
	loc, err := time.LoadLocation(strings.ToUpper(m[6]))
	if err != nil {
		return false // refused at load; closed here rather than guessing a zone
	}
	day, ok := weekdays[strings.ToLower(m[1])]
	if !ok {
		return false
	}
	start, end := minuteOf(m[2], m[3]), minuteOf(m[4], m[5])

	local := now.In(loc)
	at := local.Hour()*60 + local.Minute()
	if start < end {
		return local.Weekday() == day && at >= start && at < end
	}
	return (local.Weekday() == day && at >= start) ||
		(local.Weekday() == (day+1)%7 && at < end)
}

var weekdays = map[string]time.Weekday{
	"sun": time.Sunday, "mon": time.Monday, "tue": time.Tuesday, "wed": time.Wednesday,
	"thu": time.Thursday, "fri": time.Friday, "sat": time.Saturday,
}

// minuteOf converts the pattern's own capture groups, which it has already
// held to two digits in range, so a parse here cannot fail.
func minuteOf(hh, mm string) int {
	h, _ := strconv.Atoi(hh)
	m, _ := strconv.Atoi(mm)
	return h*60 + m
}

// Offer is what this node advertises to the control plane:
// dev/specs/12-node-guardrails.md §4.
//
// A node reports what it is offering, not everything it has. A four-GPU host
// offering three appears as a three-GPU node, and the control plane will not
// place work on the fourth.
type Offer struct {
	GPUs           []GPU    `json:"gpus"`
	MaxDeployments int      `json:"max_deployments"`
	Backends       []string `json:"backends"`
}

// Constraints are the limits that are not about inventory, carried alongside
// the offer so that both are in the approval record.
type Constraints struct {
	PrepareJobs     bool    `json:"prepare_jobs"`
	PackageInstall  bool    `json:"package_install"`
	Reboot          bool    `json:"reboot"`
	Maintenance     string  `json:"maintenance"`
	MaxVRAMFraction float64 `json:"max_vram_fraction"`
}

// Advertise narrows what the machine has by what the file offers.
//
// The narrowing is the point. `present` is what the driver reported; the result
// is what the control plane is allowed to believe exists.
func (c NodeConfig) Advertise(present []GPU, backends []string) (Offer, Constraints) {
	offered := present
	if c.Limits.GPUIndices != nil {
		offered = nil
		for _, g := range present {
			if slices.Contains(c.Limits.GPUIndices, g.Index) {
				offered = append(offered, g)
			}
		}
	}
	if offered == nil {
		offered = []GPU{}
	}

	if c.Allow.Backends != nil {
		var kept []string
		for _, b := range backends {
			if slices.Contains(c.Allow.Backends, b) {
				kept = append(kept, b)
			}
		}
		backends = kept
	}
	if backends == nil {
		backends = []string{}
	}

	o := Offer{GPUs: offered, Backends: backends, MaxDeployments: len(offered)}
	if n := c.Limits.MaxDeployments; n != nil {
		o.MaxDeployments = *n
	}

	// The defaults are dev/specs/12-node-guardrails.md §2's example read the
	// other way round: an absent setting is permissive, because an absent
	// [allow] section offers the whole machine.
	k := Constraints{PrepareJobs: true, PackageInstall: true, Reboot: true,
		Maintenance: c.Window.Maintenance, MaxVRAMFraction: 1}
	for _, f := range []struct {
		set  *bool
		into *bool
	}{
		{c.Allow.PrepareJobs, &k.PrepareJobs},
		{c.Allow.PackageInstall, &k.PackageInstall},
		{c.Allow.Reboot, &k.Reboot},
	} {
		if f.set != nil {
			*f.into = *f.set
		}
	}
	if f := c.Limits.MaxVRAMFraction; f != nil {
		k.MaxVRAMFraction = *f
	}
	return o, k
}

// RenderNodeConfig writes the file `nodary node install` places.
func RenderNodeConfig(c NodeConfig) []byte {
	var b strings.Builder
	b.WriteString(`# nodary node guardrails: dev/specs/12-node-guardrails.md
#
# Every field is optional. This file with no [limits] section offers the whole
# machine, which is the right default for a dedicated GPU host.
#
# These are safety rails against your own mistakes -- you own both ends. Edit
# them as root; the control plane reads their contents and never writes them.

`)
	if c.Limits.GPUIndices != nil || c.Limits.MaxVRAMFraction != nil || c.Limits.MaxDeployments != nil {
		b.WriteString("[limits]\n")
		if c.Limits.GPUIndices != nil {
			fmt.Fprintf(&b, "gpu_indices       = [%s]\n", joinInts(c.Limits.GPUIndices))
		}
		if f := c.Limits.MaxVRAMFraction; f != nil {
			fmt.Fprintf(&b, "max_vram_fraction = %s\n", strconv.FormatFloat(*f, 'g', -1, 64))
		}
		if n := c.Limits.MaxDeployments; n != nil {
			fmt.Fprintf(&b, "max_deployments   = %d\n", *n)
		}
		b.WriteString("\n")
	}
	if c.Allow.Backends != nil {
		fmt.Fprintf(&b, "[allow]\nbackends = [%s]\n\n", joinQuoted(c.Allow.Backends))
	}
	if c.Window.Maintenance != "" {
		fmt.Fprintf(&b, "[window]\nmaintenance = %q\n", c.Window.Maintenance)
	}
	return []byte(b.String())
}

func joinInts(in []int) string {
	out := make([]string, len(in))
	for i, n := range in {
		out[i] = strconv.Itoa(n)
	}
	return strings.Join(out, ", ")
}

func joinQuoted(in []string) string {
	out := make([]string, len(in))
	for i, s := range in {
		out[i] = strconv.Quote(s)
	}
	return strings.Join(out, ", ")
}
