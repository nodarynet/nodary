package cli

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/nodarynet/nodary/internal/agent"
	"github.com/nodarynet/nodary/internal/audit"
	"github.com/nodarynet/nodary/internal/fleet"
)

// `node list` and `node show`: what the control plane knows about the fleet.
//
// **These were stubs, and their absence was the largest hole in the product.**
// Every other verb assumes the operator knows what is out there — `node
// approve` takes a name, `gateway sync` names a node it cannot reach, the
// install closes by telling somebody to approve a node — and there was no way
// to find out except reading TOML or opening the database. The first end-to-end
// deployment ran into it directly: the install said to run `nodary node
// approve <name>`, and `nodary node list`, which is how you learn the name,
// answered "not implemented in this release".
//
// They read the local database, the way `usage show` and `audit list` do, and
// through internal/fleet, which is also what the HTTP handlers call. There is
// no `--server`: reading a *remote* control plane needs a token and a pinned
// certificate, which is a different verb's problem and not the one an
// administrator sitting at the machine has.
func cmdNodeList(e env, args []string) int {
	fs := newFlagSet(e, "node list")
	format := formatFlag(fs)
	dbPath := dbFlag(fs)
	if code := parseFlags(e, fs, args); code >= 0 {
		return code
	}
	if !checkFormat(e, *format) {
		return ExitUsage
	}

	path, _ := resolveDBIn(e, *dbPath)
	db, ok := openForReading(e, "node list", path)
	if !ok {
		return ExitFailure
	}
	defer db.Close()

	now := time.Now()
	nodes, err := fleet.Nodes(context.Background(), db.Read(), now)
	if err != nil {
		fmt.Fprintf(e.stderr, "nodary node list: %v\n", err)
		return ExitFailure
	}

	if *format == "json" {
		return writeJSON(e, "node list", map[string]any{"nodes": nodes})
	}
	if len(nodes) == 0 {
		fmt.Fprintln(e.stdout, "no nodes enrolled")
		fmt.Fprintf(e.stderr,
			"\nA node joins by enrolling. Mint a token with `nodary token join`, then run\n"+
				"`nodary node install` on the GPU host.\n")
		return ExitOK
	}

	tw := tabwriter.NewWriter(e.stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "NAME\tSTATE\tSEEN\tAGENT\tGPUS\tDEPLOYMENTS")
	for _, n := range nodes {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n",
			n.Name, n.State, seenAge(n.LastSeen, now), orDash(n.AgentVersion),
			gpuColumn(n), deploymentColumn(n))
	}
	if code := flush(e, "node list", tw); code != ExitOK {
		return code
	}
	// **A listing that only lists is half an answer.** Every state below is one
	// an operator has to act on and none of them is visible as an error: a
	// pending node is idle and healthy, a stale one looks exactly like a quiet
	// one, and a node offering nothing is the shape of an agent that could not
	// find `nvidia-smi` — which happened here, and cost an afternoon.
	for _, n := range nodes {
		switch {
		case n.State == "pending":
			fmt.Fprintf(e.stderr,
				"\n%s is pending and will receive no work until\n  nodary node approve %s\n",
				n.Name, n.Name)
		case n.State == "departed":
		case n.Stale:
			fmt.Fprintf(e.stderr,
				"\n%s has not reported in %s. On that host: systemctl status nodary-agent\n",
				n.Name, seenAge(n.LastSeen, now))
		case offeredGPUs(n) == 0:
			fmt.Fprintf(e.stderr,
				"\n%s offers no GPU, so nothing can be placed on it. On that host: nodary doctor\n",
				n.Name)
		}
	}
	return ExitOK
}

func cmdNodeShow(e env, args []string) int {
	fs := newFlagSet(e, "node show")
	format := formatFlag(fs)
	dbPath := dbFlag(fs)
	if code := parseFlags(e, fs, args); code >= 0 {
		return code
	}
	if !checkFormat(e, *format) {
		return ExitUsage
	}
	if fs.NArg() != 1 {
		fmt.Fprintf(e.stderr, "nodary node show: expected one node name\n")
		return ExitUsage
	}
	name := fs.Arg(0)

	path, _ := resolveDBIn(e, *dbPath)
	db, ok := openForReading(e, "node show", path)
	if !ok {
		return ExitFailure
	}
	defer db.Close()

	now := time.Now()
	d, err := fleet.Show(context.Background(), db.Read(), name, now)
	if errors.Is(err, sql.ErrNoRows) {
		fmt.Fprintf(e.stderr, "nodary node show: no node named %q; `nodary node list` names them\n", name)
		return ExitFailure
	}
	if err != nil {
		fmt.Fprintf(e.stderr, "nodary node show: %v\n", err)
		return ExitFailure
	}

	if *format == "json" {
		return writeJSON(e, "node show", d)
	}

	var offer agent.Offer
	_ = json.Unmarshal(d.Offer, &offer)
	var constraints agent.Constraints
	_ = json.Unmarshal(d.Constraints, &constraints)

	tw := tabwriter.NewWriter(e.stdout, 0, 0, 2, ' ', 0)
	row := func(label, value string) { fmt.Fprintf(tw, "%s\t%s\n", label, orDash(value)) }
	row("name", d.Name)
	row("state", d.State)
	row("last seen", seenDetail(d.LastSeen, now))
	row("agent", agentDetail(d))
	row("host", hostDetail(d))

	// The hardware, then the narrowing of it. An offer smaller than the
	// inventory is the node's own guardrails at work
	// (docs/specs/12-node-guardrails.md §2), and it is otherwise invisible: the
	// deployment is simply refused with nothing saying which side refused it.
	gpus := gpuList(d.GPUs)
	if len(gpus) == 0 {
		row("gpus", "none reported")
	}
	for i, g := range gpus {
		label := ""
		if i == 0 {
			label = "gpus"
		}
		fmt.Fprintf(tw, "%s\t%d: %s, %d MiB%s\n", label, g.Index, g.Name, g.MemoryMiB,
			offeredSuffix(offer, g.Index))
	}
	row("offer", offerDetail(offer))
	row("constraints", constraintDetail(constraints))
	row("certificate", certDetail(d.CertExpiresAt, now))
	row("approved", approvalDetail(d))
	if code := flush(e, "node show", tw); code != ExitOK {
		return code
	}

	if len(d.Deployments) > 0 {
		fmt.Fprintln(e.stdout)
		tw = tabwriter.NewWriter(e.stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "DEPLOYMENT\tMODEL\tROUTE\tSTATE\tHEALTH\tPORT\tGPUS")
		for _, dep := range d.Deployments {
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
				dep.ID, dep.ModelID, orDash(strings.Join(dep.Routes, ",")),
				dep.State, dep.Health, portColumn(dep.Port), orDash(joinInts(dep.GPUs)))
		}
		if code := flush(e, "node show", tw); code != ExitOK {
			return code
		}
		for _, dep := range d.Deployments {
			if dep.LastError != "" {
				fmt.Fprintf(e.stderr, "\n%s: %s\n", dep.ID, dep.LastError)
			}
			// A deployment nothing routes to is reachable by nobody: LiteLLM
			// serves route names, so a ready container with no route is a model
			// that answers 404 to every client asking for it by any name.
			if len(dep.Routes) == 0 {
				fmt.Fprintf(e.stderr,
					"\n%s is in no route, so no client can ask for it by name.\n", dep.ID)
			}
		}
	}

	// Refusals first among the follow-ups: a refused deployment is the one
	// an operator is most likely to be staring at, because it sits in
	// `defined` forever and every other column looks fine
	// (docs/specs/12-node-guardrails.md §1).
	if len(d.Refusals) > 0 {
		fmt.Fprintln(e.stdout)
		tw = tabwriter.NewWriter(e.stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "REFUSED\tREV\tREASON")
		for _, r := range d.Refusals {
			fmt.Fprintf(tw, "%s\t%d\t%s\n", r.DeploymentID, r.Rev, r.Reason)
		}
		if code := flush(e, "node show", tw); code != ExitOK {
			return code
		}
		fmt.Fprintf(e.stderr,
			"\n%s will not run the deployment(s) above and is not retrying them.\n"+
				"Fix what the reason names — the node's own limits are in /etc/nodary/node.toml on that host —\n"+
				"or remove the deployment with `nodary config apply --prune`.\n", d.Name)
	}

	if len(d.Staging) > 0 {
		fmt.Fprintln(e.stdout)
		tw = tabwriter.NewWriter(e.stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "MODEL\tSTAGING\tPROGRESS")
		for _, st := range d.Staging {
			fmt.Fprintf(tw, "%s\t%s\t%s\n", st.ModelID, st.State,
				progress(st.BytesDone, st.BytesTotal))
		}
		if code := flush(e, "node show", tw); code != ExitOK {
			return code
		}
		for _, st := range d.Staging {
			if st.Error != "" {
				fmt.Fprintf(e.stderr, "\n%s: %s\n", st.ModelID, st.Error)
			}
		}
	}
	return ExitOK
}

// --- rendering ---------------------------------------------------------------

// seenAge is how long ago, in the largest unit that is still honest. An exact
// timestamp is in `node show`; a listing wants to be scannable.
func seenAge(lastSeen string, now time.Time) string {
	if lastSeen == "" {
		return "never"
	}
	ts, err := time.Parse(audit.TimeFormat, lastSeen)
	if err != nil {
		return lastSeen
	}
	d := now.Sub(ts)
	switch {
	case d < 0:
		// A node whose clock runs ahead. Reported rather than rendered as a
		// negative age, because clock skew is itself a thing to fix.
		return "ahead"
	case d < time.Minute:
		return strconv.Itoa(int(d.Seconds())) + "s"
	case d < time.Hour:
		return strconv.Itoa(int(d.Minutes())) + "m"
	case d < 24*time.Hour:
		return strconv.Itoa(int(d.Hours())) + "h"
	}
	return strconv.Itoa(int(d.Hours()/24)) + "d"
}

func seenDetail(lastSeen string, now time.Time) string {
	if lastSeen == "" {
		return "never"
	}
	s := seenAge(lastSeen, now) + " ago (" + lastSeen + ")"
	if fleet.Stale(lastSeen, now) {
		s += " — stale"
	}
	return s
}

func agentDetail(d fleet.Detail) string {
	if d.AgentVersion == "" {
		return ""
	}
	if d.Protocol == 0 {
		return d.AgentVersion
	}
	return fmt.Sprintf("%s, protocol %d", d.AgentVersion, d.Protocol)
}

func hostDetail(d fleet.Detail) string {
	parts := []string{}
	if d.OS != "" && d.Arch != "" {
		parts = append(parts, d.OS+"/"+d.Arch)
	}
	if d.DriverVersion != "" {
		parts = append(parts, "driver "+d.DriverVersion)
	}
	return strings.Join(parts, ", ")
}

// certDetail says when the node's certificate stops being accepted, because
// that is also when it may re-enroll under the same name
// (docs/specs/02-enrollment.md §3) — and an expired one explains a node that
// went silent without anything else being wrong.
func certDetail(expires string, now time.Time) string {
	if expires == "" {
		return "unknown, which refuses re-enrollment"
	}
	ts, err := time.Parse(audit.TimeFormat, expires)
	if err != nil {
		return expires
	}
	if d := ts.Sub(now); d > 0 {
		return fmt.Sprintf("expires %s (in %dd)", expires, int(d.Hours()/24))
	}
	return fmt.Sprintf("EXPIRED %s", expires)
}

func approvalDetail(d fleet.Detail) string {
	switch {
	case d.ApprovedAt == "" && d.State == "pending":
		return "not yet; nodary node approve " + d.Name
	case d.ApprovedAt == "":
		// A console approval leaves both columns NULL by design: local root is
		// a principal without a user row, and the chain carries who and when.
		return "at the console; `nodary audit list --action node.approve` has who and when"
	}
	return d.ApprovedAt + " by " + orDash(d.ApprovedBy)
}

func offerDetail(o agent.Offer) string {
	parts := []string{fmt.Sprintf("%d %s", len(o.GPUs), plural("gpu", len(o.GPUs)))}
	if o.MaxDeployments > 0 {
		parts = append(parts, fmt.Sprintf("max %d %s",
			o.MaxDeployments, plural("deployment", o.MaxDeployments)))
	}
	if len(o.Backends) > 0 {
		parts = append(parts, "backends "+strings.Join(o.Backends, ", "))
	}
	return strings.Join(parts, ", ")
}

func constraintDetail(c agent.Constraints) string {
	parts := []string{}
	if c.Maintenance != "" {
		parts = append(parts, "maintenance "+c.Maintenance)
	}
	if c.MaxVRAMFraction > 0 {
		parts = append(parts, fmt.Sprintf("max vram %.2f", c.MaxVRAMFraction))
	}
	for _, f := range []struct {
		on   bool
		name string
	}{{c.PrepareJobs, "prepare jobs"}, {c.PackageInstall, "package install"}, {c.Reboot, "reboot"}} {
		if f.on {
			parts = append(parts, f.name+" allowed")
		}
	}
	return strings.Join(parts, ", ")
}

func gpuList(raw json.RawMessage) []agent.GPU {
	var gpus []agent.GPU
	_ = json.Unmarshal(raw, &gpus)
	return gpus
}

func offeredGPUs(n fleet.Node) int {
	var o agent.Offer
	_ = json.Unmarshal(n.Offer, &o)
	return len(o.GPUs)
}

// offeredSuffix marks a card the node has and does not offer.
func offeredSuffix(o agent.Offer, index int) string {
	for _, g := range o.GPUs {
		if g.Index == index {
			return ""
		}
	}
	return " (not offered)"
}

func gpuColumn(n fleet.Node) string {
	offered := offeredGPUs(n)
	present := len(gpuList(n.GPUs))
	if present > offered {
		return fmt.Sprintf("%d of %d", offered, present)
	}
	return strconv.Itoa(offered)
}

func deploymentColumn(n fleet.Node) string {
	if n.DeploymentCount == 0 {
		return "-"
	}
	return fmt.Sprintf("%d/%d ready", n.ReadyCount, n.DeploymentCount)
}

func portColumn(port int) string {
	if port == 0 {
		return "-"
	}
	return strconv.Itoa(port)
}

func joinInts(v []int) string {
	parts := make([]string, len(v))
	for i, n := range v {
		parts[i] = strconv.Itoa(n)
	}
	return strings.Join(parts, ",")
}

// progress renders staging bytes. `source: local` verification is
// all-or-nothing (R4-33's remote staging is what would ever make done and
// total differ), so today's done always equals total once staged, and
// showing "0.9 GiB / 0.9 GiB" would say the same number twice for every
// deployment that exists — collapsed to one figure until there is a real
// partial state to report.
func progress(done, total int64) string {
	if total <= 0 || done == total {
		return size(done)
	}
	return fmt.Sprintf("%s / %s", size(done), size(total))
}

// size renders a byte count at whichever unit keeps it readable. Most model
// weights fall in the hundreds of megabytes, and a bare GiB tier rounds that
// range to one decimal digit of a number smaller than one — "0.9 GiB" for a
// 999 MB model — which is worse than just naming the unit that fits.
func size(b int64) string {
	switch {
	case b < 1<<20:
		return fmt.Sprintf("%d B", b)
	case b < 1<<30:
		return fmt.Sprintf("%.1f MiB", float64(b)/(1<<20))
	default:
		return fmt.Sprintf("%.1f GiB", float64(b)/(1<<30))
	}
}
