package cli

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/nodarynet/nodary/internal/agent"
	"github.com/nodarynet/nodary/internal/audit"
	"github.com/nodarynet/nodary/internal/fleet"
	"github.com/nodarynet/nodary/internal/observed"
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
	server, credsPath := serverFlag(fs), credentialsFlag(fs)
	if code := parseFlags(e, fs, args); code >= 0 {
		return code
	}
	if !checkFormat(e, *format) {
		return ExitUsage
	}
	r, code := remoteFor(e, "node list", *server, *credsPath, *dbPath)
	if code >= 0 {
		return code
	}

	// Whichever way it was read, what comes back is []fleet.Node: the endpoint
	// calls fleet.Nodes too, precisely so the two front ends cannot disagree
	// about what a fleet looks like (R2-34). So everything below this is the
	// same rendering for both.
	now := time.Now()
	var nodes []fleet.Node
	var err error
	if r != nil {
		// Staleness is the control plane's clock rather than this laptop's,
		// which is the honest answer: it is derived from when *that* machine
		// last heard from the node.
		nodes, err = remoteList[fleet.Node](r, "/nodes", "nodes", nil)
	} else {
		path, _ := resolveDBIn(e, *dbPath)
		db, ok := openForReading(e, "node list", path)
		if !ok {
			return ExitFailure
		}
		defer db.Close()
		nodes, err = fleet.Nodes(context.Background(), db.Read(), now)
	}
	if err != nil {
		fmt.Fprintf(e.stderr, "nodary node list: %v\n", err)
		return exitFor(err)
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
		// Before the staleness line, because an incompatible node is *not*
		// stale — it keeps heartbeating throughout — and because it explains
		// the thing an operator would otherwise investigate: the node is up,
		// the agent is running, and nothing it is told to do is happening.
		case n.Incompatible:
			fmt.Fprintf(e.stderr,
				"\n%s speaks protocol %d and this control plane accepts %d-%d.\n"+
					"  It has stopped reconciling and is still running whatever was already up.\n"+
					"  On that host: nodary upgrade\n",
				n.Name, n.Protocol, fleet.ProtocolMin, fleet.ProtocolMax)
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
	server, credsPath := serverFlag(fs), credentialsFlag(fs)
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
	r, code := remoteFor(e, "node show", *server, *credsPath, *dbPath)
	if code >= 0 {
		return code
	}

	now := time.Now()
	var d fleet.Detail
	var err error
	if r != nil {
		err = r.do("GET", "/nodes/"+url.PathEscape(name), nil, &d)
	} else {
		path, _ := resolveDBIn(e, *dbPath)
		db, ok := openForReading(e, "node show", path)
		if !ok {
			return ExitFailure
		}
		defer db.Close()
		d, err = fleet.Show(context.Background(), db.Read(), name, now)
	}
	if errors.Is(err, sql.ErrNoRows) {
		fmt.Fprintf(e.stderr, "nodary node show: no node named %q; `nodary node list` names them\n", name)
		return ExitFailure
	}
	if err != nil {
		fmt.Fprintf(e.stderr, "nodary node show: %v\n", err)
		return exitFor(err)
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
		// The vendor is shown because it is what decides how the card is
		// reached, and a card whose name does not say which silicon it is —
		// every sysfs-enumerated one — would otherwise be unreadable here.
		fmt.Fprintf(tw, "%s\t%d: %s, %d MiB, %s%s\n", label, g.Index, g.Name, g.MemoryMiB,
			g.VendorName(), offeredSuffix(offer, g.Index))
	}
	row("offer", offerDetail(offer))
	// R4-25: a card this node offered and the driver no longer reports is a
	// GPU that has left the bus. Derived rather than stored, so it cannot go
	// stale: the offer is what the node declared at enrollment and `gpus` is
	// what it measured on its last heartbeat, and the two disagreeing is the
	// fact itself. Nothing reboots to clear it.
	if gone := offeredButAbsent(offer, gpus); len(gone) > 0 {
		row("gpu missing", joinInts(gone)+" — offered and not reported by the driver")
	}
	row("constraints", constraintDetail(constraints))
	row("certificate", certDetail(d.CertExpiresAt, now))
	row("approved", approvalDetail(d))
	if code := flush(e, "node show", tw); code != ExitOK {
		return code
	}
	if gone := offeredButAbsent(offer, gpus); len(gone) > 0 {
		fmt.Fprintf(e.stderr,
			"\n%s offers GPU %s and its driver no longer reports %s.\n"+
				"Deployments assigned to it are marked failed; nothing is rebooted to clear it.\n"+
				"Check `nvidia-smi` and `dmesg` on that host.\n",
			d.Name, joinInts(gone), pluralCard(gone))
	}

	if len(d.Deployments) > 0 {
		fmt.Fprintln(e.stdout)
		tw = tabwriter.NewWriter(e.stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "DEPLOYMENT\tMODEL\tROUTE\tSTATE\tHEALTH\tPORT\tGPUS\tEGRESS")
		for _, dep := range d.Deployments {
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
				dep.ID, dep.ModelID, orDash(strings.Join(dep.Routes, ",")),
				stateColumn(dep), dep.Health, portColumn(dep.Port), orDash(joinInts(dep.GPUs)),
				orDash(dep.Egress))
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
			if len(dep.Routes) == 0 && !dep.Disabled {
				fmt.Fprintf(e.stderr,
					"\n%s is in no route, so no client can ask for it by name.\n", dep.ID)
			}
			// Disabling stops the unit; it does not give the card back. The
			// deployment_gpu row stays, and 0006_fleet.sql's unique index means
			// nothing else can be placed on that index while it does — so an
			// operator who disabled a model to free a GPU is looking at a card
			// that is idle and still spoken for.
			if dep.Disabled && len(dep.GPUs) > 0 {
				fmt.Fprintf(e.stderr,
					"\n%s is disabled and still holds %s %s; `nodary model enable %s` "+
						"restarts it, and removing the deployment is what frees the card.\n",
					dep.ID, pluralCard(dep.GPUs), joinInts(dep.GPUs), dep.ModelID)
			}
			// docs/specs/11-failure-modes.md §3 makes a failing assertion a
			// critical alert, and the column above is a word in a table. This
			// is the line that says what it means: the isolation §5 requires
			// is the control keeping a model's weights and a customer's
			// prompts on this machine.
			switch dep.Egress {
			case fleet.EgressNonCompliant:
				fmt.Fprintf(e.stderr,
					"\n%s has a way off this box: %s\nIt is still serving. "+
						"docs/specs/03-agent.md §5 requires it not to.\n", dep.ID, dep.EgressReason)
			case fleet.EgressInconclusive:
				fmt.Fprintf(e.stderr,
					"\n%s could not be shown to be isolated: %s\n", dep.ID, dep.EgressReason)
			}
		}
	}

	// Refusals first among the follow-ups: a refused deployment is the one
	// an operator is most likely to be staring at, because it sits in
	// `defined` forever and every other column looks fine
	// (docs/specs/12-node-guardrails.md §1).
	var refused, outOfPolicy []fleet.Refusal
	for _, r := range d.Refusals {
		if r.Kind == observed.KindOutOfPolicy {
			outOfPolicy = append(outOfPolicy, r)
			continue
		}
		refused = append(refused, r)
	}

	if len(refused) > 0 {
		fmt.Fprintln(e.stdout)
		tw = tabwriter.NewWriter(e.stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "REFUSED\tREV\tREASON")
		for _, r := range refused {
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

	// Its own table, and not folded into the one above, because the operative
	// word is different: these are **running**. docs/specs/12-node-guardrails.md
	// §3 forbids killing a deployment a guardrail narrowed under, so nothing
	// here is stuck — something is serving outside the limits its own host now
	// declares, and closing that gap is a decision rather than a fix.
	if len(outOfPolicy) > 0 {
		fmt.Fprintln(e.stdout)
		tw = tabwriter.NewWriter(e.stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "OUT OF POLICY\tREV\tREASON")
		for _, r := range outOfPolicy {
			fmt.Fprintf(tw, "%s\t%d\t%s\n", r.DeploymentID, r.Rev, r.Reason)
		}
		if code := flush(e, "node show", tw); code != ExitOK {
			return code
		}
		fmt.Fprintf(e.stderr,
			"\nThe deployment(s) above are **still serving**. /etc/nodary/node.toml on %s was\n"+
				"narrowed under them, and nodary does not stop a running model because a file changed.\n"+
				"Either widen the limit again, or stop them deliberately with `nodary model disable`.\n", d.Name)
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
	if d.Incompatible {
		return fmt.Sprintf("%s, protocol %d — INCOMPATIBLE, this control plane accepts %d-%d",
			d.AgentVersion, d.Protocol, fleet.ProtocolMin, fleet.ProtocolMax)
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

// offeredButAbsent is the indices this node offers that its own driver no
// longer enumerates.
func offeredButAbsent(o agent.Offer, present []agent.GPU) []int {
	have := map[int]bool{}
	for _, g := range present {
		have[g.Index] = true
	}
	// A node that has never reported an inventory has not lost a card; it has
	// not checked in.
	if len(have) == 0 {
		return nil
	}
	var gone []int
	for _, g := range o.GPUs {
		if !have[g.Index] {
			gone = append(gone, g.Index)
		}
	}
	return gone
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

// stateColumn says why a deployment is stopped when the configuration is the
// reason.
//
// `stopped` alone is ambiguous in the way that matters: it is also what an
// operator's own `systemctl stop` produces and what a node that has not polled
// since the change still reports, so a deployment somebody turned off and one
// that fell over look the same in the one table they are both listed in.
func stateColumn(d fleet.Deployment) string {
	if d.Disabled {
		return d.State + " (disabled)"
	}
	return d.State
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

func pluralCard(idx []int) string {
	if len(idx) == 1 {
		return "it"
	}
	return "them"
}
