package agent

import (
	"bytes"
	"context"
	cryptorand "crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"math/rand"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/nodarynet/nodary/internal/api"
	"github.com/nodarynet/nodary/internal/buildinfo"
)

// Heartbeat and backoff bounds. dev/specs/03-agent.md §1 fixes the heartbeat
// at 15s, and dev/specs/11-failure-modes.md §1 asks for exponential backoff
// with jitter when the control plane is down.
const (
	HeartbeatInterval = 15 * time.Second
	backoffMin        = time.Second
	backoffMax        = 60 * time.Second
)

// Daemon is the reconcile loop of dev/specs/03-agent.md §3, running.
type Daemon struct {
	Config Config
	Node   NodeConfig
	Host   Host
	Log    *slog.Logger

	// client is swapped when the certificate is renewed, and read by the
	// heartbeat goroutine on its own timer — so it is atomic where d.last and
	// the rest are plain fields the poll goroutine owns outright.
	client atomic.Pointer[http.Client]
	// renewAt is two thirds through the current certificate's life
	// (dev/specs/02-enrollment.md §3). Touched only from the poll goroutine.
	renewAt   time.Time
	health    *Health
	rev       int64
	backoff   time.Duration
	downloads *Downloader
	// builds runs the prepare phase (R6-06). One per daemon, like downloads,
	// because both track work that outlives a single reconcile.
	builds *Preparer
	// last is the most recent plan, so the health poller has something to probe
	// between reconciles.
	last Plan
	// restarting is the deployments this agent has cycled for `nodary model
	// restart` and has not yet reported done.
	//
	// **A restart is not done when the unit has been poked.** R4-22 rolls a
	// model's replicas one at a time and the control plane moves to the next
	// only when this one reports done, so reporting on the cycle would let the
	// next node stop its copy while this one was still starting — which is the
	// outage the roll exists to avoid. Readiness is something only the node can
	// see, so the waiting is here, and report() clears an entry when the
	// deployment it names is serving again.
	//
	// Handed between goroutines without a lock, the same way d.last already is:
	// reconcile writes it and report() reads it on its own 15s timer.
	restarting map[string]bool
	// events is the queue on its way into the control plane's chain (R4-10).
	// Nil is a Daemon nobody gave one to — `agent plan` and the tests — and
	// emitting into nil is a no-op rather than a panic, because an event is a
	// record of something that happened and must never be the reason the thing
	// stops happening.
	events *Events
	// reported is the last state and egress verdict put on the wire for each
	// deployment, so an event is emitted when one *changes* rather than every
	// fifteen seconds. A chain carrying the same line four times a minute is a
	// chain nobody reads.
	reported map[string]reportedState
	// lastRefused and lastOutOfPolicy are Reconcile's verdicts rather than
	// Build's. Build states which placements node.toml narrows out; only
	// Reconcile can tell an out-of-policy placement that is serving — left
	// alone per 12 §3 — from one that never started, which is an ordinary
	// refusal. d.last carries the plan, so these carry the part of the
	// Report that the plan alone cannot answer.
	lastRefused     []Refusal
	lastOutOfPolicy []Refusal
	// lastEgress is the most recent egress verdict reached for each deployment
	// still in the plan (R4-29, dev/specs/03-agent.md §5). Sticky rather than
	// per-iteration: the probe runs on a start and while a verdict is
	// inconclusive, not every cycle, so a converged node produces no new
	// verdict and would otherwise report nothing about isolation it has
	// already established. Replaced wholesale each reconcile, which is also
	// how a deployment that left the plan stops being reported.
	lastEgress map[string]EgressVerdict
	// upgrades remembers which target version this process already tried, so a
	// self-upgrade that cannot succeed is attempted once rather than every poll.
	upgrades upgrader
}

// NewDaemon prepares the loop. It does not start it.
func NewDaemon(conf Config, node NodeConfig, h Host, log *slog.Logger) (*Daemon, error) {
	pair, err := tls.LoadX509KeyPair(conf.Certificate, conf.Key)
	if err != nil {
		return nil, fmt.Errorf("loading this node's certificate: %w", err)
	}
	client, err := Client(conf.CAFingerprint, &pair)
	if err != nil {
		return nil, err
	}
	if log == nil {
		log = slog.Default()
	}
	d := &Daemon{Config: conf, Node: node, Host: h, Log: log,
		health: NewHealth(), backoff: backoffMin, downloads: NewDownloader(h),
		builds: &Preparer{Host: h},
		// Beside the node's own configuration rather than under the models
		// directory: this is state about the agent, and a `--purge-models`
		// uninstall must not take the record of what happened with it.
		events: NewEvents(filepath.Join(filepath.Dir(conf.Certificate), "events.ndjson"))}
	d.client.Store(client)
	// Wired here rather than by the caller: it needs the daemon's own pinned
	// client and its server address, which is exactly what a Host does not
	// have. A Host built for a test or for `agent plan` leaves it nil.
	d.Host.EnsureImage = d.ensureImage

	// A certificate that cannot be parsed is not fatal here: the pair loaded,
	// so this agent can still talk to the control plane. It simply never
	// renews, which `nodary doctor` reports as an expiry nobody is moving.
	if leaf, err := leafOf(&pair); err == nil {
		d.renewAt = renewalAt(leaf)
	} else {
		log.Warn("agent", "detail", "cannot read this node's certificate expiry, so it will not renew: "+err.Error())
	}
	return d, nil
}

// http is the current client. Every request goes through it rather than a
// stored field, so a renewal mid-flight is picked up by the next call.
func (d *Daemon) http() *http.Client { return d.client.Load() }

// Run reconciles until the context is cancelled.
//
// Two loops, not one. The long-poll blocks for up to sixty seconds waiting for
// the configuration to move, and health has to be sampled every ten seconds
// regardless — running them in one loop would mean either polling health once a
// minute or abandoning the long-poll, and the long-poll is what makes a
// configuration change take effect in a second rather than in fifteen.
func (d *Daemon) Run(ctx context.Context) error {
	go d.heartbeatLoop(ctx)

	for {
		if err := ctx.Err(); err != nil {
			return nil
		}
		doc, err := d.poll(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			d.Log.Error("agent", "detail", "polling the control plane: "+err.Error(),
				"retry_in", d.backoff.String())
			d.sleep(ctx, d.jittered())
			d.grow()
			continue
		}
		d.reset()
		d.renewIfDue(ctx)

		// Reconcile forward, never replaying. dev/specs/11-failure-modes.md
		// §1: the document is a complete end state, so there is nothing in a
		// revision this node missed that converging on the current one would
		// not already cover.
		d.reconcile(ctx, doc)
		d.rev = doc.Rev
	}
}

// ReconcileOnce plans and applies one document, for `agent run --once`.
func (d *Daemon) ReconcileOnce(ctx context.Context, doc api.Desired) { d.reconcile(ctx, doc) }

// reconcile plans and applies one document.
func (d *Daemon) reconcile(ctx context.Context, doc api.Desired) {
	detected := LocalInventory(ctx).GPUs
	offer, _ := d.Node.Advertise(detected, BackendNames())
	p, err := Build(doc, PlanOptions{
		ModelsDir:  orDefault(d.Config.ModelsDir, DefaultModelsDir()),
		ConfigDir:  d.Host.ConfigDir,
		Present:    offer.GPUs,
		Detected:   detected,
		Node:       d.Node,
		WSL2:       IsWSL2(),
		CDIDevices: CDIDevices(ctx),
		Verify:     true,
		Downloads:  d.downloads,
		Builds:     d.builds,
	})
	if err != nil {
		d.Log.Error("agent", "detail", "planning: "+err.Error())
		return
	}
	d.last = p

	// **After the plan, before reconciling.** A node that is about to become a
	// different version should not first start containers this one decided on
	// — and if the upgrade succeeds, this process is replaced and the reconcile
	// below belongs to the new binary. If it fails, nothing was torn down and
	// the reconcile runs as it always would.
	d.setTarget(doc.Agent.TargetVersion)
	d.selfUpgrade(ctx, doc.Agent.TargetVersion)

	r := Reconcile(ctx, p, d.Host)
	// report() runs on a separate goroutine (the heartbeat loop) and only
	// ever sees d.last — Reconcile's own Report is otherwise built, logged
	// and discarded right here, so RestartDone has nowhere to reach the next
	// heartbeat from unless it rides along on the same handoff.
	if d.restarting == nil {
		d.restarting = map[string]bool{}
	}
	for _, id := range r.RestartDone {
		d.restarting[id] = true
	}
	d.lastRefused, d.lastOutOfPolicy = r.Refused, r.OutOfPolicy
	d.lastEgress = carryEgress(d.lastEgress, r.Units)
	for _, u := range r.Units {
		if u.Action != "" || u.Error != "" {
			d.Log.Info("agent", "deployment", u.Deployment, "state", u.State,
				"action", u.Action, "error", u.Error)
		}
		if u.Egress == nil {
			continue
		}
		// dev/specs/11-failure-modes.md §3: a failing egress verification
		// marks the deployment non-compliant and raises a critical alert. It is
		// not silently left serving, and it is not quietly logged either.
		if u.Egress.State == Compliant {
			d.Log.Info("agent", "deployment", u.Deployment, "egress", u.Egress.State)
			continue
		}
		d.Log.Error("agent", "deployment", u.Deployment, "egress", u.Egress.State,
			"reason", u.Egress.Reason)
	}
	for _, name := range r.Stopped {
		d.Log.Info("agent", "stopped", name)
	}
	for _, ref := range r.Refused {
		// A refusal is a normal outcome and is reported rather than retried
		// (dev/specs/12-node-guardrails.md §1), so it is logged every
		// iteration at a level an operator sees.
		d.Log.Warn("agent", "refused", ref.Deployment, "reason", ref.Reason)
	}
	for _, f := range p.Failed {
		// Loud, and every cycle: dev/specs/11-failure-modes.md §2 says the
		// agent reports and nothing auto-reboots, so this line is the whole
		// alert and it has to keep saying so until somebody looks.
		d.Log.Error("agent", "failed", f.Deployment, "reason", f.Reason)
	}
	for _, v := range r.OutOfPolicy {
		// Louder than a refusal, not quieter: this one is **still serving**,
		// and the gap between what node.toml now allows and what is actually
		// running is the thing an operator has to close by hand.
		d.Log.Warn("agent", "out_of_policy", v.Deployment, "reason", v.Reason,
			"detail", "still running; node.toml narrowed under it and stopping it is yours to do")
	}
	for _, e := range r.Errors {
		d.Log.Error("agent", "detail", e)
	}
}

// poll blocks on the desired-state endpoint.
func (d *Daemon) poll(ctx context.Context) (api.Desired, error) {
	var doc api.Desired
	url := strings.TrimRight(d.Config.Server, "/") + api.Prefix + "/agent/desired"
	if d.rev > 0 {
		// Omitted on the first poll so the control plane answers at once;
		// supplied afterwards so it blocks until something changes.
		url += "?rev=" + strconv.FormatInt(d.rev, 10)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return doc, err
	}
	resp, err := d.http().Do(req)
	if err != nil {
		return doc, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return doc, fmt.Errorf("%s: %s", resp.Status, strings.TrimSpace(string(body)))
	}
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return doc, err
	}
	// R4-11: an agent outside the range stops reconciling and does not guess.
	// Returning an error here keeps whatever is running running, because
	// nothing stops a unit on this path — and the heartbeat is a separate
	// goroutine, so the node stays visible to the control plane throughout
	// rather than going quiet at the moment somebody needs to see it.
	if err := compatible(doc); err != nil {
		return doc, err
	}
	return doc, nil
}

// compatible checks this agent against the range the control plane advertises.
//
// **The range, not the number.** dev/specs/03-agent.md §4 has the server
// advertise a supported range precisely so that a rollout can happen: comparing
// against `doc.Protocol` alone would have every node in the fleet stop
// reconciling the moment the control plane was upgraded to a version that still
// accepts them. A control plane old enough to advertise no range is compared
// the old way, which is the only thing that can be done with what it said.
func compatible(doc api.Desired) error {
	if doc.ProtocolMax > 0 {
		if api.Protocol < doc.ProtocolMin || api.Protocol > doc.ProtocolMax {
			return fmt.Errorf("this agent speaks protocol %d and the control plane accepts %d-%d; "+
				"it is not reconciling and whatever is running stays running. Upgrade this node: "+
				"`nodary upgrade`", api.Protocol, doc.ProtocolMin, doc.ProtocolMax)
		}
		return nil
	}
	if doc.Protocol != 0 && doc.Protocol != api.Protocol {
		return fmt.Errorf("the control plane speaks protocol %d and this agent speaks %d",
			doc.Protocol, api.Protocol)
	}
	return nil
}

// heartbeatLoop reports inventory, unit states and health on a fixed cadence.
func (d *Daemon) heartbeatLoop(ctx context.Context) {
	health := time.NewTicker(HealthInterval)
	defer health.Stop()
	beat := time.NewTicker(HeartbeatInterval)
	defer beat.Stop()

	var latest []Status
	for {
		select {
		case <-ctx.Done():
			return
		case <-health.C:
			latest = d.health.Poll(ctx, d.last.Units)
		case <-beat.C:
			if err := d.report(ctx, latest); err != nil && ctx.Err() == nil {
				// Logged and not retried here: the next tick is fifteen seconds
				// away, and a node that is silent for two beats is `stale`,
				// which is the signal an operator should see.
				d.Log.Warn("agent", "detail", "heartbeat: "+err.Error())
			}
		}
	}
}

// report sends the status of dev/specs/03-agent.md §1.
func (d *Daemon) report(ctx context.Context, health []Status) error {
	byID := map[string]Status{}
	for _, s := range health {
		byID[s.Deployment] = s
	}

	inv := LocalInventory(ctx)
	offer, _ := d.Node.Advertise(inv.GPUs, BackendNames())
	inv.GPUs = offer.GPUs

	body := api.StatusReport{
		Protocol: api.Protocol, AgentVersion: buildinfo.Version,
		Rev: d.rev, Inventory: inv.raw(),
	}
	// Why this node is not the version the fleet targets, if it is not.
	// Reported every heartbeat rather than once, because the control plane's
	// view has to be the node's current state and not an event it might have
	// missed — the same rule Refused follows.
	if target := d.target(); target != "" && target != buildinfo.Version {
		body.UpgradeTarget = target
		if failure, tried := d.upgrades.result(target); tried {
			body.UpgradeError = failure
		}
	}
	// The build each unit is waiting on, if it has one (R6-06).
	built := map[string]Prepared{}
	for _, b := range d.last.Prepare {
		built[b.Deployment] = b
	}
	for _, u := range d.last.Units {
		s := byID[u.Deployment]
		state, detail := d.observedState(ctx, u, s)
		artifact := ""
		if b, needs := built[u.Deployment]; needs && b.State == StatePrepared {
			artifact = b.Key
		}
		v := d.lastEgress[u.Deployment]
		if restartFinished(d.restarting, u.Deployment, state) {
			body.RestartDone = append(body.RestartDone, u.Deployment)
		}
		d.noteChange(u.Deployment, state, detail, d.lastEgress[u.Deployment])
		body.Deployments = append(body.Deployments, api.StatusUnit{
			ID:     u.Deployment,
			State:  state,
			Health: orDefault(s.Health, "unknown"),
			Error:  detail,
			// dev/specs/11-failure-modes.md §3 makes a failing assertion a
			// critical alert; it was one on this node's journal alone, which
			// is the machine the operator is not looking at.
			Egress:       v.State,
			EgressReason: v.Reason,
			Artifact:     artifact,
		})
	}
	for _, st := range d.last.Stage {
		body.Staging = append(body.Staging, stagingStatus(st))
	}
	// A disabled deployment builds no Unit, so it is not in d.last.Units and
	// the loop above never mentions it — without this, its row in the
	// control plane's database would freeze at whatever it last reported
	// (possibly still "ready") forever, since observed.Heartbeat only
	// touches a deployment id the report actually names. Reported as
	// observed rather than assumed: Reconcile's stop runs synchronously
	// before this heartbeat fires, but "stopped" is what is checked for,
	// not what is asserted regardless.
	for _, id := range d.last.Disabled {
		body.Deployments = append(body.Deployments,
			disabledStatus(id, d.Host.isActive(ctx, UnitName(id))))
	}
	// R4-25: a deployment whose card has left the bus builds no Unit either, so
	// it would otherwise freeze at whatever it last reported — "ready", on a
	// GPU that is not there. 0006_fleet.sql pairs `failed` with a non-null
	// `last_error` in a CHECK, so the reason travels with it or the whole
	// heartbeat transaction fails, taking every other deployment's state with
	// it.
	for _, f := range d.last.Failed {
		body.Deployments = append(body.Deployments, failedStatus(f))
	}
	body.ResetDone = d.last.ResetDone

	// R4-15: what this node will not run, and why. Recomputed by Build every
	// cycle and reported every heartbeat — until now it reached the node's
	// own journal and stopped there, so the operator who could act on it saw
	// a deployment stuck in `defined` and no reason anywhere.
	// Reconcile's set, not Build's: an out-of-policy placement that never
	// started is a refusal and one that is serving is not, and d.last.Refused
	// predates that distinction being made.
	for _, ref := range d.lastRefused {
		body.Refused = append(body.Refused,
			api.StatusRefusal{Deployment: ref.Deployment, Reason: ref.Reason})
	}
	for _, v := range d.lastOutOfPolicy {
		body.OutOfPolicy = append(body.OutOfPolicy,
			api.StatusRefusal{Deployment: v.Deployment, Reason: v.Reason})
	}

	raw, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		strings.TrimRight(d.Config.Server, "/")+api.Prefix+"/agent/status", bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := d.http().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("the control plane returned %s", resp.Status)
	}

	// After the heartbeat, on the same timer and the same connection. A queue
	// with a timer of its own would be a second thing to reason about for no
	// benefit: an event that waits fifteen seconds to reach the chain is an
	// event that reached the chain.
	//
	// Its failure does not fail the heartbeat. A control plane that cannot
	// accept events can still be told what this node is running, and losing
	// the fleet view over a full audit sink would turn one degraded thing into
	// two.
	if err := d.deliverEvents(ctx); err != nil {
		d.Log.Warn("agent", "detail", "delivering events: "+err.Error())
	}
	return nil
}

// deliverEvents hands the control plane what this node has queued (R4-10).
//
// Nothing is removed until it has been accepted, and a partial acceptance
// removes exactly what was accepted: the control plane answers with a count
// rather than a status alone, so a chain that stopped taking records halfway
// through a batch does not cost the remainder.
func (d *Daemon) deliverEvents(ctx context.Context) error {
	if d.events == nil {
		return nil
	}
	batch := d.events.Take(time.Now())
	if len(batch) == 0 {
		return nil
	}
	raw, err := json.Marshal(api.EventBatch{Events: batch})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		strings.TrimRight(d.Config.Server, "/")+api.Prefix+"/agent/events", bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := d.http().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("the control plane returned %s", resp.Status)
	}
	var out struct {
		Accepted int `json:"accepted"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return fmt.Errorf("the control plane answered with something unreadable: %w", err)
	}
	d.events.Delivered(out.Accepted)
	if out.Accepted < len(batch) {
		return fmt.Errorf("%d of %d events were accepted", out.Accepted, len(batch))
	}
	return nil
}

// carryEgress is the verdict each deployment in the plan stands at now.
//
// The probe runs on a start and while an answer is inconclusive, not every
// cycle (reconcile.go), so a converged node produces no new verdict — and a
// node that reported only what this iteration found would report isolation
// once and then nothing, which the control plane cannot tell from a node that
// was never asked. So a deployment with no new answer keeps the last one.
//
// Built fresh from the current units rather than merged into the old map, so
// a deployment that left the plan stops being reported instead of standing as
// a verdict about something that is no longer there.
func carryEgress(prev map[string]EgressVerdict, units []UnitOutcome) map[string]EgressVerdict {
	out := make(map[string]EgressVerdict, len(units))
	for _, u := range units {
		if u.Egress != nil {
			out[u.Deployment] = *u.Egress
		} else if v, ok := prev[u.Deployment]; ok {
			out[u.Deployment] = v
		}
	}
	return out
}

// failedStatus is one deployment whose hardware has gone, rendered onto the
// wire (R4-25).
//
// The reason is not decoration. 0006_fleet.sql carries
// `CHECK (state <> 'failed' OR last_error IS NOT NULL)`, so a failure reported
// with nothing beside it fails the whole heartbeat transaction and takes every
// other deployment's state on the node down with it — which is why this never
// passes an empty Error through, whatever produced the Refusal.
func failedStatus(f Refusal) api.StatusUnit {
	reason := f.Reason
	if reason == "" {
		reason = "a GPU assigned to this deployment is no longer on this host's bus"
	}
	return api.StatusUnit{ID: f.Deployment, State: "failed", Health: "unknown", Error: reason}
}

// disabledStatus is one disabled deployment rendered onto the wire, as the
// true observed fact rather than an assumption: Reconcile's stop runs
// synchronously before this heartbeat fires, but "stopped" is what is
// checked for, never asserted regardless of what systemd actually reports.
func disabledStatus(id string, active bool) api.StatusUnit {
	state := "stopped"
	if active {
		state = "starting"
	}
	return api.StatusUnit{ID: id, State: state, Health: "unknown"}
}

// stagingStatus is one Stage rendered onto the wire. Total falls back to
// Bytes: `source: local` verification is all-or-nothing and never sets
// Total, so there is nothing between "not yet staged" (0) and "staged" (the
// full count) for a partial figure to mean. `source: remote` sets both
// independently while a download is in progress.
func stagingStatus(st Stage) api.StatusStaging {
	total := st.Total
	if total == 0 {
		total = st.Bytes
	}
	return api.StatusStaging{
		Model: st.Model, State: st.State, Error: st.Reason,
		BytesDone: st.Bytes, BytesTotal: total,
	}
}

// observedState asks systemd rather than reporting what the last reconcile
// intended. dev/specs/03-agent.md §3: the agent observes, it does not assume.
//
// It returns the detail to report alongside: the health probe's own error
// ordinarily, and for a failure the reason plus the tail of the unit's log,
// which dev/specs/11-failure-modes.md §2 asks for and 0006_fleet.sql's
// CHECK (state <> 'failed' OR last_error IS NOT NULL) requires.
func (d *Daemon) observedState(ctx context.Context, u Unit, s Status) (state, detail string) {
	// **Before systemd is believed.** A deployment whose engine is still
	// compiling has no unit started, so activeState reports `inactive` and the
	// switch below reads that as `stopped` — true of the unit, false of the
	// deployment, and it would tell an operator that a six-hour build had
	// quietly given up. dev/specs/04-backends.md §4's own state is what this
	// is: `preparing`, or `failed` carrying the builder's reason.
	for _, b := range d.last.Prepare {
		if b.Deployment != u.Deployment || b.State == StatePrepared {
			continue
		}
		if b.State == StateFailed {
			return "failed", b.Reason
		}
		return "preparing", b.Reason
	}
	switch d.Host.activeState(ctx, UnitName(u.Deployment)) {
	case "active":
	case "failed":
		// R4-21: systemd restarted it until the start limit in unit.go ran
		// out. Reported, never restarted from here — a crash-loop the agent
		// kept kicking would be the system grinding against a failure
		// instead of an operator seeing one. `nodary model restart` is the
		// explicit unstick, the same shape `restage` is for corrupt weights.
		return "failed", d.failureDetail(ctx, u, "systemd stopped restarting it after repeated failures")
	default:
		return "stopped", s.Error
	}
	// **Active is not ready.** dev/specs/03-agent.md §7 waits for `ready` and
	// counts ready replicas before allowing a rolling restart to proceed, so
	// `ready` has to mean *able to serve*. The unit is `Type=exec` and its
	// ExecStart is `nerdctl run`, which systemd calls active the moment the
	// binary is exec'd — while it is still pulling twenty gigabytes, and again
	// while the model server spends minutes loading weights.
	//
	// Reported as ready anyway, this told an operator a deployment was serving
	// when no container existed at all, and would let a rolling restart count a
	// still-pulling replica as the last live one.
	if s.Health == "healthy" {
		return "ready", ""
	}

	// R4-21, the other half: a deployment that never becomes ready is failed
	// at the backend's own ready_timeout_s (dev/specs/11-failure-modes.md
	// §2) rather than sitting in `starting` forever. Measured from the first
	// probe that went unanswered and cleared by the first that is answered,
	// so it means "has not served yet", not "is unwell now" — the latter is
	// `unhealthy`, which R4-20 already decides and which does not expire.
	if timeout := time.Duration(u.Probe.ReadyTimeoutS) * time.Second; timeout > 0 && s.Waiting > timeout {
		return "failed", d.failureDetail(ctx, u,
			fmt.Sprintf("never answered %s in the %s its backend allows", u.Probe.Health, timeout))
	}
	return "starting", s.Error
}

// failureDetail is why it failed plus the tail of the unit's log.
//
// dev/specs/11-failure-modes.md §2 asks for the last 100 lines, and
// 0006_fleet.sql's CHECK (state <> 'failed' OR last_error IS NOT NULL) makes
// a reason mandatory rather than merely nice: a `failed` reported with
// nothing beside it would fail the heartbeat's whole transaction. So the
// reason stands alone when the journal has nothing to add, and the log is
// bounded by tail() — an error message is evidence, a megabyte of one is a
// denial of service against the heartbeat.
func (d *Daemon) failureDetail(ctx context.Context, u Unit, why string) string {
	logs := d.Host.LogTail(ctx, UnitName(u.Deployment), 100)
	if logs == "" {
		return why
	}
	return why + "\n" + tail([]byte(logs))
}

// Backoff, with jitter. dev/specs/11-failure-modes.md §1 asks for both: the
// exponential part stops one node turning an outage into a second one, and the
// jitter stops a fleet retrying in lockstep and arriving together the moment
// the control plane comes back.
func (d *Daemon) grow() {
	d.backoff *= 2
	if d.backoff > backoffMax {
		d.backoff = backoffMax
	}
}

func (d *Daemon) reset() { d.backoff = backoffMin }

func (d *Daemon) jittered() time.Duration {
	// Full jitter: a uniform draw from [0, backoff). Anything narrower leaves
	// the fleet's retries correlated, which is the failure this exists for.
	if d.backoff <= 0 {
		return backoffMin
	}
	return time.Duration(rand.Int63n(int64(d.backoff)))
}

func (d *Daemon) sleep(ctx context.Context, dur time.Duration) {
	t := time.NewTimer(dur)
	defer t.Stop()
	select {
	case <-ctx.Done():
	case <-t.C:
	}
}

// restartFinished reports whether a restart this node performed is done, and
// forgets it once it is.
//
// **Done means serving, not cycled.** R4-22 rolls a model's replicas one at a
// time and the control plane offers the next only when this one is reported
// done — so answering yes on the cycle would let the next node stop its copy
// while this one was still starting, which is precisely the outage the roll
// exists to avoid. Readiness is something only the node can see, so the waiting
// is here and not on the control plane.
//
// A deployment that never comes back is never reported done, which is how 03 §7's
// "halt, leave remainder running" happens without anybody implementing it.
func restartFinished(restarting map[string]bool, deployment, state string) bool {
	if !restarting[deployment] || state != "ready" {
		return false
	}
	delete(restarting, deployment)
	return true
}

// reportedState is what was last put on the wire about one deployment.
type reportedState struct {
	state  string
	egress string
}

// noteChange emits an event when a deployment's state or its egress verdict
// moves, and says nothing while they hold.
//
// **Edge, not level.** The heartbeat already carries the level every fifteen
// seconds; what the chain has no way to show is the transition — a deployment
// that failed at 04:12, recovered at 04:19 and failed again at 04:31 looks,
// in a report of the current state, exactly like one that has been failed all
// along. dev/specs/11-failure-modes.md §3 makes a failing egress assertion a
// critical alert, and an alert that only exists while it is still true is one
// nobody can review afterwards.
//
// The first report of a deployment is not a change. A node restarting would
// otherwise write an event for everything it is already running, which is
// noise at exactly the moment somebody is reading the chain.
func (d *Daemon) noteChange(deployment, state, detail string, egress EgressVerdict) {
	if d.events == nil {
		return
	}
	if d.reported == nil {
		d.reported = map[string]reportedState{}
	}
	now := time.Now()
	was, seen := d.reported[deployment]
	d.reported[deployment] = reportedState{state: state, egress: egress.State}
	if !seen {
		return
	}

	if state != was.state && state == "failed" {
		d.events.Add(api.NodeEvent{
			ID: eventID(), At: now.UTC().Format(api.EventTimeFormat),
			Action: "node.deployment_failed", Target: deployment,
			Detail: map[string]any{"reason": detail, "from": was.state},
		})
	}
	// Every move of the egress verdict, in both directions. A breach that
	// cleared is the half an assessor most needs: it says the control was not
	// in force for a window, and when.
	if egress.State != "" && egress.State != was.egress {
		d.events.Add(api.NodeEvent{
			ID: eventID(), At: now.UTC().Format(api.EventTimeFormat),
			Action: "node.egress_" + strings.ReplaceAll(egress.State, "-", "_"),
			Target: deployment,
			Detail: map[string]any{"reason": egress.Reason, "from": orDefault(was.egress, "unasserted")},
		})
	}
}

// eventID is minted on the node so a re-delivered batch is recognisable as the
// same events rather than as new ones. Delivery is at-least-once and an
// append-only chain cannot retract a duplicate, so what it can do is make one
// identifiable.
func eventID() string {
	b := make([]byte, 8)
	if _, err := cryptorand.Read(b); err != nil {
		return ""
	}
	return "ev_" + hex.EncodeToString(b)
}
