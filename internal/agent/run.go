package agent

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"math/rand"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/nodarynet/nodary/internal/api"
	"github.com/nodarynet/nodary/internal/buildinfo"
)

// Heartbeat and backoff bounds. docs/specs/03-agent.md §1 fixes the heartbeat
// at 15s, and docs/specs/11-failure-modes.md §1 asks for exponential backoff
// with jitter when the control plane is down.
const (
	HeartbeatInterval = 15 * time.Second
	backoffMin        = time.Second
	backoffMax        = 60 * time.Second
)

// Daemon is the reconcile loop of docs/specs/03-agent.md §3, running.
type Daemon struct {
	Config Config
	Node   NodeConfig
	Host   Host
	Log    *slog.Logger

	client    *http.Client
	health    *Health
	rev       int64
	backoff   time.Duration
	downloads *Downloader
	// last is the most recent plan, so the health poller has something to probe
	// between reconciles.
	last Plan
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
	return &Daemon{Config: conf, Node: node, Host: h, Log: log,
		client: client, health: NewHealth(), backoff: backoffMin,
		downloads: NewDownloader()}, nil
}

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

		// Reconcile forward, never replaying. docs/specs/11-failure-modes.md
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
	offer, _ := d.Node.Advertise(LocalInventory(ctx).GPUs, BackendNames())
	p, err := Build(doc, PlanOptions{
		ModelsDir:  orDefault(d.Config.ModelsDir, DefaultModelsDir()),
		ConfigDir:  d.Host.ConfigDir,
		Present:    offer.GPUs,
		WSL2:       IsWSL2(),
		CDIDevices: CDIDevices(ctx),
		Verify:     true,
		Downloads:  d.downloads,
	})
	if err != nil {
		d.Log.Error("agent", "detail", "planning: "+err.Error())
		return
	}
	d.last = p

	r := Reconcile(ctx, p, d.Host)
	for _, u := range r.Units {
		if u.Action != "" || u.Error != "" {
			d.Log.Info("agent", "deployment", u.Deployment, "state", u.State,
				"action", u.Action, "error", u.Error)
		}
		if u.Egress == nil {
			continue
		}
		// docs/specs/11-failure-modes.md §3: a failing egress verification
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
		// (docs/specs/12-node-guardrails.md §1), so it is logged every
		// iteration at a level an operator sees.
		d.Log.Warn("agent", "refused", ref.Deployment, "reason", ref.Reason)
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
	resp, err := d.client.Do(req)
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
	if doc.Protocol != 0 && doc.Protocol != api.Protocol {
		// R4-11: an agent outside the range stops reconciling and does not
		// guess. Returning an error here keeps whatever is running running,
		// because nothing stops a unit on this path.
		return doc, fmt.Errorf("the control plane speaks protocol %d and this agent speaks %d",
			doc.Protocol, api.Protocol)
	}
	return doc, nil
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

// report sends the status of docs/specs/03-agent.md §1.
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
	for _, u := range d.last.Units {
		s := byID[u.Deployment]
		body.Deployments = append(body.Deployments, api.StatusUnit{
			ID:     u.Deployment,
			State:  d.observedState(ctx, u, s.Health),
			Health: orDefault(s.Health, "unknown"),
			Error:  s.Error,
		})
	}
	for _, st := range d.last.Stage {
		// Total falls back to Bytes: `source: local` verification is
		// all-or-nothing and never sets Total, so there is nothing between
		// "not yet staged" (0) and "staged" (the full count) for a partial
		// figure to mean. `source: remote` sets both independently while a
		// download is in progress.
		total := st.Total
		if total == 0 {
			total = st.Bytes
		}
		body.Staging = append(body.Staging, api.StatusStaging{
			Model: st.Model, State: st.State, Error: st.Reason,
			BytesDone: st.Bytes, BytesTotal: total,
		})
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
	resp, err := d.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("the control plane returned %s", resp.Status)
	}
	return nil
}

// observedState asks systemd rather than reporting what the last reconcile
// intended. docs/specs/03-agent.md §3: the agent observes, it does not assume.
func (d *Daemon) observedState(ctx context.Context, u Unit, health string) string {
	if !d.Host.isActive(ctx, UnitName(u.Deployment)) {
		return "stopped"
	}
	// **Active is not ready.** docs/specs/03-agent.md §7 waits for `ready` and
	// counts ready replicas before allowing a rolling restart to proceed, so
	// `ready` has to mean *able to serve*. The unit is `Type=exec` and its
	// ExecStart is `nerdctl run`, which systemd calls active the moment the
	// binary is exec'd — while it is still pulling twenty gigabytes, and again
	// while the model server spends minutes loading weights.
	//
	// Reported as ready anyway, this told an operator a deployment was serving
	// when no container existed at all, and would let a rolling restart count a
	// still-pulling replica as the last live one.
	if health == "healthy" {
		return "ready"
	}
	return "starting"
}

// Backoff, with jitter. docs/specs/11-failure-modes.md §1 asks for both: the
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
