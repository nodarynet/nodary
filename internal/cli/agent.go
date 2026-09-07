package cli

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/nodarynet/nodary/internal/agent"
	"github.com/nodarynet/nodary/internal/api"
)

// agentVerbs this release does not implement, listed rather than falling
// through to "unknown" for the reason nodeVerbs gives.
var agentVerbs = map[string]string{
	"run":    "the reconcile loop: staging, units, health (R4c)",
	"audit":  "the node's own audit records",
	"status": "what this node is running",
}

func cmdAgent(e env, args []string) int {
	if len(args) == 0 {
		fmt.Fprintf(e.stderr, "nodary agent: expected a subcommand (plan)\n")
		return ExitUsage
	}
	if args[0] == "plan" {
		return cmdAgentPlan(e, args[1:])
	}
	if what, ok := agentVerbs[args[0]]; ok {
		fmt.Fprintf(e.stderr, "nodary agent %s: %s is not implemented in this release (%s)\n",
			args[0], what, versionString())
		return ExitFailure
	}
	fmt.Fprintf(e.stderr, "nodary agent: unknown subcommand %q (want plan)\n", args[0])
	return ExitUsage
}

// cmdAgentPlan shows what this node would do with its current desired state,
// and does none of it.
//
// It exists because the reconcile loop is the part of this product an operator
// has least visibility into: a deployment that never starts is otherwise a
// container log on a GPU host. Rendering the decision separately from the acting
// means the answer to "why is nothing running" is one command, and it is the
// same code path that will run it.
func cmdAgentPlan(e env, args []string) int {
	fs := newFlagSet(e, "agent plan")
	confPath := fs.String("config", "", "agent.toml path")
	from := fs.String("from", "", "read the desired-state document from a file instead of the control plane")
	noVerify := fs.Bool("no-verify", false,
		"skip reading every staged byte; reports weights as unverified rather than staged")
	format := formatFlag(fs)
	if code := parseFlags(e, fs, args); code >= 0 {
		return code
	}
	if !checkFormat(e, *format) {
		return ExitUsage
	}

	confFile := orElse(*confPath, agent.ConfigPath())
	conf, err := agent.LoadConfig(confFile)
	if err != nil {
		fmt.Fprintf(e.stderr, "nodary agent plan: %v\n", err)
		if os.IsNotExist(err) {
			fmt.Fprintf(e.stderr, "  this host has not enrolled; run `nodary node enroll`\n")
		}
		return exitFor(err)
	}

	doc, err := desiredDocument(e, conf, *from)
	if err != nil {
		fmt.Fprintf(e.stderr, "nodary agent plan: %v\n", err)
		return exitFor(err)
	}

	// The offer, not the machine: the plan must refuse a GPU this node does not
	// advertise, so it is built against the same narrowing enrolment reported.
	// node.toml sits beside agent.toml, so a --config pointing somewhere else
	// finds the guardrails that go with it rather than the host's.
	guardrails, err := agent.LoadNodeConfig(filepath.Join(filepath.Dir(confFile), "node.toml"))
	if err != nil {
		fmt.Fprintf(e.stderr, "nodary agent plan: %v\n", err)
		return exitFor(err)
	}
	offer, _ := guardrails.Advertise(agent.LocalInventory(context.Background()).GPUs, agent.BackendNames())

	p, err := agent.Build(doc, agent.PlanOptions{
		ModelsDir: orElse(conf.ModelsDir, agent.DefaultModelsDir()),
		Present:   offer.GPUs,
		Verify:    !*noVerify,
	})
	if err != nil {
		fmt.Fprintf(e.stderr, "nodary agent plan: %v\n", err)
		return ExitFailure
	}

	if *format == "json" {
		return writeJSON(e, "agent plan", p)
	}
	renderPlan(e, p)
	// A refusal is a normal outcome and not a failure of this command, so the
	// exit code says the plan was produced. What it says about the fleet is in
	// the output.
	return ExitOK
}

func renderPlan(e env, p agent.Plan) {
	fmt.Fprintf(e.stdout, "node %s at revision %d\n", p.Node, p.Rev)

	fmt.Fprintf(e.stdout, "\nweights\n")
	if len(p.Stage) == 0 {
		fmt.Fprintf(e.stdout, "  (none)\n")
	}
	for _, s := range p.Stage {
		fmt.Fprintf(e.stdout, "  %-28s %-10s %s\n", s.Model, s.State, s.Reason)
	}

	fmt.Fprintf(e.stdout, "\nunits\n")
	if len(p.Units) == 0 {
		fmt.Fprintf(e.stdout, "  (none)\n")
	}
	for _, u := range p.Units {
		fmt.Fprintf(e.stdout, "  %s\n", u.Service)
		fmt.Fprintf(e.stdout, "    %s\n", u.EnvPath)
		for _, v := range u.Env {
			fmt.Fprintf(e.stdout, "      %s=%s\n", v.Key, v.Value)
		}
	}

	if len(p.Refused) > 0 {
		// Refusals last and never hidden: docs/specs/12-node-guardrails.md §1
		// makes a refusal something an operator sees rather than something the
		// system grinds against.
		fmt.Fprintf(e.stdout, "\nrefused\n")
		for _, r := range p.Refused {
			fmt.Fprintf(e.stdout, "  %-16s %s\n", r.Deployment, r.Reason)
		}
	}
}

// desiredDocument reads the document from the control plane, or from a file so
// the plan can be inspected on a host with no network.
func desiredDocument(e env, conf agent.Config, from string) (api.Desired, error) {
	var doc api.Desired
	if from != "" {
		body, err := os.ReadFile(from)
		if err != nil {
			return doc, err
		}
		if err := json.Unmarshal(body, &doc); err != nil {
			return doc, fmt.Errorf("%s is not a desired-state document: %w", from, err)
		}
		return doc, nil
	}

	pair, err := tls.LoadX509KeyPair(conf.Certificate, conf.Key)
	if err != nil {
		return doc, fmt.Errorf("loading this node's certificate: %w", err)
	}
	client, err := agent.Client(conf.CAFingerprint, &pair)
	if err != nil {
		return doc, err
	}
	// No `rev`, so the control plane answers at once rather than holding the
	// connection open for its long-poll window: this is a question, not a loop.
	resp, err := client.Get(strings.TrimRight(conf.Server, "/") + api.Prefix + "/agent/desired")
	if err != nil {
		return doc, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return doc, fmt.Errorf("the control plane returned %s: %s", resp.Status, strings.TrimSpace(string(body)))
	}
	err = json.NewDecoder(resp.Body).Decode(&doc)
	return doc, err
}
