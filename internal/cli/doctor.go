package cli

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/nodarynet/nodary/internal/agent"
	"github.com/nodarynet/nodary/internal/api"
	"github.com/nodarynet/nodary/internal/preflight"
)

// cmdDoctor is docs/specs/10-cli.md §3: the diagnostic entry point, and the
// first thing to tell anyone to run.
//
// It is preflight plus the checks that need a running system, because they are
// one mechanism seen at two times — building them separately would give two
// answers to "is the driver new enough" depending on which verb was typed.
//
// It exits non-zero on any hard failure, and it runs egress verification here
// as well as after every deployment start: R5-18's own reasoning is that a
// control only checked at creation time is a control that drifts, and
// docs/plans/R4d-egress-isolation.md is what happens when that turns out to be
// literally true.
func cmdDoctor(e env, args []string) int {
	fs := newFlagSet(e, "doctor")
	format := formatFlag(fs)
	confPath := fs.String("config", "", "agent.toml path")
	role := fs.String("role", "", "node or server; default is whichever this host is configured as")
	if code := parseFlags(e, fs, args); code >= 0 {
		return code
	}
	if !checkFormat(e, *format) {
		return ExitUsage
	}

	ctx := context.Background()
	conf, haveAgent := loadAgentQuietly(orElse(*confPath, agent.ConfigPath()))

	which := preflight.Role(*role)
	if which == "" {
		which = preflight.RoleServer
		if haveAgent {
			which = preflight.RoleNode
		}
	}

	r := preflight.Run(ctx, preflight.Options{
		Role:      which,
		ModelsDir: orElse(conf.ModelsDir, agent.DefaultModelsDir()),
		DataDir:   dataDirOf(),
	})
	r.Checks = append(r.Checks, buildCheck())

	// The checks that need a running system. Skipped rather than failed when
	// this host has not enrolled: a control plane running `doctor` is not
	// broken for having no agent.toml.
	if haveAgent {
		r.Checks = append(r.Checks, certificateCheck(conf), controlPlaneCheck(ctx, conf))
		r.Checks = append(r.Checks, egressChecks(ctx, e)...)
	} else {
		r.Checks = append(r.Checks, preflight.Check{Name: "node", Level: preflight.LevelSkip,
			Detail: "this host has not enrolled; `nodary node enroll` to join a control plane"})
	}

	if *format == "json" {
		code := writeJSON(e, "doctor", map[string]any{"checks": r.Checks, "ok": r.OK()})
		if code != ExitOK {
			return code
		}
		if !r.OK() {
			return ExitFailure
		}
		return ExitOK
	}

	for _, c := range r.Checks {
		fmt.Fprintf(e.stdout, "%s %-18s %s\n", mark(c.Level), c.Name, c.Detail)
	}
	if !r.OK() {
		// A copy-pasteable summary: the point of `doctor` is that its output is
		// what somebody sends to whoever can help.
		fmt.Fprintf(e.stderr, "\n%d hard failure(s). nodary %s\n",
			len(r.Failures()), versionString())
		return ExitFailure
	}
	return ExitOK
}

func mark(l preflight.Level) string {
	switch l {
	case preflight.LevelOK:
		return "✔"
	case preflight.LevelWarn:
		return "⚠"
	case preflight.LevelFail:
		return "✘"
	}
	return "–"
}

func buildCheck() preflight.Check {
	return preflight.Check{Name: "binary", Level: preflight.LevelOK, Detail: versionString()}
}

// loadAgentQuietly reads agent.toml without complaining about its absence: a
// control plane legitimately has none.
func loadAgentQuietly(path string) (agent.Config, bool) {
	c, err := agent.LoadConfig(path)
	if err != nil {
		return agent.Config{}, false
	}
	return c, true
}

func dataDirOf() string {
	if c, err := api.LoadServerConfig(serverConfigPath("")); err == nil && c.DataDir != "" {
		return c.DataDir
	}
	return "/var/lib/nodary"
}

// certificateCheck reports how long this node's identity has left.
//
// docs/specs/02-enrollment.md §3 renews at two-thirds of lifetime, so a
// certificate inside the last third and not renewing is a node heading for a
// re-enrolment that needs an administrator.
func certificateCheck(conf agent.Config) preflight.Check {
	c := preflight.Check{Name: "certificate"}
	body, err := os.ReadFile(conf.Certificate)
	if err != nil {
		c.Level, c.Detail = preflight.LevelFail, "cannot read "+conf.Certificate+": "+err.Error()
		return c
	}
	block, _ := pem.Decode(body)
	if block == nil {
		c.Level, c.Detail = preflight.LevelFail, conf.Certificate+" is not PEM"
		return c
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		c.Level, c.Detail = preflight.LevelFail, "unparseable certificate: "+err.Error()
		return c
	}
	left := time.Until(cert.NotAfter)
	switch {
	case left <= 0:
		c.Level = preflight.LevelFail
		c.Detail = fmt.Sprintf("expired %s ago; this node must re-enroll with a fresh token", days(-left))
	case left < 30*24*time.Hour:
		// docs/specs/02-enrollment.md §3 renews at two-thirds of a 90-day
		// lifetime, so inside the last third and still here means renewal is
		// not happening — and past expiry needs an administrator.
		c.Level = preflight.LevelWarn
		c.Detail = fmt.Sprintf("valid, expires in %s and renewal has not happened", days(left))
	default:
		c.Level = preflight.LevelOK
		c.Detail = "valid, expires in " + days(left)
	}
	return c
}

// days renders a duration the way an operator thinks about a certificate.
// "2160h0m0s" is technically the same thing and nobody reads it that way.
func days(d time.Duration) string {
	n := int(d.Hours() / 24)
	if n == 1 {
		return "1 day"
	}
	return fmt.Sprintf("%d days", n)
}

// controlPlaneCheck reaches the control plane the way the agent does, and
// measures the clock against it.
//
// Clock skew is here rather than in preflight because it needs the other end:
// docs/specs/11-failure-modes.md §1 makes skew over 60s a hard failure, since
// it breaks both mTLS validity windows and audit ordering.
func controlPlaneCheck(ctx context.Context, conf agent.Config) preflight.Check {
	c := preflight.Check{Name: "control plane"}
	pair, err := tls.LoadX509KeyPair(conf.Certificate, conf.Key)
	if err != nil {
		c.Level, c.Detail = preflight.LevelFail, "loading this node's certificate: "+err.Error()
		return c
	}
	client, err := agent.Client(conf.CAFingerprint, &pair)
	if err != nil {
		c.Level, c.Detail = preflight.LevelFail, err.Error()
		return c
	}
	client.Timeout = 15 * time.Second

	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		strings.TrimRight(conf.Server, "/")+api.Prefix+"/agent/desired", nil)
	if err != nil {
		c.Level, c.Detail = preflight.LevelFail, err.Error()
		return c
	}
	sent := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		c.Level, c.Detail = preflight.LevelFail, "unreachable: "+err.Error()
		return c
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		c.Level, c.Detail = preflight.LevelFail,
			fmt.Sprintf("%s returned %s", conf.Server, resp.Status)
		return c
	}

	// The server's own Date header against this clock. Crude, and enough: 60s
	// is the threshold, and a round trip is milliseconds.
	if served, err := http.ParseTime(resp.Header.Get("Date")); err == nil {
		skew := served.Sub(sent).Abs()
		if skew > 60*time.Second {
			c.Level = preflight.LevelFail
			c.Detail = fmt.Sprintf("reachable, but the clock is %s from the control plane's; "+
				"over 60s breaks mTLS validity and audit ordering", skew.Round(time.Second))
			return c
		}
		c.Level = preflight.LevelOK
		c.Detail = fmt.Sprintf("reachable, protocol %d, clock skew %s",
			api.Protocol, skew.Round(time.Millisecond))
		return c
	}
	c.Level, c.Detail = preflight.LevelOK, fmt.Sprintf("reachable, protocol %d", api.Protocol)
	return c
}

// egressChecks asserts the isolation of every deployment this node is running.
//
// The same VerifyEgress the reconcile loop calls after a start. R5-18: a
// control that is only checked at creation time is a control that drifts, and
// docs/plans/R4d-egress-isolation.md found a runtime that would have made that
// literal — a resolver injected on the container's own loopback, invisible to
// any route check.
func egressChecks(ctx context.Context, e env) []preflight.Check {
	self, err := os.Executable()
	if err != nil {
		return []preflight.Check{{Name: "egress", Level: preflight.LevelWarn,
			Detail: "cannot locate this binary to run the probe: " + err.Error()}}
	}
	host := agent.RealHost("", "")

	units, err := agent.RunningDeployments(ctx, host)
	if err != nil {
		return []preflight.Check{{Name: "egress", Level: preflight.LevelSkip,
			Detail: "no container runtime on this host, so nothing is serving: " + err.Error()}}
	}
	if len(units) == 0 {
		return []preflight.Check{{Name: "egress", Level: preflight.LevelSkip,
			Detail: "no deployments are running"}}
	}

	out := make([]preflight.Check, 0, len(units))
	for _, id := range units {
		c := preflight.Check{Name: "egress: " + id}
		v, err := agent.VerifyEgress(ctx, host, id, self)
		switch {
		case err != nil:
			// An assertion that could not run has not passed.
			c.Level, c.Detail = preflight.LevelWarn, "could not be checked: "+err.Error()
		case v.State == agent.Compliant:
			c.Level, c.Detail = preflight.LevelOK, v.Reason
		case v.State == agent.Inconclusive:
			c.Level, c.Detail = preflight.LevelWarn, v.Reason
		default:
			c.Level, c.Detail = preflight.LevelFail, "ISOLATION BREACH — "+v.Reason
		}
		out = append(out, c)
	}
	return out
}
