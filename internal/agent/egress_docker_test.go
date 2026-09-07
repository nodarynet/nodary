package agent

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The assertion this whole slice exists for, against a real container rather
// than a namespace made by `unshare`.
//
// The configuration under test is the one docs/specs/03-agent.md §5 describes:
// a container on a host-local bridge with no default route. A route check calls
// that isolated. The probe does not, because docker injects a resolver at
// 127.0.0.11 on the container's own loopback — reachable without any route, and
// answering with live records.
//
// It runs against docker because that is what is installed here; containerd and
// nerdctl arrive with R5-04. The kernel primitives are the same, and what is
// being asserted is that the *probe* sees what is there — not that docker is
// how nodary will run this.
func TestTheProbeCatchesWhatARouteCheckMisses(t *testing.T) {
	if testing.Short() {
		t.Skip("-short")
	}
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker is not installed")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()
	if err := exec.CommandContext(ctx, "docker", "info").Run(); err != nil {
		t.Skip("docker is not usable by this user")
	}

	// A static binary, because the probe runs inside an image that promises
	// nothing — which is the reason it is a Go binary and not a shell script.
	probe := filepath.Join(t.TempDir(), "nodary")
	build := exec.CommandContext(ctx, "go", "build", "-C", "../..", "-o", probe, "./cmd/nodary")
	build.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("building the probe: %v\n%s", err, out)
	}

	const network = "nodary-egress-test"
	_ = exec.CommandContext(ctx, "docker", "network", "rm", network).Run()
	if out, err := exec.CommandContext(ctx, "docker", "network", "create",
		"--subnet", "10.88.42.0/24", network).CombinedOutput(); err != nil {
		t.Skipf("cannot create a docker network here: %v\n%s", err, out)
	}
	t.Cleanup(func() {
		_ = exec.Command("docker", "network", "rm", network).Run()
	})

	run := exec.CommandContext(ctx, "docker", "run", "--rm",
		"--network", network, "--cap-add", "NET_ADMIN",
		"-v", probe+":/nodary:ro", "alpine:3",
		"sh", "-c", "ip route del default; /nodary agent egress-probe --format json")
	out, err := run.CombinedOutput()
	if err != nil && len(out) == 0 {
		t.Skipf("cannot run a container here: %v", err)
	}

	var p EgressProbe
	if err := json.Unmarshal(trimToJSON(out), &p); err != nil {
		t.Fatalf("probe output: %v\n%s", err, out)
	}
	byName := map[string]Check{}
	for _, c := range p.Checks {
		byName[c.Name] = c
	}

	// The two a route check would rely on.
	if !byName[CheckRoute].Isolated {
		t.Fatalf("the container has a default route, so this is not the configuration "+
			"under test: %s", byName[CheckRoute].Detail)
	}
	if !byName[CheckConnect].Isolated {
		t.Errorf("connect = %q, want unreachable", byName[CheckConnect].Detail)
	}

	// And the one that decides whether this assertion is worth anything.
	if byName[CheckDNS].Isolated {
		t.Logf("DNS did not resolve in this container (%s). The runtime may no longer "+
			"inject a resolver; the check is still required, because nothing about "+
			"a missing route guarantees it.", byName[CheckDNS].Detail)
		return
	}

	t.Logf("as measured: %s", byName[CheckDNS].Detail)
	v := Judge("dep_one", p, RunEgressProbe(ctx))
	if v.State != NonCompliant {
		t.Errorf("verdict = %q, want non-compliant: a container that can resolve names "+
			"has a channel out, whatever its routing table says", v.State)
	}
	if !strings.Contains(v.Reason, CheckDNS) {
		t.Errorf("reason = %q, want it to name the DNS check", v.Reason)
	}
}

func trimToJSON(out []byte) []byte {
	s := string(out)
	i := strings.Index(s, "{")
	j := strings.LastIndex(s, "}")
	if i < 0 || j <= i {
		return out
	}
	return []byte(s[i : j+1])
}
