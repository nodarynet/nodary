package cli

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/nodarynet/nodary/internal/audit"
)

// TestNodeListNamesWhatAnOperatorMustActOn.
//
// A listing that only lists is half an answer. Each state asserted here is one
// an operator has to act on and none of them looks like an error: a pending
// node is idle and healthy, a stale one is indistinguishable from a quiet one,
// and a node that offers no GPU is what an agent that could not find
// `nvidia-smi` produces — which happened on this project's first real host and
// showed up only as every deployment being refused.
func TestNodeListNamesWhatAnOperatorMustActOn(t *testing.T) {
	a := newAppliance(t)
	a.enrolled("pending-box")
	a.enrolled("silent-box")
	a.enrolled("blind-box")

	now := time.Now().UTC()
	a.execSQL(fmt.Sprintf(
		`UPDATE node SET state = 'approved', last_seen = '%s', agent_version = '0.1.0',
		 offer_json = '{"gpus":[{"index":0,"name":"RTX 5090","memory_mib":32607}],"max_deployments":1}'
		 WHERE name = 'silent-box'`,
		now.Add(-5*time.Minute).Format(audit.TimeFormat)))
	a.execSQL(fmt.Sprintf(
		`UPDATE node SET state = 'approved', last_seen = '%s', agent_version = '0.1.0',
		 offer_json = '{"gpus":[],"max_deployments":1}' WHERE name = 'blind-box'`,
		now.Format(audit.TimeFormat)))

	code, stdout, stderr := a.run("node", "list")
	if code != ExitOK {
		t.Fatalf("exit = %d: %s", code, stderr)
	}
	for _, want := range []string{"pending-box", "silent-box", "blind-box", "NAME", "DEPLOYMENTS"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("stdout does not mention %q:\n%s", want, stdout)
		}
	}

	// The exact line the install tells an operator to run. It was a stub, and
	// `node list` — which is how you learn the name to pass it — was a stub too.
	if !strings.Contains(stderr, "nodary node approve pending-box") {
		t.Errorf("a pending node is not called out:\n%s", stderr)
	}
	if !strings.Contains(stderr, "silent-box has not reported") {
		t.Errorf("a stale node is not called out:\n%s", stderr)
	}
	if !strings.Contains(stderr, "blind-box offers no GPU") {
		t.Errorf("a node offering nothing is not called out:\n%s", stderr)
	}
	// Guidance is diagnostic and belongs on stderr, so `node list | column` is
	// still a table (docs/specs/10-cli.md §4).
	if strings.Contains(stdout, "nodary node approve") {
		t.Errorf("guidance leaked onto stdout:\n%s", stdout)
	}
}

// TestNodeShowExplainsWhyAModelIsNotServing.
//
// The question this verb exists to answer. Every fact needed to tell a model
// that is serving from one that is not — the deployment's state, its health, the
// port it published, and the route name a client actually asks for — was only
// reachable by opening the database.
func TestNodeShowExplainsWhyAModelIsNotServing(t *testing.T) {
	a := newAppliance(t)
	a.enrolled("fractal")
	now := time.Now().UTC().Format(audit.TimeFormat)
	a.execSQL(fmt.Sprintf(`UPDATE node SET state = 'approved', last_seen = '%s',
		agent_version = '0.1.0', protocol = 1, driver_version = '570.86.15',
		gpus_json = '[{"index":0,"name":"RTX 5090","memory_mib":32607}]',
		offer_json = '{"gpus":[{"index":0,"name":"RTX 5090","memory_mib":32607}],"max_deployments":2,"backends":["vllm"]}'
		WHERE name = 'fractal'`, now))
	a.execSQL(`INSERT INTO model (id, backend, source, artifact, created_at)
		VALUES ('org/small', 'vllm', 'local', 'hf-cache', '2026-09-08T00:00:00.000Z')`)
	a.execSQL(fmt.Sprintf(`INSERT INTO deployment
		(id, model_id, node_name, backend, port, state, health, created_at, updated_at)
		VALUES ('served', 'org/small', 'fractal', 'vllm', 8001, 'ready', 'healthy', '%s', '%s'),
		       ('orphan', 'org/small', 'fractal', 'vllm', 8002, 'ready', 'healthy', '%s', '%s')`,
		now, now, now, now))
	a.execSQL(`INSERT INTO deployment_gpu (deployment_id, node_name, gpu_index)
		VALUES ('served', 'fractal', 0)`)
	a.execSQL(`INSERT INTO route (name, created_at) VALUES ('small', '2026-09-08T00:00:00.000Z')`)
	a.execSQL(`INSERT INTO route_member (route_name, deployment_id) VALUES ('small', 'served')`)
	a.execSQL(`INSERT INTO staging (model_id, node_name, state, bytes_done, bytes_total, updated_at)
		VALUES ('org/small', 'fractal', 'staged', 1288490188, 1288490188, '2026-09-08T00:00:00.000Z')`)

	code, stdout, stderr := a.run("node", "show", "fractal")
	if code != ExitOK {
		t.Fatalf("exit = %d: %s", code, stderr)
	}
	// The route name is the one a client sends as `model`, so a deployment
	// listed without it says a model is ready while leaving nobody able to call
	// it.
	for _, want := range []string{"served", "small", "8001", "healthy", "org/small",
		"RTX 5090", "protocol 1", "570.86.15", "staged"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("stdout does not mention %q:\n%s", want, stdout)
		}
	}
	if !strings.Contains(stderr, "orphan is in no route") {
		t.Errorf("a deployment nothing routes to is not called out:\n%s", stderr)
	}
}

func TestNodeShowNamesTheVerbThatListsNodes(t *testing.T) {
	a := newAppliance(t)
	a.enrolled("fractal")
	code, _, stderr := a.run("node", "show", "nonesuch")
	if code != ExitFailure {
		t.Fatalf("exit = %d, want %d", code, ExitFailure)
	}
	if !strings.Contains(stderr, "nodary node list") {
		t.Errorf("the error does not say how to find the name:\n%s", stderr)
	}
}

func TestProgressAndSizeRendering(t *testing.T) {
	// The bug: a 999 MB model — most of them, in practice — rounded to one
	// decimal of a GiB figure smaller than one, and every staged deployment
	// showed its own byte count twice ("X / X") for a state that can't yet be
	// partial.
	for _, tc := range []struct {
		done, total int64
		want        string
	}{
		{500, 0, "500 B"},
		{999604126, 999604126, "953.3 MiB"},
		{999604126, 0, "953.3 MiB"},
		{2147483648, 2147483648, "2.0 GiB"},
		{1 << 20, 2 << 20, "1.0 MiB / 2.0 MiB"},
	} {
		if got := progress(tc.done, tc.total); got != tc.want {
			t.Errorf("progress(%d, %d) = %q, want %q", tc.done, tc.total, got, tc.want)
		}
	}
}
