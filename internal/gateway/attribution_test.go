package gateway_test

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/nodarynet/nodary/internal/audit"
	"github.com/nodarynet/nodary/internal/dataplane"
)

// addDeployment stands up the fleet rows a usage row is attributed through: a
// node, a model, a deployment of it, and the GPU it claimed.
func (f *fixture) addDeployment(id, modelID, node string, gpu int) {
	f.t.Helper()
	ctx := context.Background()
	now := time.Now().UTC().Format(audit.TimeFormat)
	if err := f.db.WriteTx(ctx, func(tx *sql.Tx) error {
		for _, stmt := range []struct {
			sql  string
			args []any
		}{
			// OR IGNORE: newFixture already places a node and a model, because
			// a route with no ready member behind it is a 503 now. A test
			// adding a second deployment on the same node is adding to that
			// fleet rather than describing a fresh one.
			{`INSERT OR IGNORE INTO node (name, state, created_at) VALUES (?, 'ready', ?)`, []any{node, now}},
			{`INSERT OR IGNORE INTO model (id, backend, source, artifact, created_at)
			  VALUES (?, 'vllm', 'local', '/srv/models/x', ?)`, []any{modelID, now}},
			{`INSERT INTO deployment (id, model_id, node_name, backend, state, created_at, updated_at)
			  VALUES (?, ?, ?, 'vllm', 'ready', ?, ?)`, []any{id, modelID, node, now, now}},
			{`INSERT INTO deployment_gpu (deployment_id, node_name, gpu_index) VALUES (?, ?, ?)`,
				[]any{id, node, gpu}},
		} {
			if _, err := tx.ExecContext(ctx, stmt.sql, stmt.args...); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		f.t.Fatal(err)
	}
}

// attribution reads the columns that say which machine did the work.
func (f *fixture) attribution() (deployment, node, model string, gpus []int) {
	f.t.Helper()
	ctx := context.Background()
	err := f.db.Read().QueryRowContext(ctx,
		`SELECT coalesce(deployment_id, ''), coalesce(node_name, ''), coalesce(model_id, '')
		 FROM usage ORDER BY ts DESC, id LIMIT 1`).Scan(&deployment, &node, &model)
	if err != nil {
		f.t.Fatal(err)
	}
	if deployment == "" {
		return deployment, node, model, nil
	}
	rows, err := f.db.Read().QueryContext(ctx,
		`SELECT gpu_index FROM deployment_gpu WHERE deployment_id = ? ORDER BY gpu_index`, deployment)
	if err != nil {
		f.t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var i int
		if err := rows.Scan(&i); err != nil {
			f.t.Fatal(err)
		}
		gpus = append(gpus, i)
	}
	return deployment, node, model, gpus
}

func completionWithModelID(id string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if id != "" {
			w.Header().Set("X-Litellm-Model-Id", id)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id": "chatcmpl-1", "object": "chat.completion", "model": "acme/tiny",
			"choices": []any{map[string]any{"index": 0, "finish_reason": "stop",
				"message": map[string]any{"role": "assistant", "content": "hi"}}},
			"usage": map[string]any{"prompt_tokens": 3, "completion_tokens": 1, "total_tokens": 4},
		})
	}
}

// The usage table has carried deployment_id and node_name since 0006_fleet.sql
// and the gateway populated neither, so per-node and per-GPU chargeback — most
// of what metering is for at this size — was not available from the data as
// recorded. A route may have several members and LiteLLM picks between them, so
// the only component that knows which deployment ran the request is LiteLLM;
// `gateway sync` writes our deployment id into model_info and it comes back on
// every response.
func TestAUsageRowNamesTheDeploymentNodeAndGPUThatServedIt(t *testing.T) {
	f := newFixture(t, completionWithModelID("dep_tiny_gpu01"))
	f.addDeployment("dep_tiny_gpu01", "acme/tiny-31b", "gpu-01", 3)

	resp, body := f.post("/v1/chat/completions", f.key,
		map[string]any{"model": "acme/tiny", "messages": []any{map[string]any{"role": "user", "content": "hi"}}})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d: %s", resp.StatusCode, body)
	}

	deployment, node, model, gpus := f.attribution()
	if deployment != "dep_tiny_gpu01" {
		t.Errorf("deployment_id = %q", deployment)
	}
	if node != "gpu-01" {
		t.Errorf("node_name = %q", node)
	}
	// The model id, not the route name. `model register` takes both and
	// nothing makes them equal, so recording the route in a model_id column
	// was recording the wrong string.
	if model != "acme/tiny-31b" {
		t.Errorf("model_id = %q, want the deployment's model", model)
	}
	if len(gpus) != 1 || gpus[0] != 3 {
		t.Errorf("gpus = %v, want [3] through deployment_gpu", gpus)
	}
}

// A response with no such header attributes nothing rather than guessing. A row
// naming a deployment that may not have run the request is worse than a row
// that names none: chargeback against the wrong GPU is a number somebody bills.
func TestAnUnattributedResponseClaimsNoDeployment(t *testing.T) {
	f := newFixture(t, completionWithModelID(""))
	f.addDeployment("dep_tiny_gpu01", "acme/tiny-31b", "gpu-01", 3)

	if resp, body := f.post("/v1/chat/completions", f.key,
		map[string]any{"model": "acme/tiny", "messages": []any{map[string]any{"role": "user", "content": "hi"}}}); resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d: %s", resp.StatusCode, body)
	}
	deployment, node, _, _ := f.attribution()
	if deployment != "" || node != "" {
		t.Errorf("deployment = %q, node = %q; both should be empty", deployment, node)
	}
}

// An id LiteLLM returns for a deployment this control plane does not have is
// recorded as given and resolved to nothing. Dropping it would lose the one
// clue that the two are out of step.
func TestAnUnknownDeploymentIsRecordedAndNotResolved(t *testing.T) {
	f := newFixture(t, completionWithModelID("dep_gone"))

	if resp, body := f.post("/v1/chat/completions", f.key,
		map[string]any{"model": "acme/tiny", "messages": []any{map[string]any{"role": "user", "content": "hi"}}}); resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d: %s", resp.StatusCode, body)
	}
	deployment, node, _, _ := f.attribution()
	if deployment != "dep_gone" {
		t.Errorf("deployment_id = %q, want the id as given", deployment)
	}
	if node != "" {
		t.Errorf("node_name = %q, want empty", node)
	}
}

// The rendered configuration is what makes the header carry our id, so the two
// halves are pinned together: a model_list entry without model_info gets an id
// LiteLLM invents, which resolves to no deployment here.
func TestTheRenderedConfigurationNamesEachDeployment(t *testing.T) {
	body := string(dataplane.LiteLLM.Render(dataplane.Config{MasterKey: "sk-test", Members: []dataplane.Member{
		{Name: "tiny", Model: "tiny", APIBase: "http://127.0.0.1:8000/v1", ID: "dep_tiny_gpu01"},
	}}))
	if !strings.Contains(body, "model_info:") || !strings.Contains(body, `id: "dep_tiny_gpu01"`) {
		t.Errorf("no model_info id in:\n%s", body)
	}

	// And omitted rather than written empty when there is no id: LiteLLM
	// rejects a model_info with no id, and a configuration it refuses is a
	// control plane that serves nothing.
	body = string(dataplane.LiteLLM.Render(dataplane.Config{MasterKey: "sk-test", Members: []dataplane.Member{
		{Name: "tiny", Model: "tiny", APIBase: "http://127.0.0.1:8000/v1"},
	}}))
	if strings.Contains(body, "model_info") {
		t.Errorf("model_info written with no id:\n%s", body)
	}
}
