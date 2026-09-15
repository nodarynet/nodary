package gateway_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nodarynet/nodary/internal/components"
	"github.com/nodarynet/nodary/internal/gateway"
)

// R3-04's real risk is not that the configuration is wrong in principle — it is
// that LiteLLM rejects it, and nothing here would know until an install.
//
// So this runs the pinned image from components.json against a configuration
// this package rendered, and asserts it starts and serves the route. It is the
// same digest a real install fetches, so a version bump that changes the schema
// fails here rather than on a customer's control plane.
func TestTheRealLiteLLMAcceptsTheGeneratedConfiguration(t *testing.T) {
	if testing.Short() {
		t.Skip("-short")
	}
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker is not installed")
	}
	image := pinnedLiteLLM(t)
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Second)
	defer cancel()
	if err := exec.CommandContext(ctx, "docker", "info").Run(); err != nil {
		t.Skip("docker is not usable by this user")
	}
	if err := exec.CommandContext(ctx, "docker", "image", "inspect", image).Run(); err != nil {
		t.Skipf("the pinned image is not present; `docker pull %s` to run this", image)
	}

	dir := t.TempDir()
	conf := gateway.LiteLLMConfig{
		MasterKey: "sk-nodary-test-master",
		Models: []gateway.LiteLLMModel{
			{Name: "acme/tiny", Model: "acme/tiny", APIBase: "http://127.0.0.1:9/v1"},
		},
	}
	body := conf.Render()
	// The same assertion the gateway makes before using a configuration.
	if err := gateway.AssertLoggingOff(body); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "litellm.yaml")
	if err := os.WriteFile(path, body, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}

	const name = "nodary-litellm-test"
	_ = exec.CommandContext(ctx, "docker", "rm", "-f", name).Run()
	run := exec.CommandContext(ctx, "docker", "run", "-d", "--name", name,
		"-p", "127.0.0.1:14999:4000", "-v", path+":/app/config.yaml:ro",
		image, "--config", "/app/config.yaml", "--port", "4000")
	if out, err := run.CombinedOutput(); err != nil {
		t.Skipf("cannot run the image here: %v\n%s", err, out)
	}
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", name).Run() })

	// It has to come up. A configuration LiteLLM rejects exits instead.
	var up bool
	for i := 0; i < 90 && !up; i++ {
		resp, err := http.Get("http://127.0.0.1:14999/health/liveliness")
		if err == nil {
			resp.Body.Close()
			up = resp.StatusCode == http.StatusOK
		}
		if !up {
			time.Sleep(time.Second)
		}
	}
	if !up {
		logs, _ := exec.Command("docker", "logs", name).CombinedOutput()
		t.Fatalf("LiteLLM did not start against the generated configuration:\n%s",
			tailLines(string(logs), 30))
	}

	// And it loaded the route, which proves the model_list shape is right
	// rather than merely parseable.
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://127.0.0.1:14999/v1/models", nil)
	req.Header.Set("Authorization", "Bearer "+conf.MasterKey)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var list struct {
		Data []struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(raw, &list); err != nil {
		t.Fatalf("models: %v\n%s", err, raw)
	}
	if len(list.Data) != 1 || list.Data[0].ID != "acme/tiny" {
		t.Errorf("LiteLLM loaded %s, want the one route the configuration named", raw)
	}

	// The master key is the only credential, and that is only meaningful if it
	// is also required: dev/specs/06-gateway.md §1 never exposes it to clients.
	bare, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://127.0.0.1:14999/v1/models", nil)
	if resp, err := http.DefaultClient.Do(bare); err == nil {
		resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			t.Error("LiteLLM served /v1/models without the master key")
		}
	}
}

// pinnedLiteLLM reads the digest out of the component manifest, so this test
// and a real install cannot disagree about which image is under test.
func pinnedLiteLLM(t *testing.T) string {
	t.Helper()
	m, err := components.Load()
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range m.ForPlatform("linux/amd64") {
		if c.Name != "litellm" {
			continue
		}
		p, ok := c.Platforms["linux/amd64"]
		if !ok || p.Image == "" {
			t.Fatal("the litellm component has no pinned image for linux/amd64")
		}
		return p.Image
	}
	t.Fatal("no litellm component in the manifest")
	return ""
}

func tailLines(s string, n int) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}

// fakeUpstream is an OpenAI-compatible responder, run from the LiteLLM image
// itself so this test pulls nothing of its own.
//
// In a container beside LiteLLM rather than on the host: a stand-in on the host
// has to be reached through host-gateway, which is a Docker-specific flag and a
// host firewall's business, and neither is what this test is about.
const fakeUpstream = `
import json, http.server
B = json.dumps({"id": "c1", "object": "chat.completion", "created": 0, "model": "acme/tiny",
    "choices": [{"index": 0, "message": {"role": "assistant", "content": "hi"},
                 "finish_reason": "stop"}],
    "usage": {"prompt_tokens": 3, "completion_tokens": 1, "total_tokens": 4}}).encode()
class H(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def do_POST(self):
        self.rfile.read(int(self.headers.get("Content-Length", 0)))
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(B)))
        self.end_headers()
        self.wfile.write(B)
    def log_message(self, *a): pass
http.server.ThreadingHTTPServer(("0.0.0.0", 8000), H).serve_forever()
`

// The deployment id in a usage row comes back from LiteLLM in a response
// header, and a header is a contract nobody promised us.
//
// So it is asserted against the pinned digest rather than assumed. `gateway
// sync` writes each route member's deployment id into `model_info.id`, and
// internal/gateway reads it back as `x-litellm-model-id` to say which node —
// and through deployment_gpu, which GPU — served a request. A version bump that
// drops the header, renames it, or stops honoring our id turns per-node
// chargeback silently back into NULLs, and nothing else in the tree would
// notice: every other test here supplies the header itself.
func TestLiteLLMReturnsTheDeploymentIdWeGaveIt(t *testing.T) {
	if testing.Short() {
		t.Skip("-short")
	}
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker is not installed")
	}
	image := pinnedLiteLLM(t)
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Second)
	defer cancel()
	if err := exec.CommandContext(ctx, "docker", "info").Run(); err != nil {
		t.Skip("docker is not usable by this user")
	}
	if err := exec.CommandContext(ctx, "docker", "image", "inspect", image).Run(); err != nil {
		t.Skipf("the pinned image is not present; `docker pull %s` to run this", image)
	}

	const (
		network    = "nodary-attribution-net"
		upstream   = "nodary-attribution-upstream"
		proxy      = "nodary-attribution-litellm"
		deployment = "dep_tiny_gpu01"
	)
	_ = exec.CommandContext(ctx, "docker", "rm", "-f", upstream, proxy).Run()
	_ = exec.CommandContext(ctx, "docker", "network", "rm", network).Run()
	if out, err := exec.CommandContext(ctx, "docker", "network", "create", network).CombinedOutput(); err != nil {
		t.Skipf("cannot create a docker network here: %v\n%s", err, out)
	}
	t.Cleanup(func() {
		_ = exec.Command("docker", "rm", "-f", upstream, proxy).Run()
		_ = exec.Command("docker", "network", "rm", network).Run()
	})

	if out, err := exec.CommandContext(ctx, "docker", "run", "-d", "--name", upstream,
		"--network", network, "--entrypoint", "python3", image, "-c", fakeUpstream,
	).CombinedOutput(); err != nil {
		t.Skipf("cannot run the stand-in upstream: %v\n%s", err, out)
	}

	conf := gateway.LiteLLMConfig{
		MasterKey: "sk-nodary-test-master",
		Models: []gateway.LiteLLMModel{{
			Name: "acme/tiny", Model: "acme/tiny", ID: deployment,
			APIBase: "http://" + upstream + ":8000/v1",
		}},
	}
	body := conf.Render()
	// The same assertion the gateway makes before using a configuration: a
	// model_info block must not have cost us the logging pins.
	if err := gateway.AssertLoggingOff(body); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "litellm.yaml")
	if err := os.WriteFile(path, body, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}

	if out, err := exec.CommandContext(ctx, "docker", "run", "-d", "--name", proxy,
		"--network", network, "-p", "127.0.0.1:14998:4000",
		"-v", path+":/app/config.yaml:ro", image,
		"--config", "/app/config.yaml", "--host", "0.0.0.0", "--port", "4000",
	).CombinedOutput(); err != nil {
		t.Skipf("cannot run the image here: %v\n%s", err, out)
	}

	var up bool
	for i := 0; i < 90 && !up; i++ {
		resp, err := http.Get("http://127.0.0.1:14998/health/liveliness")
		if err == nil {
			resp.Body.Close()
			up = resp.StatusCode == http.StatusOK
		}
		if !up {
			time.Sleep(time.Second)
		}
	}
	if !up {
		logs, _ := exec.Command("docker", "logs", proxy).CombinedOutput()
		t.Fatalf("LiteLLM did not start:\n%s", tailLines(string(logs), 30))
	}

	// Both shapes. A stream's headers go out before its body, so if the id did
	// not survive that path half the traffic would be unattributed.
	for _, stream := range []bool{false, true} {
		ask, err := json.Marshal(map[string]any{"model": "acme/tiny", "stream": stream,
			"messages": []any{map[string]any{"role": "user", "content": "hi"}}})
		if err != nil {
			t.Fatal(err)
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost,
			"http://127.0.0.1:14998/v1/chat/completions", bytes.NewReader(ask))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer "+conf.MasterKey)
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("stream=%v: %v", stream, err)
		}
		got := resp.Header.Get("X-Litellm-Model-Id")
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			logs, _ := exec.Command("docker", "logs", proxy).CombinedOutput()
			t.Fatalf("stream=%v: status %d\n%s", stream, resp.StatusCode, tailLines(string(logs), 40))
		}
		if got != deployment {
			t.Errorf("stream=%v: X-Litellm-Model-Id = %q, want the model_info.id this rendered (%q)",
				stream, got, deployment)
		}
	}
}
