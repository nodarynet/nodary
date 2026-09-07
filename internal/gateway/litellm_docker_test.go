package gateway_test

import (
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
	// is also required: docs/specs/06-gateway.md §1 never exposes it to clients.
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
