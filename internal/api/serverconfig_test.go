package api

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// server.toml is where the data plane is chosen (dev/specs/06-gateway.md §7),
// and a typo there must not be the difference between the posture an operator
// configured and one nodary picked for them.
func TestAnUnknownDataPlaneIsRefusedAndAnAbsentOneIsNot(t *testing.T) {
	write := func(t *testing.T, body string) string {
		t.Helper()
		path := filepath.Join(t.TempDir(), "server.toml")
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}

	// Absent: every install that predates the key runs LiteLLM, and it must
	// keep loading and keep running it.
	c, err := LoadServerConfig(write(t, "bind = \"0.0.0.0:8443\"\ndata_dir = \"/var/lib/nodary\"\n"))
	if err != nil {
		t.Fatalf("a server.toml with no data_plane must load: %v", err)
	}
	if c.DataPlane != "" {
		t.Errorf("data_plane = %q, want empty", c.DataPlane)
	}

	// Named: what the file says is what comes back, so `gateway sync`,
	// `upgrade` and `status` all read one answer.
	c, err = LoadServerConfig(write(t,
		"bind = \"0.0.0.0:8443\"\ndata_dir = \"/var/lib/nodary\"\ndata_plane = \"litellm\"\n"))
	if err != nil {
		t.Fatalf("litellm must load: %v", err)
	}
	if c.DataPlane != "litellm" {
		t.Errorf("data_plane = %q, want litellm", c.DataPlane)
	}

	// Unknown: refused here, at load, rather than falling back to the default
	// and serving inference through software the operator did not choose.
	_, err = LoadServerConfig(write(t,
		"bind = \"0.0.0.0:8443\"\ndata_dir = \"/var/lib/nodary\"\ndata_plane = \"litellmm\"\n"))
	if !errors.Is(err, ErrBadServerConfig) {
		t.Fatalf("err = %v, want ErrBadServerConfig", err)
	}
	if !strings.Contains(err.Error(), "litellmm") {
		t.Errorf("the refusal does not name what was written: %v", err)
	}
}

// The rendered file says which plane it runs rather than leaving a reader to
// know what an absent key means, and what it renders must load again.
func TestTheRenderedServerConfigRoundTrips(t *testing.T) {
	in := ServerConfig{Bind: "0.0.0.0:8443", DataDir: "/var/lib/nodary", DataPlane: "litellm"}
	path := filepath.Join(t.TempDir(), "server.toml")
	if err := os.WriteFile(path, RenderServerConfig(in), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := LoadServerConfig(path)
	if err != nil {
		t.Fatalf("what RenderServerConfig writes must load: %v", err)
	}
	if out.DataPlane != in.DataPlane {
		t.Errorf("data_plane = %q, want %q", out.DataPlane, in.DataPlane)
	}
}
