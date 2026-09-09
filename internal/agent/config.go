package agent

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/BurntSushi/toml"
	"github.com/nodarynet/nodary/internal/paths"
)

// Config is /etc/nodary/agent.toml: how this node reaches its control plane.
//
// It holds no secrets. The join token is spent at enrollment and never written
// down, and the node's private key is a file this points at rather than
// material it carries — so this file is 0644 and safe in a configuration
// backup, while node.key is 0600 and is not.
type Config struct {
	Server        string `toml:"server"`
	Name          string `toml:"name"`
	CAFingerprint string `toml:"ca_fingerprint"`
	Certificate   string `toml:"certificate"`
	Key           string `toml:"key"`
	ModelsDir     string `toml:"models_dir"`
}

// ConfigPath is where agent.toml lives, beside the rest of the configuration.
func ConfigPath() string { return filepath.Join(paths.ConfigDir, "agent.toml") }

// DefaultModelsDir is where weights are staged. docs/specs/05-catalog.md §3.
func DefaultModelsDir() string { return filepath.Join(paths.DataDir, "models") }

// LoadConfig reads and validates agent.toml.
//
// Unknown keys are refused, as everywhere else nodary reads a file a human
// edits: a key nobody applies is a setting an operator believes is in force.
func LoadConfig(path string) (Config, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}
	var c Config
	md, err := toml.Decode(string(body), &c)
	if err != nil {
		return Config{}, fmt.Errorf("%w: %v", ErrBadConfig, err)
	}
	if u := md.Undecoded(); len(u) > 0 {
		keys := make([]string, len(u))
		for i, k := range u {
			keys[i] = k.String()
		}
		return Config{}, fmt.Errorf("%w: unknown keys %s", ErrBadConfig, strings.Join(keys, ", "))
	}
	return c, c.Validate()
}

// Validate checks what can be checked without touching the network.
func (c Config) Validate() error {
	switch {
	case strings.TrimSpace(c.Server) == "":
		return fmt.Errorf("%w: server is required", ErrBadConfig)
	case !strings.HasPrefix(c.Server, "https://"):
		// There is no plaintext mode on the server and there is none here
		// either. An http:// URL in this file is a node that would hand its
		// certificate to anything that answered.
		return fmt.Errorf("%w: server must be https://…, got %q", ErrBadConfig, c.Server)
	case strings.TrimSpace(c.Name) == "":
		return fmt.Errorf("%w: name is required", ErrBadConfig)
	case !fingerprintPattern.MatchString(strings.ToLower(c.CAFingerprint)):
		return fmt.Errorf("%w: ca_fingerprint must be sha256:<64 hex>", ErrBadConfig)
	case c.Certificate == "" || c.Key == "":
		return fmt.Errorf("%w: certificate and key are both required", ErrBadConfig)
	}
	return nil
}

// RenderConfig writes the file `nodary node enroll` places.
func RenderConfig(c Config) []byte {
	var b strings.Builder
	b.WriteString(`# nodary agent.
#
# server          the control plane, https:// always
# name            this node's name in the fleet; it is the certificate's subject
# ca_fingerprint  the certificate this node pins, carried out of band from
#                 ` + "`nodary server install`" + `. Changing it re-points this node
#                 at a different control plane, which is why it is here and not
#                 discovered
# certificate     this node's client certificate, issued at enrollment
# key             its private half. 0600, and never leaves this machine
# models_dir      where weights are staged

`)
	fmt.Fprintf(&b, "server = %q\nname = %q\nca_fingerprint = %q\ncertificate = %q\nkey = %q\nmodels_dir = %q\n",
		c.Server, c.Name, c.CAFingerprint, c.Certificate, c.Key, c.ModelsDir)
	return []byte(b.String())
}
