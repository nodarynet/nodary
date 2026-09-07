package api

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/BurntSushi/toml"
)

// ServerConfig is /etc/nodary/server.toml (R2-35, docs/specs/01-install.md §12).
type ServerConfig struct {
	Bind    string `toml:"bind"`
	DataDir string `toml:"data_dir"`
	TLS     TLS    `toml:"tls"`
}

// TLS points at the certificate the control plane serves.
//
// Empty paths mean the self-signed pair `nodary server install` generates
// (R2-39). A site with its own CA points these at its own files and nothing
// else changes.
type TLS struct {
	Certificate string `toml:"certificate"`
	Key         string `toml:"key"`
}

// ErrBadServerConfig is any unusable server.toml.
var ErrBadServerConfig = errors.New("invalid server configuration")

// DefaultServerConfig is what a fresh install runs.
func DefaultServerConfig(dataDir string) ServerConfig {
	return ServerConfig{Bind: "0.0.0.0:8443", DataDir: dataDir}
}

// LoadServerConfig reads and validates server.toml.
//
// Unknown keys are refused, as everywhere else a human edits a file nodary
// reads: a key nobody applies is a setting an operator believes is in force.
func LoadServerConfig(path string) (ServerConfig, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return ServerConfig{}, err
	}
	var c ServerConfig
	md, err := toml.Decode(string(body), &c)
	if err != nil {
		return ServerConfig{}, fmt.Errorf("%w: %v", ErrBadServerConfig, err)
	}
	if u := md.Undecoded(); len(u) > 0 {
		keys := make([]string, len(u))
		for i, k := range u {
			keys[i] = k.String()
		}
		return ServerConfig{}, fmt.Errorf("%w: unknown keys %s", ErrBadServerConfig, strings.Join(keys, ", "))
	}
	return c, c.Validate()
}

// Validate checks what can be checked without touching the filesystem.
func (c ServerConfig) Validate() error {
	if strings.TrimSpace(c.Bind) == "" {
		return fmt.Errorf("%w: bind is required", ErrBadServerConfig)
	}
	if _, _, err := net.SplitHostPort(c.Bind); err != nil {
		return fmt.Errorf("%w: bind %q is not host:port", ErrBadServerConfig, c.Bind)
	}
	// A certificate without its key, or the reverse, is a configuration that
	// starts and then fails at the first connection.
	if (c.TLS.Certificate == "") != (c.TLS.Key == "") {
		return fmt.Errorf("%w: tls.certificate and tls.key must be given together", ErrBadServerConfig)
	}
	return nil
}

// RenderServerConfig writes the file `server install` places.
func RenderServerConfig(c ServerConfig) []byte {
	var b strings.Builder
	b.WriteString(`# nodary control plane.
#
# bind        where the API and the node protocol are served
# data_dir    the database, the component cache and the PKI
# tls         the certificate served to operators and agents. Left empty, the
#             self-signed pair generated at install is used, and its fingerprint
#             is what a node pins with --ca-fingerprint.

`)
	fmt.Fprintf(&b, "bind = %q\ndata_dir = %q\n", c.Bind, c.DataDir)
	if c.TLS.Certificate != "" {
		fmt.Fprintf(&b, "\n[tls]\ncertificate = %q\nkey = %q\n", c.TLS.Certificate, c.TLS.Key)
	}
	return []byte(b.String())
}
