package api

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/BurntSushi/toml"

	"github.com/nodarynet/nodary/internal/dataplane"
	"github.com/nodarynet/nodary/internal/paths"
)

// ServerConfig is /etc/nodary/server.toml (R2-35, dev/specs/01-install.md §12).
type ServerConfig struct {
	Bind    string `toml:"bind"`
	DataDir string `toml:"data_dir"`
	// DataPlane names the OpenAI-compatible process the gateway proxies to
	// (dev/specs/06-gateway.md §7). Empty reads as dataplane.Default.
	//
	// Here and not in a configuration revision, deliberately. Which software
	// runs on this host beside the gateway is a fact about the host, like the
	// bind address and the certificate paths, and 00 §1 puts those in this
	// file. It is still attributable: `nodary status` names it, the manifest
	// pins it, and switching it is an act performed as root on the host.
	DataPlane string `toml:"data_plane"`
	TLS       TLS    `toml:"tls"`
	Audit     Audit  `toml:"audit"`
}

// Audit is where committed records are delivered (R2-41).
//
// Here rather than in the systemd unit, which is the only other place it could
// have gone: the unit says "Written by nodary. Edits are overwritten." at the
// top and means it, so configuring a SIEM by adding an Environment= line would
// be configuration that an upgrade silently deletes.
//
// No credential field, deliberately. The Authorization header value lives in
// paths.AuditSinkToken(); server.toml is read by anyone diagnosing the control
// plane and pasted into support threads, and a secret that survives one paste
// has leaked.
type Audit struct {
	// Sinks is audit.ParseSinks's specification — "file:/path",
	// "https://host/path", "stdout", "stderr", "none", comma-separated. Empty
	// means the JSONL file alone, which is what an install without a SIEM runs.
	Sinks string `toml:"sinks"`
	// OnFailure is "warn" (the default) or "block".
	OnFailure string `toml:"on_failure"`
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
	// A plane this build does not have is refused here rather than falling
	// back, because falling back would start the wrong data plane on a host
	// whose operator wrote down which one they wanted.
	if _, err := dataplane.Select(c.DataPlane); err != nil {
		return fmt.Errorf("%w: %v", ErrBadServerConfig, err)
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
# audit       where committed records are delivered

`)
	fmt.Fprintf(&b, "bind = %q\ndata_dir = %q\n", c.Bind, c.DataDir)
	// Written explicitly rather than left to the default, so a host says which
	// plane it runs instead of a reader having to know what an absent key
	// means. `nodary upgrade` never writes it; an operator switching planes
	// edits this line.
	if c.DataPlane != "" {
		fmt.Fprintf(&b, "data_plane = %q\n", c.DataPlane)
	}
	if c.TLS.Certificate != "" {
		fmt.Fprintf(&b, "\n[tls]\ncertificate = %q\nkey = %q\n", c.TLS.Certificate, c.TLS.Key)
	}
	// Written commented rather than omitted. The audit chain's only anchor
	// outside this machine is a copy that has already left it, and an operator
	// who never learns the option exists ships nothing off-box — so the file
	// says how, at the moment they are reading it anyway.
	fmt.Fprintf(&b, `
# [audit]
# sinks      = %q
# on_failure = "warn"          # or "block": refuse the next mutation while a sink is down
#
# sinks is comma-separated: file:PATH, https://host/path, syslog:, stdout,
# stderr, or none.
# A network sink posts NDJSON, one record per line, and never blocks a mutation:
# a destination that fell behind is re-synced with `+"`nodary audit export --from-seq`"+`.
# Its Authorization header value — "Splunk …", "Bearer …", "ApiKey …" — goes in
# %s, not here: this file gets read and pasted while diagnosing things.
#
# No SIEM? The file above is on the same disk as the database it mirrors, so it
# proves nothing against somebody who owns this box. "syslog:" hands the records
# to the local daemon — "syslog:tcp://collector:514" to a remote one — and lets
# whatever the site already collects be the off-box copy. Syslog truncates long
# messages, so treat that stream as monitoring and keep the file (and
# `+"`audit export`"+`) as the evidentiary copy.
`, "file:"+paths.AuditLog()+",https://siem.example.internal/ingest", paths.AuditSinkToken())
	return []byte(b.String())
}

// LoadAudit reads only server.toml's [audit] block.
//
// Separate from LoadServerConfig, which validates the whole file, because every
// CLI verb resolves audit delivery on its way to opening a session: a typo in a
// TLS path would otherwise fail `nodary backup create`, which is exactly the
// command somebody reaches for while putting a broken appliance back together.
// The control plane still holds the whole file to LoadServerConfig when it
// starts, so nothing goes unchecked — it is checked where acting on it matters.
func LoadAudit(path string) (Audit, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return Audit{}, err
	}
	var c struct {
		Audit Audit `toml:"audit"`
	}
	if _, err := toml.Decode(string(body), &c); err != nil {
		return Audit{}, fmt.Errorf("%w: %v", ErrBadServerConfig, err)
	}
	return c.Audit, nil
}
