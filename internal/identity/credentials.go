package identity

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/nodarynet/nodary/internal/paths"
)

// The CLI's personal-token file: docs/specs/07-identity-audit.md §1's
// ~/.nodary/credentials, mode 0600.
//
// It is per-operator rather than per-host, which is why it lives under a home
// directory and not in /etc. A credential readable by anyone else on the
// machine is a credential that has leaked, so a file with group or other
// permissions is refused rather than read — the same rule ssh applies to a
// private key, and for the same reason.

// LocalServer is the key R1 stores a credential under.
//
// The map is keyed by target because docs/specs/10-cli.md §2 has --server, and
// an operator with a laptop credential for two appliances would otherwise need
// two files. R1 has no server, so there is exactly one key; the shape is here
// so R2 adds a key rather than a format.
const LocalServer = "local"

// credentialsVersion is the file format's version. It is checked on read: a
// file from a future release is refused rather than half-understood.
const credentialsVersion = 1

var (
	// ErrNoCredentials means there is no credential for the requested target.
	ErrNoCredentials = errors.New("no credentials")
	// ErrCredentialsExposed is a credentials file others can read.
	ErrCredentialsExposed = errors.New("credentials file is readable by others")
	// ErrCredentialsFormat is a file this release cannot read.
	ErrCredentialsFormat = errors.New("credentials file is not in a format this release reads")
)

// Credential is one target's stored credential.
type Credential struct {
	Token string `json:"token"`
	// User is the name the token belonged to when it was written. It is for
	// display: authority comes from the token, never from this.
	User string `json:"user,omitempty"`
}

// Credentials is the file.
type Credentials struct {
	Version int                   `json:"version"`
	Servers map[string]Credential `json:"servers"`
}

// LoadCredentials reads the file at path.
//
// An absent file is not an error — running without credentials is the ordinary
// case on an appliance — so it returns an empty set. Everything else is: a file
// that exists and cannot be used should say why, not fall back silently to a
// different identity.
func LoadCredentials(path string) (*Credentials, error) {
	empty := &Credentials{Version: credentialsVersion, Servers: map[string]Credential{}}

	fi, err := os.Lstat(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return empty, nil
	case err != nil:
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%w: %s is not a regular file", ErrCredentialsFormat, path)
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("%w: %s is mode %#o, want %#o",
			ErrCredentialsExposed, path, fi.Mode().Perm(), paths.ModeCredentials)
	}

	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	var c Credentials
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("%w: %s: %v", ErrCredentialsFormat, path, err)
	}
	if c.Version != credentialsVersion {
		return nil, fmt.Errorf("%w: %s declares version %d, this release reads %d",
			ErrCredentialsFormat, path, c.Version, credentialsVersion)
	}
	if c.Servers == nil {
		c.Servers = map[string]Credential{}
	}
	return &c, nil
}

// Token returns the stored credential for a target.
func (c *Credentials) Token(server string) (Credential, error) {
	cred, ok := c.Servers[server]
	if !ok || cred.Token == "" {
		return Credential{}, fmt.Errorf("%w for %q", ErrNoCredentials, server)
	}
	return cred, nil
}

// Set records a credential, replacing any for the same target.
func (c *Credentials) Set(server string, cred Credential) {
	if c.Servers == nil {
		c.Servers = map[string]Credential{}
	}
	c.Version = credentialsVersion
	c.Servers[server] = cred
}

// Save writes the file at path, mode 0600, atomically.
//
// Written to a temporary file and renamed so an interrupted write cannot leave
// a truncated file where a working credential was. The temporary file is
// created with the final mode, not chmod-ed afterwards: between the two there
// is a window in which the credential is on disk and world-readable.
func (c *Credentials) Save(path string) error {
	dir := filepath.Dir(path)
	// 0700, and never loosened if it already exists: this directory holds a
	// credential and nothing else needs to see it.
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("creating %s: %w", dir, err)
	}

	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return fmt.Errorf("encoding credentials: %w", err)
	}
	b = append(b, '\n')

	tmp, err := os.CreateTemp(dir, ".credentials.")
	if err != nil {
		return fmt.Errorf("creating a temporary file in %s: %w", dir, err)
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(paths.ModeCredentials); err != nil {
		tmp.Close()
		return fmt.Errorf("setting the mode on %s: %w", tmp.Name(), err)
	}
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return fmt.Errorf("writing %s: %w", tmp.Name(), err)
	}
	// Durability before the rename: a credential the operator was told was
	// saved and that a power cut removes is worse than one that failed loudly.
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("syncing %s: %w", tmp.Name(), err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("closing %s: %w", tmp.Name(), err)
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return fmt.Errorf("installing %s: %w", path, err)
	}
	return nil
}
