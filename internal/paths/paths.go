// Package paths names the on-disk locations nodary owns, and the modes they
// are created with.
//
// Nothing here is configurable and nothing here is mutable. Every constructor
// elsewhere takes an explicit path, so a test passes a temporary directory
// rather than reaching in and rebinding a global; this package only supplies
// the production defaults, in one place, each traceable to the spec that fixed
// it.
//
// The modes travel with the paths deliberately. A file's permissions are part
// of its contract — /etc/nodary/secret.key at 0644 is a silent total compromise
// (docs/specs/08-data-model.md §4) — and keeping them here stops each package
// inventing its own answer.
package paths

import (
	"fmt"
	"os"
	"path/filepath"
)

// Directories nodary owns. See docs/specs/08-data-model.md and
// docs/specs/07-identity-audit.md §3.
const (
	DataDir   = "/var/lib/nodary"
	ConfigDir = "/etc/nodary"
	LogDir    = "/var/log/nodary"
)

// Modes for the files and directories below.
//
// DataDir is 0700 rather than 0755 because the database sits beside its -wal
// sidecar, and the write-ahead log holds committed-but-uncheckpointed audit
// records and encrypted secrets just as the database does.
const (
	ModeDataDir     os.FileMode = 0o700
	ModeConfigDir   os.FileMode = 0o755
	ModeLogDir      os.FileMode = 0o700
	ModeDatabase    os.FileMode = 0o600
	ModeSecretKey   os.FileMode = 0o400
	ModeAuditLog    os.FileMode = 0o600
	ModeCredentials os.FileMode = 0o600
)

// Database is the SQLite database. One file, WAL mode.
// docs/specs/08-data-model.md
func Database() string { return filepath.Join(DataDir, "nodary.db") }

// SecretKey is the at-rest encryption key: TOTP seeds, the LiteLLM master key
// and the agent CA private key are all sealed under it.
//
// A backup of the database without this file is useless, which is why
// `nodary backup create` captures both.
// docs/specs/08-data-model.md §4
func SecretKey() string { return filepath.Join(ConfigDir, "secret.key") }

// AuditLog is the append-only JSONL mirror of the audit chain.
//
// It exists to be shipped off-box. A compromised control plane can rewrite the
// chain in the database consistently; it cannot quietly rewrite a copy that
// already left the machine.
// docs/specs/07-identity-audit.md §3
func AuditLog() string { return filepath.Join(LogDir, "audit.jsonl") }

// Credentials is the CLI's personal-token file, under the invoking user's home
// directory rather than a system path — it is per-operator, not per-host.
// docs/specs/07-identity-audit.md §1
func Credentials() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("locating home directory for credentials: %w", err)
	}
	return filepath.Join(home, ".nodary", "credentials"), nil
}
