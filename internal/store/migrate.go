package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"embed"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

// Refusals. Every one of these aborts rather than repairing:
// docs/specs/08-data-model.md §5 requires refusing to proceed against an
// unexpected schema, and a migration runner that silently corrects what it
// finds is indistinguishable from one that corrupts it.
var (
	// ErrChecksumMismatch means an applied migration's file has changed since
	// it ran. The schema in the database is not the schema this binary thinks
	// it wrote.
	ErrChecksumMismatch = errors.New("migration checksum does not match the applied schema")

	// ErrDowngrade means the database carries a migration this binary does not
	// know about. Downgrade is not supported; the documented recovery is
	// restoring a backup taken before the upgrade.
	ErrDowngrade = errors.New("database schema is newer than this binary")

	// ErrMigrationGap means an embedded migration sits below the highest
	// applied version but was never applied — what two branches numbering
	// independently produces. Applying it now would run it out of order
	// against a schema it was never written for.
	ErrMigrationGap = errors.New("migration was skipped and cannot be applied out of order")

	// ErrUnsafeMigration means a migration file contains a statement that
	// cannot do what its author expects inside a transaction.
	ErrUnsafeMigration = errors.New("migration contains a statement that is unsafe in a transaction")
)

// appliedAtFormat is when a migration ran. R1b freezes this same layout for
// audit record timestamps, where it is hashed and therefore load-bearing; here
// it is only for a human reading the table, and is kept identical so there is
// one timestamp shape in the database rather than two.
const appliedAtFormat = "2006-01-02T15:04:05.000Z"

// filename is NNNN_name.sql. The number orders migrations and is their
// permanent identity, so it is parsed strictly rather than sorted as text.
var filenamePattern = regexp.MustCompile(`^(\d{4})_([a-z0-9_]+)\.sql$`)

// PRAGMA is silently a no-op inside a transaction, which quietly breaks the
// twelve-step table rebuild an ALTER needs; VACUUM cannot run in one at all.
// Both are rejected at load rather than discovered as a migration that appeared
// to succeed and did nothing.
var unsafePattern = regexp.MustCompile(`(?i)\b(PRAGMA|VACUUM)\b`)

type migration struct {
	version  int
	name     string
	sql      string
	checksum string
}

// Migrate applies every pending embedded migration.
func (db *DB) Migrate(ctx context.Context) error {
	return db.MigrateFS(ctx, migrationsFS, "migrations")
}

// MigrateFS is Migrate against an arbitrary filesystem, so tests drive the
// runner with fstest.MapFS instead of fixtures on disk.
func (db *DB) MigrateFS(ctx context.Context, fsys fs.FS, dir string) error {
	want, err := loadMigrations(fsys, dir)
	if err != nil {
		return err
	}

	// The entire run is one immediate transaction. Two processes reaching this
	// at once is not hypothetical — docs/tasks/R1-core-audit-identity.md has
	// the CLI opening the database directly, so a CLI invocation can race a
	// server start. Reading the applied set inside the transaction, after the
	// write lock is held, is what makes the loser a no-op rather than a second
	// application of the same migration.
	return db.WriteTx(ctx, func(tx *sql.Tx) error {
		applied, err := appliedMigrations(tx)
		if err != nil {
			return err
		}
		if err := reconcile(want, applied); err != nil {
			return err
		}
		for _, m := range want {
			if _, done := applied[m.version]; done {
				continue
			}
			if err := apply(tx, m); err != nil {
				return err
			}
		}
		return nil
	})
}

// loadMigrations reads and validates the migration set.
func loadMigrations(fsys fs.FS, dir string) ([]migration, error) {
	entries, err := fs.ReadDir(fsys, dir)
	if err != nil {
		return nil, fmt.Errorf("reading migrations: %w", err)
	}

	var out []migration
	seen := make(map[int]string)
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		m := filenamePattern.FindStringSubmatch(e.Name())
		if m == nil {
			return nil, fmt.Errorf("migration %q is not named NNNN_name.sql", e.Name())
		}
		version, err := strconv.Atoi(m[1])
		if err != nil || version < 1 {
			return nil, fmt.Errorf("migration %q has no usable version", e.Name())
		}
		if prev, dup := seen[version]; dup {
			return nil, fmt.Errorf("migrations %q and %q share version %d", prev, e.Name(), version)
		}
		seen[version] = e.Name()

		body, err := fs.ReadFile(fsys, dir+"/"+e.Name())
		if err != nil {
			return nil, fmt.Errorf("reading %s: %w", e.Name(), err)
		}
		if kw := unsafeKeyword(string(body)); kw != "" {
			return nil, fmt.Errorf("%w: %s uses %s", ErrUnsafeMigration, e.Name(), kw)
		}

		sum := sha256.Sum256(body)
		out = append(out, migration{
			version:  version,
			name:     m[2],
			sql:      string(body),
			checksum: hex.EncodeToString(sum[:]),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].version < out[j].version })
	return out, nil
}

// unsafeKeyword reports a PRAGMA or VACUUM outside comments, or "" if clean.
// Comments are stripped first so a migration may explain in prose why it does
// not use one.
func unsafeKeyword(body string) string {
	if m := unsafePattern.FindString(stripSQLComments(body)); m != "" {
		return strings.ToUpper(m)
	}
	return ""
}

func stripSQLComments(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); {
		switch {
		case strings.HasPrefix(s[i:], "--"):
			j := strings.IndexByte(s[i:], '\n')
			if j < 0 {
				return b.String()
			}
			i += j
		case strings.HasPrefix(s[i:], "/*"):
			j := strings.Index(s[i+2:], "*/")
			if j < 0 {
				return b.String()
			}
			i += j + 4
		default:
			b.WriteByte(s[i])
			i++
		}
	}
	return b.String()
}

// appliedMigrations reads what the database says has run.
//
// Absence of schema_migration is detected by asking the catalogue, not by
// matching an error string: the driver returns SQLITE_ERROR with different
// messages for many failures, and string-matching would read a corrupt database
// as a fresh one.
func appliedMigrations(q querier) (map[int]string, error) {
	var present int
	if err := q.QueryRow(
		`SELECT count(*) FROM sqlite_master WHERE type='table' AND name='schema_migration'`,
	).Scan(&present); err != nil {
		return nil, fmt.Errorf("looking for schema_migration: %w", err)
	}
	applied := make(map[int]string)
	if present == 0 {
		return applied, nil // a fresh database; 0001 creates the table
	}

	rows, err := q.Query(`SELECT version, checksum FROM schema_migration`)
	if err != nil {
		return nil, fmt.Errorf("reading schema_migration: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var v int
		var sum string
		if err := rows.Scan(&v, &sum); err != nil {
			return nil, err
		}
		applied[v] = sum
	}
	return applied, rows.Err()
}

// reconcile refuses every state from which applying the pending set would be
// wrong, before anything is applied.
func reconcile(want []migration, applied map[int]string) error {
	known := make(map[int]migration, len(want))
	highestApplied := 0
	for _, m := range want {
		known[m.version] = m
	}

	for version, sum := range applied {
		if version > highestApplied {
			highestApplied = version
		}
		m, ok := known[version]
		if !ok {
			return fmt.Errorf("%w: migration %04d has been applied and this binary does not have it",
				ErrDowngrade, version)
		}
		if m.checksum != sum {
			return fmt.Errorf("%w: %04d_%s applied as %s, embedded copy is %s",
				ErrChecksumMismatch, m.version, m.name, sum, m.checksum)
		}
	}

	for _, m := range want {
		if _, done := applied[m.version]; done {
			continue
		}
		if m.version < highestApplied {
			return fmt.Errorf("%w: %04d_%s is below the applied high-water mark %04d",
				ErrMigrationGap, m.version, m.name, highestApplied)
		}
	}
	return nil
}

// apply runs one migration and records it in the same transaction.
//
// Splitting those apart is what makes a migration runner unrecoverable: a crash
// between them would leave 0001's table present with an empty applied set, so
// the next start re-runs 0001, its CREATE TABLE fails, and startup is
// permanently dead with no way forward that is not manual surgery.
func apply(tx *sql.Tx, m migration) error {
	if _, err := tx.Exec(m.sql); err != nil {
		return fmt.Errorf("applying %04d_%s: %w", m.version, m.name, err)
	}
	_, err := tx.Exec(
		`INSERT INTO schema_migration(version, name, checksum, applied_at) VALUES (?, ?, ?, ?)`,
		m.version, m.name, m.checksum, time.Now().UTC().Format(appliedAtFormat))
	if err != nil {
		return fmt.Errorf("recording %04d_%s: %w", m.version, m.name, err)
	}
	return nil
}
