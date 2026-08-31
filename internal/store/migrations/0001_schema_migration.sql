-- The migration runner's own bookkeeping table, created by the migration
-- system rather than by bootstrap DDL in Go. The runner treats an absent
-- schema_migration as an empty applied set, so this file is a real migration
-- and not a special case: 0001 is applied and recorded like every other.
--
-- version is the permanent identity of a migration and never reused.
-- checksum is SHA-256 over the file's bytes; a mismatch on a later start means
-- the schema in this database is not the one this binary believes it wrote,
-- and startup aborts rather than proceeding (docs/specs/08-data-model.md 5).
CREATE TABLE schema_migration (
    version    INTEGER PRIMARY KEY,
    name       TEXT NOT NULL,
    checksum   TEXT NOT NULL,
    applied_at TEXT NOT NULL
) STRICT;
