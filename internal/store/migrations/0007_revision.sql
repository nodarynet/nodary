-- Configuration revisions (docs/specs/08-data-model.md 2).
--
-- An immutable, hash-chained snapshot per configuration change, carrying author
-- and justification. It replaces version control: there is no git repository of
-- desired state, and no reconciliation between a file somebody edited and a
-- database somebody changed, because the database is the only copy and every
-- change to it is recorded here.
--
-- It hashes the way `audit` does and is deliberately not the same chain. A
-- configuration snapshot and an administrative act are different objects at
-- different volumes (00 3), and every revision is accompanied by an audit
-- record naming who wrote it: the revision carries the state, the audit record
-- carries the act.
--
-- prev_hash and hash are both UNIQUE for the reason 08 1 gives about the audit
-- chain: it puts "two revisions cannot claim the same predecessor" in the
-- schema rather than only in the write path.
CREATE TABLE revision (
    seq           INTEGER PRIMARY KEY,
    ts            TEXT NOT NULL,
    actor         TEXT NOT NULL,
    justification TEXT,
    snapshot_json TEXT NOT NULL,
    prev_hash     TEXT NOT NULL UNIQUE,
    hash          TEXT NOT NULL UNIQUE,

    CHECK (seq > 0),
    CHECK (length(actor) > 0),
    CHECK (length(snapshot_json) > 0),
    CHECK (length(hash) = 64 AND length(prev_hash) = 64),
    CHECK (ts GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z')
) STRICT;
