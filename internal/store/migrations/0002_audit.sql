-- The audit chain (docs/specs/07-identity-audit.md 3).
--
-- The row is the record decomposed: docs/specs/07-identity-audit.md gives actor
-- three contents, source two, and target a kind plus an identity, so each
-- becomes its own column here while the record keeps them as objects. Filtering
-- by actor and action wants an indexed column rather than JSON extraction over
-- a blob.
--
-- prev_hash and hash are both UNIQUE, which is not redundancy. It moves the
-- guarantee that two records cannot claim the same predecessor out of the
-- write path's transaction discipline and into the schema, where it holds even
-- against a writer that never goes through WriteTx -- a hand-run sqlite3, or a
-- future migration that gets its locking wrong. A chain fork becomes a
-- constraint violation, and a second genesis record is impossible because 64
-- zeros can appear only once.
--
-- The two CHECK constraints on shape exist so that reading a row back can never
-- be ambiguous. A half-set target could not be distinguished from no target at
-- all, and a malformed timestamp would re-encode differently on the way out --
-- either of which would report tampering that never happened, the one failure a
-- tamper-detector must not have.
CREATE TABLE audit (
    seq            INTEGER PRIMARY KEY,
    v              INTEGER NOT NULL,
    install        TEXT    NOT NULL,
    ts             TEXT    NOT NULL,
    actor_id       TEXT,
    actor_method   TEXT    NOT NULL,
    actor_session  TEXT,
    source_ip      TEXT,
    source_version TEXT,
    action         TEXT    NOT NULL,
    target_kind    TEXT,
    target_id      TEXT,
    intent_hash    TEXT,
    justification  TEXT,
    outcome        TEXT    NOT NULL,
    detail_json    TEXT    NOT NULL,
    prev_hash      TEXT    NOT NULL UNIQUE,
    hash           TEXT    NOT NULL UNIQUE,

    CHECK (seq > 0),
    CHECK (v > 0),
    CHECK (outcome IN ('success', 'failure', 'partial')),
    CHECK (length(hash) = 64 AND length(prev_hash) = 64),
    CHECK (ts LIKE '____-__-__T__:__:__.___Z'),
    CHECK ((target_kind IS NULL) = (target_id IS NULL))
) STRICT;

CREATE INDEX audit_ts ON audit (ts);
CREATE INDEX audit_actor ON audit (actor_id);
CREATE INDEX audit_action ON audit (action);

-- One row, enforced by the primary key's CHECK. The identifier is minted on
-- first write rather than here, because a migration is static SQL and cannot
-- generate one.
--
-- It exists so records from several appliances can be told apart once they are
-- shipped somewhere central: every chain starts at seq 1 with the same genesis
-- prev_hash, so without it they interleave indistinguishably.
CREATE TABLE installation (
    singleton  INTEGER PRIMARY KEY CHECK (singleton = 1),
    id         TEXT    NOT NULL,
    created_at TEXT    NOT NULL
) STRICT;
