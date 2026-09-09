-- The commercial licence and the key an install signs its evidence with
-- (docs/specs/13-evidence.md, docs/adr/0005-editions-and-the-advisory-feed.md).
--
-- Both are singletons for the same reason the policy row is: history is the
-- chain's job. Applying a licence and creating a signing key are audited
-- mutations, so "when did this install become licensed" and "when did this key
-- come into existence" are answered by the evidence rather than by a table
-- nobody exports.
CREATE TABLE license (
    singleton  INTEGER PRIMARY KEY CHECK (singleton = 1),
    source     TEXT NOT NULL,
    signature  TEXT NOT NULL,
    applied_at TEXT NOT NULL,
    CHECK (length(source) > 0),
    CHECK (length(signature) > 0),
    CHECK (applied_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z')
) STRICT;

-- The signing key an assessor's copy of minisign checks a bundle against.
--
-- The private half is sealed with the at-rest key, like a TOTP seed. The public
-- half is stored in the clear because it is not a secret and because a bundle
-- carries it: an assessor needs it, and needing the database to read it would
-- defeat "verifies without nodary installed" (13 3).
--
-- Its authenticity comes from the chain, not from this table. The record of its
-- creation sits inside the evidence the key later signs, so a substituted key
-- is a key with no creation record.
CREATE TABLE evidence_key (
    singleton   INTEGER PRIMARY KEY CHECK (singleton = 1),
    key_id      TEXT NOT NULL,
    public_key  TEXT NOT NULL,
    private_enc BLOB NOT NULL,
    created_at  TEXT NOT NULL,
    CHECK (length(key_id) = 16),
    CHECK (length(public_key) > 0),
    CHECK (created_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z')
) STRICT;
