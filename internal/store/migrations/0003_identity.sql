-- Users, tokens and the key binding (docs/specs/07-identity-audit.md 1,
-- docs/specs/08-data-model.md 1).
--
-- A user is never removed. Audit records name a user by id
-- (docs/specs/07-identity-audit.md 3), and evidence that cannot be resolved to
-- a name is worth less, so `delete` is a state. What deletion does destroy is
-- the sealed TOTP seed, and the CHECK below makes that a property of the schema
-- rather than a promise of the delete path.
--
-- The name, unlike the row, does come back: the unique index is partial, so a
-- deleted alice frees `alice` while a live one does not. Without that, deleting
-- a user by mistake means living with `alice2` forever.
--
-- There is no password column. Authentication in R1 is by personal token
-- (docs/specs/07-identity-audit.md 1) and the only thing that verifies a
-- password is the login endpoint in R2, which is where the hashing lands. It is
-- an ordinary forward-only migration when it does: nothing hashes a user row.
--
-- totp_last_step records the last step number consumed. RFC 6238 codes stand
-- for a whole 30-second step and the accepted skew widens that further, so a
-- code that outlives its own use can be replayed by anyone who saw it once --
-- which is precisely what docs/specs/07-identity-audit.md 2's re-entry exists
-- to prevent.
CREATE TABLE user (
    id               TEXT PRIMARY KEY,
    name             TEXT NOT NULL,
    email            TEXT,
    role             TEXT NOT NULL,
    state            TEXT NOT NULL,
    totp_secret_enc  BLOB,
    totp_last_step   INTEGER,
    totp_enrolled_at TEXT,
    created_at       TEXT NOT NULL,

    CHECK (id GLOB 'usr_*'),
    CHECK (length(name) > 0),
    CHECK (role IN ('viewer', 'user', 'operator', 'admin')),
    CHECK (state IN ('active', 'suspended', 'deleted')),
    -- Read back, a half-enrolled row would be ambiguous: a seed with no
    -- enrollment time and an enrollment time with no seed mean different
    -- things and neither is a state the code can act on.
    CHECK ((totp_secret_enc IS NULL) = (totp_enrolled_at IS NULL)),
    CHECK (totp_last_step IS NULL OR totp_last_step >= 0),
    CHECK (totp_secret_enc IS NOT NULL OR totp_last_step IS NULL),
    CHECK (state <> 'deleted' OR totp_secret_enc IS NULL)
) STRICT;

CREATE UNIQUE INDEX user_live_name ON user (name) WHERE state <> 'deleted';

-- Personal tokens and service keys (docs/specs/02-enrollment.md 4). Join tokens
-- are below: they belong to no user and carry a use count instead of a subject.
--
-- The stored hash is SHA-256 of the whole presented string, prefix included, so
-- authentication hashes exactly what the operator pasted. SHA-256 rather than a
-- slow KDF is correct here and is not the compromise it looks like: a token is
-- 256 bits from crypto/rand, so there is no dictionary to run and an attacker
-- who can invert SHA-256 on a uniform 256-bit secret has already won
-- everywhere. A KDF would only put a deliberate delay on every authenticated
-- request.
--
-- prefix is the leading, non-secret span kept for display, so `token list` can
-- identify a token without holding anything that authenticates as one.
--
-- allow_unattended exists because docs/specs/08-data-model.md 1 puts it on the
-- row. Nothing sets it yet: the grant exists in order to be refused when a
-- profile sets allow_unattended_tokens = false, and there is no policy to
-- refuse it with until R1d. Shipping the grant before the thing that denies it
-- is the wrong order.
CREATE TABLE token (
    id               TEXT    PRIMARY KEY,
    user_id          TEXT    NOT NULL REFERENCES user(id),
    kind             TEXT    NOT NULL,
    hash             TEXT    NOT NULL UNIQUE,
    prefix           TEXT    NOT NULL,
    name             TEXT,
    expires_at       TEXT,
    revoked_at       TEXT,
    last_used_at     TEXT,
    allow_unattended INTEGER NOT NULL DEFAULT 0,
    created_at       TEXT    NOT NULL,

    CHECK (id GLOB 'tok_*'),
    CHECK (kind IN ('pt', 'sk')),
    CHECK (length(hash) = 64),
    CHECK (length(prefix) > 0),
    CHECK (allow_unattended IN (0, 1))
) STRICT;

CREATE INDEX token_user ON token (user_id);

-- Join tokens enroll a node and nothing else (docs/specs/02-enrollment.md 4).
-- They are minted here; redeeming one is node enrollment, in R2 and R4.
--
-- prefix is here for the same reason it is on the token row: it is what lets a
-- credential pasted into a chat window or found in a log be matched to a row
-- without holding anything that authenticates as one.
CREATE TABLE join_token (
    id         TEXT    PRIMARY KEY,
    hash       TEXT    NOT NULL UNIQUE,
    prefix     TEXT    NOT NULL,
    uses_left  INTEGER NOT NULL,
    expires_at TEXT    NOT NULL,
    created_by TEXT    NOT NULL,
    created_at TEXT    NOT NULL,

    CHECK (id GLOB 'jt_*'),
    CHECK (length(prefix) > 0),
    CHECK (uses_left >= 0),
    CHECK (length(hash) = 64)
) STRICT;

-- Which key sealed this database's secrets (docs/specs/08-data-model.md 4).
--
-- Nullable, and set on the first seal rather than here, because until something
-- is sealed there is nothing to lose and a database that simply predates the
-- key must not be refused. After that a mismatch is reported instead of
-- answered by minting a fresh key -- the failure this exists to prevent, where
-- every sealed TOTP seed becomes permanently unreadable behind a clean startup
-- that says nothing is wrong.
ALTER TABLE installation ADD COLUMN secret_key_id TEXT;
