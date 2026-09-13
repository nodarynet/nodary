-- docs/specs/09-api.md §2: "POST endpoints accept Idempotency-Key. A repeat
-- within 24h returns the original response rather than acting twice."
--
-- Keyed by (key, principal) and not by the key alone. A key is chosen by a
-- client, so two clients can pick the same one -- and returning one caller's
-- response to another would be a disclosure, not merely a wrong answer.
--
-- `request` is a digest of the method, path and body. A key reused for a
-- *different* request is a client bug, and replaying the old response to it
-- would hide that bug behind a plausible success; it is refused instead.
--
-- `status` is 0 while the request is in flight. That is what makes this an
-- exclusion and not merely a cache: the row is inserted before the handler
-- runs, so a concurrent retry -- the ordinary case, where a client timed out
-- and tried again while the first attempt was still working -- collides here
-- instead of acting twice. A request that fails deletes its own row, so a
-- retry after a refusal is free to proceed.
--
-- `response` is sealed under secret.key, not stored as it was sent: POST /tokens
-- returns a plaintext token that docs/specs/10-cli.md 4 says is shown exactly
-- once and never readable again, and a replayable copy sitting in a column would
-- make that untrue of the database file.
--
-- A row left at 0 by a process that died mid-request is not cleaned up on the
-- next attempt, deliberately: nobody knows whether that mutation committed, and
-- guessing "it did not" is how you mint two tokens. The retry is told to look,
-- and `nodary audit list` is where the answer is.
CREATE TABLE idempotency (
    key        TEXT NOT NULL,
    principal  TEXT NOT NULL,
    request    TEXT NOT NULL,
    status     INTEGER NOT NULL DEFAULT 0,
    response   BLOB NOT NULL DEFAULT x'',
    created_at TEXT NOT NULL,

    PRIMARY KEY (key, principal),
    CHECK (length(key) > 0),
    CHECK (length(request) = 64),
    CHECK (status >= 0),
    CHECK (created_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z')
) STRICT;

CREATE INDEX idempotency_created ON idempotency (created_at);
