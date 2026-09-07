-- The active policy profile (docs/specs/07-identity-audit.md 4).
--
-- The profile is stored as the TOML an operator wrote, not as a column per
-- setting. 07 4 calls a profile "a single reviewable object", worth as much to
-- an assessor as to a maintainer; sixteen columns are sixteen facts that can
-- disagree with the document they came from, and every new setting becomes a
-- migration. `policy show` re-parses these bytes, so it cannot drift from what
-- `policy apply` accepted -- they run the same code over the same source.
--
-- One row. History is not kept here because it is already kept better
-- elsewhere: every apply is an audited mutation carrying the source it applied,
-- so "what was the posture in March" is a chain query
-- (docs/specs/13-evidence.md), answered by the same evidence as every other
-- historical question.
--
-- A fresh install has no row. The absence means `default`, which is what 07 4
-- says a fresh install runs -- rather than seeding a row here, because a seeded
-- row would claim somebody applied it and no audit record would say who.
CREATE TABLE policy (
    singleton  INTEGER PRIMARY KEY CHECK (singleton = 1),
    name       TEXT    NOT NULL,
    source     TEXT    NOT NULL,
    applied_at TEXT    NOT NULL,
    CHECK (length(name) > 0),
    CHECK (length(source) > 0),
    CHECK (applied_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z')
) STRICT;
