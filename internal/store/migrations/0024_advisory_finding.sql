-- What this install knew, and since when (docs/tasks/R9-evidence-remediation.md R9-16).
--
-- An observation, not a decision: nobody chose anything by running `advisory
-- check`, so this is written like a heartbeat rather than through the audit
-- chain. Recording every run as a mutation would bury the chain under a verb
-- an operator is meant to run on a whim, and the chain's job here is the
-- *decision* (R9-17) — "the chain already is the remediation record" is about
-- what was decided, not about what was looked at.
--
-- first_seen_at is the clock, and it is local on purpose. The feed revision's
-- `generated` timestamp would be the lazier source and it is the wrong one: a
-- site that updates to a newer revision would see every finding's clock reset,
-- so being current would make an overdue finding look new. What an assessor
-- asks is when *this site* could have known, and that is when a revision
-- carrying it first arrived here.
--
-- The digest is in the key because an advisory against a digest the site has
-- since moved off is a different finding from the same advisory against the
-- one it runs now. The old row stays as history and simply stops matching.
CREATE TABLE advisory_finding (
    advisory_id   TEXT NOT NULL,
    component     TEXT NOT NULL,
    platform      TEXT NOT NULL,
    digest        TEXT NOT NULL,
    first_seen_at TEXT NOT NULL,
    feed_revision INTEGER NOT NULL,
    PRIMARY KEY (advisory_id, component, platform, digest)
) STRICT;
