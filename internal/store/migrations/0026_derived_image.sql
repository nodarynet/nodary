-- The image `nodary backend build` produced for a derive (docs/specs/04-backends.md §5).
--
-- **Outside the configuration snapshot, deliberately.** A build is a recorded
-- act, not a configuration decision. Putting its output into config.Snapshot
-- would make every build rewrite a revision's hash preimage, and `config
-- rollback` would then re-pin a digest the image store may no longer hold. The
-- configuration says which backend a deployment uses; this says what was built
-- for it; and the audit chain says who built it, from what, and why -- which is
-- the record §5 actually asks for.
--
-- One row per backend: the current build. The history is the audit chain, which
-- is the thing that is supposed to hold it.
--
-- **No foreign key to backend(name).** `backend remove` goes through
-- config.Apply, which knows nothing about this table, and a constraint here
-- would turn removal into a failure an operator has no verb to act on. An
-- orphan row is invisible -- nothing lists a backend that is not registered --
-- and if the name is registered again with a different descriptor its
-- recipe_sha256 no longer matches, so it reads `stale`, which is the correct
-- answer rather than a lucky one.
CREATE TABLE derived_image (
    name          TEXT PRIMARY KEY,
    -- Of the recipe, not of the descriptor: see backend.Derive.RecipeSHA256.
    recipe_sha256 TEXT NOT NULL,
    -- Stored as well as hashed into recipe_sha256, because §5 requires the
    -- record to carry it by name and `backend show` should not have to
    -- re-read the descriptor to say what a build came from.
    base_digest   TEXT NOT NULL,
    -- The reference a deployment pins, and the digest it resolved to when the
    -- build ran. Two columns because they answer different questions: one is
    -- what to run, the other is what ran -- and §5 requires the second by name.
    image         TEXT NOT NULL,
    digest        TEXT NOT NULL,
    built_at      TEXT NOT NULL,
    -- The actor, duplicated out of the audit record for the reason backend.sha256
    -- is duplicated out of backend.body: an operator asking what is in force
    -- should not have to walk the chain to find out.
    built_by      TEXT NOT NULL
) STRICT;
