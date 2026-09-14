-- Operator-registered backend descriptors (docs/specs/04-backends.md §9).
--
-- The body is the TOML itself, verbatim, for the reason config.Policy stores a
-- profile's source and model.manifest_body stores a manifest's: the bytes are
-- the authority, and a struct re-serialized is a second reading of the
-- operator's document. sha256 is derived from body and stored anyway, because
-- §9 requires registration to record it and an operator checking what is in
-- force should not have to hash a column to find out.
--
-- Built-in descriptors are NOT here. They are compiled into the binary and a
-- registered row may not take one of their names: an operator who redefined
-- `vllm` would silently change the meaning of every deployment already using
-- it. That refusal lives in the applier, not in a constraint, because the set
-- of built-ins is a property of the build rather than of the database.
CREATE TABLE backend (
    name       TEXT PRIMARY KEY,
    body       TEXT NOT NULL,
    sha256     TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
) STRICT;
