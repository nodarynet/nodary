-- Which routes a user may call (docs/specs/06-gateway.md 2).
--
-- The gateway applies this on every inference request, and
-- docs/specs/07-identity-audit.md 5 maps it to AC-3 and AC-6 with the words
-- "per-user model allowlists, least privilege by default".
--
-- **A user with no rows here may call nothing**, and that is what makes the
-- second half of that sentence true. The alternative -- an empty allowlist
-- meaning every route -- reads friendlier and is the wrong default to be
-- holding when an assessor asks what "least privilege by default" means here:
-- it would make the role grant, not the allowlist, the only real control, and
-- the allowlist a restriction an administrator has to remember to opt into.
--
-- The role still gates whether a user may use inference at all
-- (identity.PermInferenceUse). This gates which models, and the two are
-- different questions: a role is what someone does, a grant is what they reach.
CREATE TABLE user_route (
    user_id    TEXT NOT NULL REFERENCES user(id) ON DELETE CASCADE,
    route_name TEXT NOT NULL REFERENCES route(name) ON DELETE CASCADE,
    granted_by TEXT REFERENCES user(id),
    granted_at TEXT NOT NULL,

    PRIMARY KEY (user_id, route_name)
) STRICT;

CREATE INDEX user_route_by_route ON user_route (route_name);
