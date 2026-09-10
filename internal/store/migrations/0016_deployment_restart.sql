-- `nodary model restart` (R4-36): a one-shot "cycle this unit now" request,
-- with no declarative change to persist -- the params before and after a
-- restart can be identical -- so it is an edge-triggered row the agent
-- consumes and acknowledges over the heartbeat, not part of config.Snapshot.
-- Same shape stage_reset (0014_stage_reset.sql) already uses for the same
-- reason: docs/specs/03-agent.md 2's protocol has no other way to express
-- "do this now".
CREATE TABLE deployment_restart (
    node_name     TEXT NOT NULL REFERENCES node(name),
    deployment_id TEXT NOT NULL REFERENCES deployment(id),
    requested_at  TEXT NOT NULL,

    PRIMARY KEY (node_name, deployment_id)
) STRICT;
