-- R4-35/R4-36: `nodary model restage`/`unstage` (docs/specs/05-catalog.md 3-4).
--
-- The desired-state document has no imperative commands (docs/specs/03-agent.md
-- 2), so "delete this model's weights and try again" can't be sent as one.
-- This is the same fix the protocol already uses for join-token redemption:
-- an edge-triggered row, consumed once the agent acts on it and reports back
-- over the heartbeat (internal/observed).
--
-- No requested_by/justification columns: the audit chain already carries
-- both for the act that created the row, and this table is not itself a
-- record -- it is a mailbox the agent drains.
CREATE TABLE stage_reset (
    node_name    TEXT NOT NULL REFERENCES node(name),
    model_id     TEXT NOT NULL REFERENCES model(id),
    requested_at TEXT NOT NULL,

    PRIMARY KEY (node_name, model_id)
) STRICT;
