-- R2-02 / R4-15: a node's rejection of part of a desired-state document.
--
-- docs/specs/12-node-guardrails.md 1: "A refusal is surfaced against the node
-- in the interface ... The control plane does not retry automatically,
-- because a limit that is being hit repeatedly is something an operator
-- should see rather than something the system should grind against."
--
-- The agent already decided these (internal/agent/plan.go's Build refuses an
-- unknown backend, a GPU that is not on offer, a deployment with no image)
-- and had nowhere to put them: they were logged into the node's own journal
-- and went no further, so a deployment the node would never run appeared to
-- an operator as one stuck in `defined` with no reason given anywhere.
--
-- Keyed by deployment rather than appended to: a refusal is a standing
-- condition recomputed every reconcile, not an event. Appending one row per
-- heartbeat would bury a month of them under two hundred thousand copies of
-- the same sentence -- the reasoning internal/observed's package comment
-- gives for keeping telemetry out of the audit chain, applied to its own
-- table.
--
-- rev is the revision the refusal was computed against, so an operator can
-- tell "refused, and the configuration has not moved since" from "refused,
-- and this is stale".
CREATE TABLE refusal (
    node_name     TEXT NOT NULL REFERENCES node(name),
    deployment_id TEXT NOT NULL REFERENCES deployment(id) ON DELETE CASCADE,
    rev           INTEGER NOT NULL,
    reason        TEXT NOT NULL,
    updated_at    TEXT NOT NULL,

    PRIMARY KEY (node_name, deployment_id),
    CHECK (length(reason) > 0)
) STRICT;
