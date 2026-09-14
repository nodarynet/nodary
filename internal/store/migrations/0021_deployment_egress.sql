-- The last egress verdict a node reached about each of its deployments.
--
-- docs/specs/03-agent.md 5 makes the assertion mandatory and R4-29 runs it
-- after every start -- but the verdict reached the node's own journal and
-- stopped there, so the one place an assessor or an operator looks knew
-- nothing about it. The control plane could serve
-- `GET /nodes/{name}/verify-egress` (09 1, R2-26) only by returning a stored
-- result, and there was no stored result.
--
-- On `deployment` rather than a table of its own for the reason
-- `pruned_through_seq` gives in 0019: there is one answer per deployment, not
-- a history. The history of what a node found is in its journal, and the
-- decision an operator takes from it is "is this one isolated right now".
--
-- Nullable, and null means *not asserted*, which is neither compliant nor
-- non-compliant: a deployment that has never run has had nothing to probe, and
-- defaulting it to either verdict would put an answer where there is no
-- question yet. `inconclusive` is a different thing -- the probe ran and could
-- not establish isolation (internal/agent's Judge) -- and it is recorded as
-- itself.
--
-- No CHECK on the state: SQLite cannot add one with ALTER TABLE, and the
-- vocabulary is internal/agent's three constants rather than this schema's.
ALTER TABLE deployment ADD COLUMN egress_state TEXT;
ALTER TABLE deployment ADD COLUMN egress_reason TEXT;
ALTER TABLE deployment ADD COLUMN egress_checked_at TEXT;
