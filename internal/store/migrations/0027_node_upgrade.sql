-- Why a node is not running the version the fleet targets (R5-15).
--
-- A node upgrades itself from the control plane's mirror, and an upgrade that
-- cannot happen must not stop the one that is serving: docs/specs/01-install.md
-- §9 has the agent keep running what it has and say so. Without somewhere to
-- put that, "say so" is a log line on the node -- which is the machine an
-- operator cannot reach, on a fleet whose whole point is that they do not have
-- to.
--
-- Nullable and beside agent_version rather than a state machine: the fact is
-- "this node tried and could not, for this reason", and it is cleared by the
-- node succeeding or by the target moving. node.agent_version already says what
-- it is running, so this adds the reason for the gap and nothing else.
ALTER TABLE node ADD COLUMN upgrade_error TEXT;
ALTER TABLE node ADD COLUMN upgrade_target TEXT;
