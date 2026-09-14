-- The decision that closes a finding's clock (R9-17).
--
-- Columns on the finding rather than a table of its own: there is exactly one
-- current decision per finding, and a second table would need the same
-- four-column key to say so. ALTER TABLE ADD COLUMN follows 0012 and 0013, and
-- like them adds no CHECK — the vocabulary is validated in Go, where the
-- refusal can name the three words instead of reporting a constraint.
--
-- decided_by is NULL for a local principal, the way node.approved_by is: 07 §1
-- makes local root a real principal without a user row, and the chain carries
-- who either way.
--
-- There is deliberately no column pointing at the chain record. audit.Log.Act
-- runs the mutation before it appends, so the sequence does not exist while
-- this row is being written, and a column filled by a second write after the
-- commit would be a link that is absent exactly when the commit was the thing
-- that failed. The chain record is found by its action and target.
--
-- review_at is what makes `defer` a deferral rather than a mute button. A
-- deferred finding past its review date reads as undecided again and its clock
-- resumes from the original first sighting — the time already spent deferring
-- is time the finding was known, and an assessor counts it.
ALTER TABLE advisory_finding ADD COLUMN decision TEXT;
ALTER TABLE advisory_finding ADD COLUMN justification TEXT;
ALTER TABLE advisory_finding ADD COLUMN decided_by TEXT;
ALTER TABLE advisory_finding ADD COLUMN decided_at TEXT;
ALTER TABLE advisory_finding ADD COLUMN review_at TEXT;
