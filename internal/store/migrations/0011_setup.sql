-- The one-time setup credential of docs/specs/01-install.md 4, step 9.
--
-- Two columns on the installation row rather than a table of its own, because
-- there is only ever one of these and because the state that makes it
-- single-use is already here. A setup link creates the *first* administrator,
-- so the existence of any user retires it whether or not it was ever redeemed.
-- A table would hold at most one row and would let a second live credential be
-- represented, which is a state this feature has no meaning for.
--
-- Stored as a SHA-256 hash, like every other bearer credential in the product
-- (docs/specs/02-enrollment.md 4). Nulled on redemption in the same UPDATE that
-- checks it, so the check and the burn cannot come apart.
ALTER TABLE installation ADD COLUMN setup_hash TEXT;
ALTER TABLE installation ADD COLUMN setup_expires_at TEXT;
