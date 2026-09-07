-- The fleet: nodes, models, staging, deployments, routes, limits, usage and
-- join tokens (docs/specs/08-data-model.md 1, docs/specs/00-overview.md 3).
--
-- Every state machine is a CHECK and every relationship a foreign key, for the
-- reason 08 1 gives about the audit chain's UNIQUE columns: a rule enforced in
-- the write path holds only against writers that use it, and this milestone is
-- about to grow an HTTP surface and an agent protocol that cannot see each
-- other's transactions.
--
-- `backend` on model and deployment is plain text with no foreign key. The
-- backend catalog is R2-03 and belongs to R6; a constraint against a table that
-- does not exist is not a constraint, and naming a backend nothing has
-- registered is a state this milestone cannot reach.

CREATE TABLE node (
    name             TEXT PRIMARY KEY,
    fingerprint      TEXT,
    state            TEXT NOT NULL,
    arch             TEXT,
    os               TEXT,
    driver_version   TEXT,
    gpus_json        TEXT NOT NULL DEFAULT '[]',
    topology_json    TEXT NOT NULL DEFAULT '{}',
    offer_json       TEXT NOT NULL DEFAULT '{}',
    constraints_json TEXT NOT NULL DEFAULT '{}',
    reboot_policy    TEXT NOT NULL DEFAULT 'manual-console',
    agent_version    TEXT,
    protocol         INTEGER,
    last_seen        TEXT,
    approved_by      TEXT REFERENCES user(id),
    approved_at      TEXT,
    departed_at      TEXT,
    created_at       TEXT NOT NULL,

    CHECK (length(name) > 0),
    CHECK (state IN ('pending', 'approved', 'ready', 'draining', 'departed')),
    -- docs/specs/03-agent.md 7: nodary never initiates a reboot under either
    -- policy, so this records which kind of machine it is rather than granting
    -- permission.
    CHECK (reboot_policy IN ('manual-console', 'host-managed', 'unattended')),
    -- An approval has an author and a time or it has neither. A node that is
    -- approved by nobody is the gap docs/specs/02-enrollment.md 3 exists to
    -- close, and half a record of it is worse than none.
    CHECK ((approved_by IS NULL) = (approved_at IS NULL)),
    CHECK (state <> 'departed' OR departed_at IS NOT NULL)
) STRICT;

CREATE TABLE model (
    id              TEXT PRIMARY KEY,
    backend         TEXT NOT NULL,
    source          TEXT NOT NULL,
    artifact        TEXT NOT NULL,
    origin_org      TEXT,
    origin_country  TEXT,
    license         TEXT,
    manifest_sha256 TEXT,
    total_bytes     INTEGER,
    hints_json      TEXT NOT NULL DEFAULT '{}',
    registered_by   TEXT REFERENCES user(id),
    created_at      TEXT NOT NULL,

    CHECK (length(id) > 0),
    -- docs/specs/05-catalog.md 3: `local` is the air-gapped path and a
    -- first-class one, not a workaround.
    CHECK (source IN ('remote', 'local')),
    CHECK (total_bytes IS NULL OR total_bytes >= 0),
    CHECK (manifest_sha256 IS NULL OR length(manifest_sha256) = 64)
) STRICT;

CREATE TABLE staging (
    model_id    TEXT NOT NULL REFERENCES model(id),
    node_name   TEXT NOT NULL REFERENCES node(name),
    state       TEXT NOT NULL,
    bytes_done  INTEGER NOT NULL DEFAULT 0,
    bytes_total INTEGER,
    error       TEXT,
    updated_at  TEXT NOT NULL,

    PRIMARY KEY (model_id, node_name),
    CHECK (state IN ('absent', 'staging', 'verifying', 'staged', 'corrupt')),
    CHECK (bytes_done >= 0),
    CHECK (bytes_total IS NULL OR bytes_total >= bytes_done),
    -- docs/specs/11-failure-modes.md 2: `corrupt` is terminal and needs an
    -- explicit restage, so it always says what went wrong.
    CHECK (state <> 'corrupt' OR error IS NOT NULL)
) STRICT;

CREATE TABLE deployment (
    id                TEXT PRIMARY KEY,
    model_id          TEXT NOT NULL REFERENCES model(id),
    node_name         TEXT NOT NULL REFERENCES node(name),
    backend           TEXT NOT NULL,
    params_json       TEXT NOT NULL DEFAULT '{}',
    extra_args_json   TEXT NOT NULL DEFAULT '[]',
    port              INTEGER,
    image_digest      TEXT,
    prepared_artifact TEXT,
    state             TEXT NOT NULL,
    health            TEXT NOT NULL DEFAULT 'unknown',
    last_error        TEXT,
    created_at        TEXT NOT NULL,
    updated_at        TEXT NOT NULL,

    CHECK (length(id) > 0),
    CHECK (state IN ('defined', 'staging', 'preparing', 'starting', 'ready', 'stopped', 'failed')),
    CHECK (health IN ('unknown', 'healthy', 'unhealthy')),
    -- docs/specs/03-agent.md 5: a deployment's port is published on loopback
    -- only, so it is an ordinary unprivileged port or it is nothing yet.
    CHECK (port IS NULL OR (port > 1024 AND port < 65536)),
    CHECK (state <> 'failed' OR last_error IS NOT NULL)
) STRICT;

-- A deployment's GPUs are rows, not a JSON array, and this is the whole of
-- R2-10.
--
-- docs/specs/11-failure-modes.md 2 makes "two deployments claim one GPU" a
-- failure mode, and the two writers that will race for it are an HTTP handler
-- and an agent reconcile that cannot see each other's transaction. So the
-- control plane's half has to be something the database refuses, and SQLite
-- cannot build a unique index over the contents of a JSON array: `[0,1]` and
-- `[1,0]` would be different values, and `[0]` would look compatible with
-- `[0,1]`. It would forbid the wrong things.
--
-- 08 1's `gpus_json` therefore becomes the rendering of these rows rather than
-- their storage: there is no gpus_json column on deployment, and the API
-- renders one from here.
CREATE TABLE deployment_gpu (
    deployment_id TEXT NOT NULL REFERENCES deployment(id) ON DELETE CASCADE,
    node_name     TEXT NOT NULL REFERENCES node(name),
    gpu_index     INTEGER NOT NULL,

    PRIMARY KEY (deployment_id, gpu_index),
    CHECK (gpu_index >= 0)
) STRICT;

-- The claim lasts as long as the deployment does, and the index is
-- unconditional.
--
-- The alternative -- exclusive only while a deployment is live -- cannot be
-- written: SQLite prohibits subqueries in a partial index WHERE clause, so the
-- deployment's state cannot be consulted from here. Reaching it would mean
-- copying that state into this table and keeping the copy in step, which is the
-- write-path discipline this index exists to replace.
--
-- Holding the claim through `stopped` and `failed` is also the better rule. A
-- failed deployment on GPU 0 is one to fix and restart, not one to quietly
-- build over; freeing the GPU means deleting the deployment, which is an
-- explicit act by somebody, recorded -- which is what this product does
-- everywhere else.
CREATE UNIQUE INDEX deployment_gpu_exclusive ON deployment_gpu (node_name, gpu_index);

CREATE TABLE route (
    name       TEXT PRIMARY KEY,
    strategy   TEXT NOT NULL DEFAULT 'round-robin',
    created_at TEXT NOT NULL,

    CHECK (length(name) > 0),
    CHECK (strategy IN ('round-robin'))
) STRICT;

CREATE TABLE route_member (
    route_name    TEXT NOT NULL REFERENCES route(name) ON DELETE CASCADE,
    deployment_id TEXT NOT NULL REFERENCES deployment(id) ON DELETE CASCADE,
    weight        INTEGER NOT NULL DEFAULT 1,

    PRIMARY KEY (route_name, deployment_id),
    CHECK (weight > 0)
) STRICT;

CREATE TABLE limits (
    subject_kind   TEXT NOT NULL,
    subject_id     TEXT NOT NULL,
    rpm            INTEGER,
    tpm            INTEGER,
    daily_tokens   INTEGER,
    max_concurrent INTEGER,

    PRIMARY KEY (subject_kind, subject_id),
    -- docs/specs/06-gateway.md 4: limits apply per user, per role and globally.
    CHECK (subject_kind IN ('user', 'role', 'global')),
    CHECK (rpm IS NULL OR rpm > 0),
    CHECK (tpm IS NULL OR tpm > 0),
    CHECK (daily_tokens IS NULL OR daily_tokens > 0),
    CHECK (max_concurrent IS NULL OR max_concurrent > 0)
) STRICT;

-- Usage is a separate chain from audit and never joins it (00 3, R2-08).
--
-- No prev_hash and no hash: this is telemetry, written per request at a volume
-- the audit chain would choke on and pruned on a schedule the audit chain must
-- never be pruned on (08 3). Making it tamper-evident would cost enormously;
-- making administrative acts disposable to match would cost more.
--
-- There is no column for request or response content, and there is not going to
-- be one. docs/adr/0006-cui-boundary-and-fips.md makes "nodary records that a
-- request happened, never what it said" a structural guarantee, and this schema
-- is where "structural" is cashed out: a closed schema has nowhere to write it.
CREATE TABLE usage (
    id                TEXT PRIMARY KEY,
    ts                TEXT NOT NULL,
    user_id           TEXT REFERENCES user(id),
    token_id          TEXT REFERENCES token(id),
    route             TEXT,
    model_id          TEXT,
    deployment_id     TEXT,
    node_name         TEXT,
    request_id        TEXT,
    prompt_tokens     INTEGER NOT NULL DEFAULT 0,
    completion_tokens INTEGER NOT NULL DEFAULT 0,
    latency_ms        INTEGER,
    status            INTEGER NOT NULL,
    streamed          INTEGER NOT NULL DEFAULT 0,
    partial           INTEGER NOT NULL DEFAULT 0,

    CHECK (prompt_tokens >= 0 AND completion_tokens >= 0),
    CHECK (latency_ms IS NULL OR latency_ms >= 0),
    CHECK (streamed IN (0, 1) AND partial IN (0, 1)),
    CHECK (ts GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z')
) STRICT;

CREATE INDEX usage_ts ON usage (ts);
CREATE INDEX usage_user_ts ON usage (user_id, ts);

CREATE TABLE usage_daily (
    day               TEXT NOT NULL,
    user_id           TEXT,
    model_id          TEXT,
    requests          INTEGER NOT NULL DEFAULT 0,
    prompt_tokens     INTEGER NOT NULL DEFAULT 0,
    completion_tokens INTEGER NOT NULL DEFAULT 0,

    PRIMARY KEY (day, user_id, model_id),
    CHECK (day GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]'),
    CHECK (requests >= 0 AND prompt_tokens >= 0 AND completion_tokens >= 0)
) STRICT;
