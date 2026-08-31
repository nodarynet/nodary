# 08 — Data model

SQLite at `/var/lib/nodary/nodary.db`, WAL mode.

**WAL means the database is not one file, and copying `nodary.db` alone is not a backup.**
A live database is `nodary.db` plus `nodary.db-wal` and `nodary.db-shm`, and a commit lives
in the write-ahead log until it is checkpointed — so a copy of the first file alone silently
loses the most recent writes, including audit records. A backup must either checkpoint
first or use `VACUUM INTO`, which writes a genuine single-file snapshot from a consistent
view. `nodary backup create` does this; anything hand-rolled must too.

A pure-Go SQLite driver (`modernc.org/sqlite`) is used so the binary stays cgo-free and
genuinely static ([ADR 0002](../adr/0002-go-with-package-manager-wrappers.md)).

## 1. Schema

```sql
node(name PK, fingerprint, state, arch, os, driver_version, gpus_json, topology_json,
     offer_json, constraints_json, reboot_policy, agent_version, protocol,
     last_seen, approved_by, approved_at, departed_at, created_at)

refusal(id PK, node_name, rev, deployment_id, reason, detail_json, ts)

backend(name PK, source, inherits, descriptor_toml, descriptor_sha256, registered_by, created_at)

derived_image(backend PK, base_digest, recipe_sha256, result_digest, state,
              built_by, built_at, log_tail)

model(id PK, backend, source, artifact, origin_org, origin_country, license,
      manifest_sha256, total_bytes, hints_json, registered_by, created_at)

staging(model_id, node_name, state, bytes_done, bytes_total, error, updated_at,
        PRIMARY KEY (model_id, node_name))

deployment(id PK, model_id, node_name, backend, gpus_json, params_json, extra_args_json,
           port, image_digest, prepared_artifact, state, health, last_error,
           created_at, updated_at)

route(name PK, strategy, created_at)
route_member(route_name, deployment_id, weight, PRIMARY KEY (route_name, deployment_id))

user(id PK, name, email, role, state, password_hash, totp_secret_enc, created_at)
token(id PK, user_id, kind, hash, prefix, name, expires_at, revoked_at, last_used_at,
      allow_unattended, created_at)
limits(subject_kind, subject_id, rpm, tpm, daily_tokens, max_concurrent,
       PRIMARY KEY (subject_kind, subject_id))

revision(seq PK, ts, actor, justification, snapshot_json, prev_hash, hash)
audit(seq PK, ts, actor, source, action, target, intent_hash, justification,
      outcome, detail_json, prev_hash, hash)
usage(id PK, ts, user_id, token_id, route, model_id, deployment_id, node_name,
      request_id, prompt_tokens, completion_tokens, latency_ms, status, streamed, partial)
usage_daily(day, user_id, model_id, requests, prompt_tokens, completion_tokens,
            PRIMARY KEY (day, user_id, model_id))

policy(name PK, body_toml, active, applied_by, applied_at)
join_token(id PK, hash, uses_left, expires_at, created_by, created_at)
```

## 2. Revisions replace version control

`revision` retains change control without git: an immutable, hash-chained snapshot per
configuration change, carrying author and justification.

```sh
nodary config show [--rev N]
nodary config diff <a> <b>
nodary config rollback <rev> --justify "..."
nodary config export > nodary.toml     # canonical, for provisioning and DR
nodary config apply -f nodary.toml     # reads it back
```

The database is authoritative; the export is a convenience. A rollback is itself a new
revision — history is append-only and nothing is ever rewritten.

## 3. Retention

| Table | Policy |
| :--- | :--- |
| `audit` | `audit_retention_days` (default 1095). Never pruned below the active policy's floor |
| `usage` | `usage_retention_days` raw (default 90), then rolled into `usage_daily` |
| `usage_daily` | Indefinite — small, and the basis for long-range reporting |
| `revision` | Indefinite. Snapshots are small and are the configuration history |
| `join_token` | Purged 24h after expiry |

Pruning runs as a periodic task and writes an audit record naming the range removed. A
retention job that silently deletes evidence is indistinguishable from tampering.

## 4. Secrets at rest

TOTP seeds, the LiteLLM master key, and the agent CA private key are encrypted with a key at
`/etc/nodary/secret.key` (0400, root).

**A backup of `nodary.db` alone is useless without that file, and this must be stated loudly
wherever backup is documented.** The inverse is the real risk: an operator who backs up only
the database discovers at restore time that every agent must re-enroll and every TOTP
enrollment must be redone.

`nodary backup create` captures both by default and refuses to write to a world-readable
destination.

## 5. Migrations

Schema migrations are embedded in the binary and forward-only. Each is recorded with its
checksum; a mismatch aborts startup rather than proceeding against an unexpected schema.

They are applied by **any process that opens the database for writing**, not only by the
server. The CLI operates on a local database directly, so on a first install an operator's
first command and the server's first start reach an unmigrated database together. The whole
run therefore happens inside one immediate transaction, with the applied set re-read after
the write lock is held, which makes the loser of that race a no-op rather than a second
application of the same migration. A read-only open never migrates: it refuses when the
schema is behind rather than changing it underneath a reader.

Downgrade is not supported. Rolling back a nodary version requires restoring a backup taken
before the upgrade, which `nodary upgrade` takes automatically and names in its output.
