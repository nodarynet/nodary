# 07 — Identity, audit & policy

## 1. Users and roles

| Role | May |
| :--- | :--- |
| `viewer` | Read state; read own usage |
| `user` | The above, plus use the inference API |
| `operator` | The above, plus enable, disable and restart models; stage weights; drain nodes |
| `admin` | Everything: configuration, catalog and backend registration, node approval, user and token management, policy |

Authentication is local: argon2id password hashing plus TOTP. The web interface uses
short-lived signed session cookies; the CLI uses personal tokens at `~/.nodary/credentials`
(mode 0600).

OIDC against an external identity provider is a later swap behind the same interface, not a
rewrite. It is deliberately not the initial mechanism: an appliance that cannot authenticate
its own administrator when the network is degraded is an appliance that cannot be recovered.

## 2. Attestation

Every mutating action requires three things:

1. **A rendered preview** of exactly what will change.
2. **A justification** — free text, required, minimum length enforced by policy.
3. **Re-authentication** — TOTP re-entry, when the active policy requires it.

The third is what makes this a *personal* attestation rather than a session cookie. A cookie
proves someone logged in at some point; a re-entered code proves a person was present for
this specific act.

On the CLI this is `--justify "..."` plus a TOTP prompt. Non-interactive use requires a token
minted with `--allow-unattended`, which is itself an audited grant and is refused outright
when policy sets `allow_unattended_tokens = false`.

## 3. The audit chain

| Field | Contents |
| :--- | :--- |
| `v` | Record schema version |
| `install` | Which installation wrote it |
| `seq` | Monotonic integer |
| `ts` | RFC3339 UTC |
| `actor` | User id, authentication method, session id |
| `source` | Client IP, client version |
| `action` | `model.enable`, `node.approve`, `token.revoke`, `config.commit`, `policy.apply`, … |
| `target` | Component, node, model, or user |
| `intent_hash` | SHA-256 of the rendered diff shown to the operator |
| `justification` | Required for mutations |
| `outcome` | `success`, `failure`, `partial` |
| `detail` | Exit status, error tail, objects changed |
| `prev_hash` | SHA-256 of the previous record |
| `hash` | SHA-256 over canonical JSON of this record, including `prev_hash` |

`actor`, `source` and `target` are objects, since each carries more than one value; `target`
is null for an action that has none. Every field is present in every record — an unset
optional is `null`, never absent and never an empty string, because absent, null and empty
are three different hashes.

### `v` and `install`

Both are inside the hash preimage, which is why they exist from the first record rather than
being added when they are first needed.

`install` is what lets records from several appliances be told apart once they are shipped
somewhere central. Every chain starts at `seq` 1 with the same all-zero `prev_hash`, so
without it they interleave indistinguishably, and a `prev_hash` that is unique per
installation reads as a fork. A shipper can tag by host, but a tag added outside the record
is one that whoever controls the shipper can change; inside the preimage it is bound to the
hash.

`v` is what allows the field set to grow. A set that can never change will eventually be
wrong; one that changes without a version is unverifiable, because re-encoding an older
record under a newer shape changes its hash and reports tampering that never happened. It is
`1`, and it is what will let the per-node sequence number below be added without
invalidating anything already written.

### `intent_hash`

The load-bearing field. It binds the preview an operator approved to what was actually
applied: at apply time the change is re-rendered, re-hashed, and **the operation refuses if
the hash no longer matches**.

This closes the window between "operator reads a diff" and "system performs an action" — a
window in which state can move underneath them. It is a genuine change-control gate for very
little code.

### `prev_hash`

Makes the log tamper-evident. Altering any record invalidates every hash after it.
`nodary audit verify` walks the chain and reports the first break by sequence number.

The chain does not prevent tampering; it makes tampering *detectable*. A compromised control
plane can rewrite the whole chain consistently. Shipping the JSONL mirror off-box is what
turns detection into something an attacker cannot quietly undo, and deployments that care
should do so.

### Storage and delivery

SQLite (WAL) is authoritative. The record exists when its transaction commits, in the same
transaction as the change it describes.

**Where records go afterwards is configuration.** A file — `/var/log/nodary/audit.jsonl` by
default — plus `stdout` for a container, `stderr` for a terminal, `none`, or any combination.
Delivery happens after the commit, so a destination can never block or roll back a change,
and a destination that fell behind is resynchronised from the database with
`nodary audit export --from-seq`. Each record carries `seq` and `hash`, so a receiver dedupes
and detects gaps without having to trust the sender.

Shipping off-box is what turns detection into something an attacker cannot quietly undo, and
a deployment that must demonstrate control should do it — to a SIEM with WORM retention, by
pointing a log shipper at the file. Records are not pushed by nodary itself: a serving
deployment has no outbound path by design ([03](03-agent.md#5-egress-isolation)), and a
shipper already solves retry, backpressure and credentials. `nodary audit verify --mirror`
validates any such copy, on a machine that has never seen the database it came from.

When a destination fails, the default is to report it and carry on
([NIST SP 800-171](https://csrc.nist.gov/pubs/sp/800/171/r2/upd1/final) 3.3.4 asks for an
alert on an audit logging failure, not a halt). A deployment may instead refuse further
mutations until delivery recovers. What is never configurable is whether the record is
written.

Agents generate records locally and forward them; they are chained on arrival at the server,
and node-local ordering is preserved by a per-node sequence number so a disconnected agent does
not lose events. An agent's queue is bounded and spills to disk; if it overflows, the drop is
itself recorded.

## 4. Policy profiles

A named, versioned object constraining what a deployment permits. Applying one is audited, and
the active profile is displayed on every relevant screen.

### What a profile cannot turn off

Some properties are the product rather than a posture, and no profile disables them:

- the audit chain itself — actor, action, target, outcome, `prev_hash` (§3);
- `intent_hash` binding an approved preview to what was applied (§2);
- release signature and digest verification ([01](01-install.md#2-the-installsh-contract));
- digest-pinned components ([ADR 0004](../adr/0004-release-artifacts-and-channels.md));
- egress isolation for serving deployments ([03](03-agent.md#5-egress-isolation)).

Each of these costs nothing at run time. What a profile adjusts is **ceremony** — how much a
human must do before a change is allowed — and **retention**, not whether the record exists.
This is the distinction that lets one codebase serve a homelab and a regulated site without
being two products.

### `default` — ships active

The profile a fresh install runs. It suits the common case: a few GPU machines, one or two
administrators, hardware they own outright.

```toml
[policy]
name = "default"

require_totp             = false   # ceremony, not security: the session already authenticated
require_justification    = false   # the audit record is still written, with actor and outcome
min_justification_length = 0
require_signed_artifacts = true    # free, and never the right thing to disable
allow_unattended_tokens  = true    # scripts and cron are the normal case here
allow_custom_backends    = true
allow_derived_images     = true
require_pinned_derives   = false

egress_default           = "deny"  # a serving deployment needs no outbound path
model_origin_allowlist   = []      # empty: any origin
require_model_manifest   = false

audit_retention_days     = 365
usage_retention_days     = 90
session_ttl_minutes      = 10080   # a week
token_max_ttl_days       = 3650
```

An operator restarting a model under this profile types `nodary model restart chat` and
nothing else. The chain still records who did it, when, against what, and whether it worked.

### `regulated` — for sites that must demonstrate control

```toml
[policy]
name = "regulated"

require_totp             = true
require_justification    = true
min_justification_length = 12
require_signed_artifacts = true
allow_unattended_tokens  = false
allow_custom_backends    = false
allow_derived_images     = true    # a FIPS override is the motivating case, not the risk
require_pinned_derives   = true

egress_default           = "deny"
model_origin_denylist    = ["CN"]
model_origin_allowlist   = ["US", "FR", "GB", "CA", "DE"]
require_model_manifest   = true

audit_retention_days     = 1095
usage_retention_days     = 90
session_ttl_minutes      = 30
token_max_ttl_days       = 365
```

The difference between the two profiles is entirely ceremony and retention. Both write the
same records; `regulated` demands a re-entered TOTP code and a written justification before
each mutation, holds evidence for three years, and constrains model provenance.

This is how one codebase serves both a homelab and a regulated deployment: the tool ships
profiles; a deployment chooses to apply one. It also makes the posture a **single reviewable
object** rather than something inferred from scattered code — worth as much to an assessor as
it is to a maintainer.

`nodary policy diff` compares the active profile against a candidate and shows exactly which
constraints would loosen. Loosening is permitted; doing it silently is not.

## 5. Control mapping

Most deployments will never need this section. It is here for the site that has to show an
assessor where its evidence lives — a small business under NIST SP 800-171 or CMMC 2.0, rather
than the homelab the `default` profile is written for.

The mapping assumes the `regulated` profile is active.

| Control family | Satisfied by |
| :--- | :--- |
| AU-2, AU-3, AU-12 | Audit chain — who, what, when, where, outcome |
| AU-9 | Hash chain, append-only mirror, store separate from what it audits |
| AU-11 | Retention windows; usage and audit separated (§3, [06](06-gateway.md#3-metering)) |
| AC-2 | User and **node** account lifecycle, including approval ([02](02-enrollment.md)) |
| AC-3, AC-6 | Roles, per-user model allowlists, least privilege by default |
| IA-2, IA-5 | Password plus TOTP, mTLS for agents, scoped tokens, single-display secrets |
| CM-3, CM-5 | Config revisions, attestation, `intent_hash` binding |
| SI-7 | Signed release artifacts, digest-pinned components, weights manifests, `audit verify` |
| SC-7 | Egress isolation with continuous assertion ([03](03-agent.md#5-egress-isolation)) |

This is a mapping, not a certification. It shows where the evidence lives.
