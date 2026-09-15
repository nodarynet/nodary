# 07 — Identity, audit & policy

## 1. Users and roles

| Role | May |
| :--- | :--- |
| `viewer` | Read state; read own usage |
| `user` | The above, plus use the inference API |
| `operator` | The above, plus enable, disable and restart models; stage weights; drain nodes |
| `admin` | Everything: configuration, catalog and backend registration, node approval, user and token management, policy |

Authentication is local: PBKDF2-SHA256 password hashing plus TOTP. The web interface uses
short-lived signed session cookies; the CLI uses personal tokens at `~/.nodary/credentials`
(mode 0600).

**PBKDF2 rather than argon2id**, which is the stronger password KDF and is not FIPS-approved.
[ADR 0006](../adr/0006-cui-boundary-and-fips.md) puts nodary inside a CUI boundary, and
arguing to an assessor that password hashing does not protect CUI confidentiality is more
expensive than the change — the argument may well be right and it still costs a meeting.
The salt is **at least 128 bits**, which Go's FIPS module enforces and which is therefore a
correctness requirement rather than a preference; Go enforces no iteration floor, so the cost
parameter is ours to choose and to raise on verify ([R2-42](../tasks/R2-control-plane.md)).

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
and a destination that fell behind is resynchronized from the database with
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

advisory_decision_days   = 30
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

advisory_decision_days   = 14
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

This section is for the primary audience: a small site under NIST SP 800-171 or CMMC Level 2
that has to show an assessor where its evidence lives ([00 §1](00-overview.md#1-scope)). A
homelab can skip it.

**It shows where evidence lives. It does not discharge a requirement.** Every requirement still
has an owner inside the operating organization, and the accuracy of the System Security Plan is
theirs — nodary's part is to make a claim in that plan something they can show. A row means
"when the `regulated` profile is active, the mechanism named is what an assessor would be
shown", and nothing more.

**The table itself is not here, and that is deliberate.** It lives in one place,
[`ee/evidence/crosswalk.go`](../../ee/evidence/crosswalk.go), because three things have to
agree about it: the `controls.json` and `controls.md` members of every evidence bundle, the
`narratives/` paragraphs written to be pasted into a plan, and the published page at
[`docs/compliance.md`](../../docs/compliance.md) that a buyer reads before they install
anything. A control mapping duplicated across three artifacts is one where two of them are
quietly wrong, and the one that is wrong is the one somebody pasted. Tests assert they agree.

**800-171 Revision 2, transcribed rather than recalled.** Every identifier and every quoted
requirement comes from NIST's own published requirements list for Rev 2. The section used to
carry 800-53 *control families* with a block quote saying they were an orientation and not
something to paste into a plan; that is what [R9-19](../tasks/R9-evidence-remediation.md)
replaced. NIST withdrew Rev 2 on 14 May 2024 in favour of Rev 3, and CMMC assesses Level 2
against Rev 2 anyway — 32 CFR part 170 is written against those 110 requirements and the
rulemaking that would move it is in progress rather than in force ([R9-20](../tasks/R9-evidence-remediation.md)).
The identifiers renumber when that lands.

The requirements the crosswalk holds evidence for, by family: access control (3.1.1, 3.1.2,
3.1.5, 3.1.7, 3.1.8, 3.1.11, 3.1.13), audit and accountability (3.3.1, 3.3.2, 3.3.8, 3.3.9),
configuration management (3.4.1, 3.4.2, 3.4.3, 3.4.5), identification and authentication
(3.5.1, 3.5.2, 3.5.3, 3.5.10), security assessment (3.12.2, 3.12.3, 3.12.4) and system and
communications protection (3.13.1, 3.13.6, 3.13.8, 3.13.11).

**What it is not evidence for is published beside it**, in the bundle and on the page: an index
listing only what it covers reads as though it covers everything, which is how a family nobody
looked at ends up marked as handled. Awareness and training, incident response, maintenance,
media protection, personnel security, physical protection and risk assessment are the
organization's, and the crosswalk says so by name.

This is a mapping, not a certification, and not an assessment.
