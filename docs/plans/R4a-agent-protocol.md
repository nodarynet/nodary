# R4a — Enrolment and the agent protocol

**Slice of:** [R4](../tasks/R4-agent.md) ·
**Tasks:** R4-01 – R4-04, R4-07 – R4-09 · **Status:** complete

The control plane's half of [S5](mvp.md#4-the-route). Everything here is server-side plus
the smallest client that proves it: a node that enrols, is refused a workload until somebody
approves it, long-polls a desired state, and heartbeats. The agent that *acts* on that
document is R4b; the isolation it acts under is R4c.

## Why these seven tasks are one slice

None of them is provable alone. An enrolment endpoint with nothing behind mTLS issues a
certificate nobody has demonstrated works. A long-poll with no enrolment has no caller that
could reach it. [R4-04](../tasks/R4-agent.md)'s guarantee — *a `pending` node can heartbeat
and cannot serve* — is a statement about all three endpoints at once, and it is the sentence
[02 §2](../specs/02-enrollment.md#2-why-approval-is-a-separate-step) exists to make true.

So the slice boundary is the protocol, and the test that closes it is one node walking the
whole of [02 §1](../specs/02-enrollment.md#1-flow): mint, enrol, poll (empty), approve, poll
(populated), heartbeat.

## 1. The pin is checked during the handshake, not fetched before it

**Decided.** The agent dials with `InsecureSkipVerify: true` and a `VerifyPeerCertificate`
that compares SHA-256 of the leaf DER against `--ca-fingerprint`. Chain validation is off;
an exact key match replaces it.

**Why.** [02 §1](../specs/02-enrollment.md#1-flow) says the agent "fetches the CA certificate
on first contact and refuses it unless the fingerprint matches". Verifying inside the
handshake *is* first contact, and it is the only reading with no window in it. `--insecure`
plus an exact pin being stricter than CA validation rather than weaker is already the
argument [01 §5](../specs/01-install.md#5-node-install) makes for the `curl --pinnedpubkey`
form; this is the same trade in Go.

**Rejected — fetch `/ca.crt` over an unverified connection, compare, then reconnect trusting
it.** It matches the sentence in the specification literally. It also makes two connections
where one will do, and the first of them is unauthenticated: anything that answers gets to
choose what the second one trusts, and check-then-use across two TCP connections is a race
by construction.

## 2. The CSR contributes a public key and nothing else

**Decided.** The server ignores the CSR's subject entirely. The certificate's common name is
the node name from the enrolment request, which is also the name recorded in `node`.

**Why.** The CSR is attacker-controlled input on the one unauthenticated endpoint in the
product, and its subject would otherwise become the fleet identity that mTLS then trusts. A
node whose certificate says `gpu-01` and whose row says `gpu-02` is a state nothing later
could reconcile.

**Rejected — honour the CSR's common name and drop the name field.** One less field, and it
is what most PKIs do. It puts the naming decision in the hands of whoever holds the token,
and it makes the certificate and the database disagreeable in a way no constraint catches.

## 3. Enrolment is audited through `audit.Log.Act`, not `core.Act`

**Decided.** `POST /api/v1/enroll` calls the log directly, with
`Actor{ID: <node>, Method: "join-token"}`.

**Why.** [`core.Act`](../../internal/core/core.go) runs the attestation ceremony of
[07 §2](../specs/07-identity-audit.md#2-attestation) — justification, intent binding, TOTP —
against a principal with a role. An enrolling node has none of those, and the precedent is
already in the codebase: `login` is a mutation performed by somebody who is not yet a
principal, and it takes the same path.

**Rejected — give the agent a synthetic principal so it can use `core.Act`.** Uniform, and
it would mean one orchestration rather than two entry points. It requires inventing a role
for machines, which is an authorisation decision nobody has made, and it would demand a TOTP
code from a process with no human attached — which the ceremony would then have to learn to
exempt, one exemption away from being exemptable by anything.

## 4. What a human decided is audited; what a machine observed is not

**Decided.** Enrolment, approval and revocation go through `audit.Log.Act`. The heartbeat
writes `last_seen`, `agent_version`, `protocol` and reported inventory through
`store.WriteTx` and produces no audit record.

**Why.** This is the `usage` table's rule
([0006_fleet.sql](../../internal/store/migrations/0006_fleet.sql)) applied to the node table.
A record every 15 seconds per node is not evidence, it is telemetry with an evidence-shaped
cost: the chain is what an assessor reads, and burying six administrative acts a month under
a hundred and seventy thousand heartbeats makes it unreadable while making every export
larger.

The line is not "cheap versus expensive". It is **decision versus observation**, and it is
the same line [`config.Snapshot`](../../internal/config/snapshot.go) already draws for
revisions. The heartbeat's write is one statement over a fixed column list so that the
distinction is visible in the code rather than only here.

**Rejected — audit the heartbeat at a reduced rate, or on change.** Keeps the seam
absolutely uniform. "On change" means reported inventory, which changes when a GPU falls off
the bus — an event [R4-25](../tasks/R4-agent.md) already handles properly — and a rate limit
inside the seam is a rule about when not to record, which is exactly the kind of rule this
product does not want anywhere near the audit chain.

### The gate that had to be widened, and by how much

`TestNothingBypassesTheSeam` in [internal/audit](../../internal/audit) scans every non-test
file for `.WriteTx(` outside a short list of directories, and it caught the heartbeat
immediately — correctly. The fix is not an exemption for `internal/api`, which would put
every handler in the product outside the gate in order to let one write through. It is
[`internal/observed`](../../internal/observed): one directory, on the list, whose package
comment carries the rule it is allowed to exist under and whose every statement names its
columns explicitly, so the rule can be checked by reading it.

`node.state`, `approved_by` and `approved_at` appear in none of those statements. A node
cannot promote itself by reporting that it has.

R3's usage rows belong there too, for the same reason — which is the evidence this is a
category rather than a convenience carved out for one endpoint.

## 5. Staleness is derived at read time, never stored

**Decided.** `node.state` keeps its five values. A node whose `last_seen` is older than 60
seconds renders `"stale": true` alongside its state.

**Why.** [11 §1](../specs/11-failure-modes.md#1-control-plane-and-agent) says a node is
marked `stale` after 60s of silence. Storing it would need something to do the marking — a
sweeper goroutine, a lifecycle, and a window in which the database says `ready` about a node
that has been gone for a minute. A node is stale whether or not anybody wrote it down, and
the read that cares can subtract two timestamps.

It also keeps staleness out of the configuration snapshot, which
[R2b](R2b-revisions.md) requires: `state` is in the snapshot, and a revision that differed
because a node missed a heartbeat would make `config diff` unreadable.

**Rejected — a `stale` state in the CHECK constraint.** One column, no arithmetic at read
time. It conflates a decision (`draining`) with an observation, and it makes recovery a
write: the node comes back, and something has to remember what state it was in before.

## 6. `rev` is the configuration revision sequence

**Decided.** The desired-state document's `rev` is the sequence number of the latest
[revision](R2b-revisions.md). The long-poll returns when that exceeds the caller's `rev`.

**Why.** The hash-chained revision counter already exists, already advances on every
configuration change, and is already the thing `config` and the API agree on. A node that
wakes for a change on another node pays one round trip and sees a document identical to the
one it holds.

**The one gap this exposes, and closes:** `node approve` and `node drain` change
`node.state`, which *is* in the snapshot, and they were not recording a revision. So the
configuration chain had a hole in it before this slice needed one — the transitions now
record a revision like every other configuration change.

**Rejected — a per-node revision counter.** Precise: a node wakes only for its own changes.
It is a second counter to keep in step with the first, and the failure mode of drifting apart
is a node that never wakes.

## 7. The long-poll polls

**Decided.** The handler re-reads the revision sequence once a second for up to 60 seconds,
and returns as soon as it moves or the client goes away.

**Why.** It is a read of one indexed row against SQLite in the same process. For a fleet an
SMB runs, the cost is unmeasurable, and the alternative is a broadcast mechanism with a
subscriber lifecycle, which is a thing to get wrong for no benefit anybody can perceive. The
ceiling is named in the code: it becomes worth replacing when the node count makes a
once-a-second read hot, and not before.

**Rejected — a `sync.Cond` fanned out from the writer.** Correct, no polling, wakes
instantly. It couples the writer to the reader's lifecycle, and it is wrong the moment there
is a second process writing the database — which is not hypothetical, because the CLI writes
directly.

## 8. Re-enrolment is allowed only once the certificate has expired

**Decided.** Enrolling a name that already exists is refused, unless the recorded certificate
has expired — in which case a new one is issued and the node keeps its state and its
approval.

**Why.** Both halves are in [02 §3](../specs/02-enrollment.md#3-certificate-lifecycle): "a
node offline past expiry must re-enroll with a fresh token", and a leaked token must not get
a workload. Without the expiry condition, a leaked token plus a guessed name replaces a live
node's certificate — and because the node is already approved, the replacement is approved
too, which defeats [02 §2](../specs/02-enrollment.md#2-why-approval-is-a-separate-step)
entirely.

**Rejected — refuse every duplicate name and require `node revoke` first.** Simpler, and it
puts an administrator in the loop. The administrator is already in the loop: they had to mint
the token. It also makes routine certificate expiry — which happens on a schedule, unattended,
possibly while nobody is watching — into an incident.

## 9. A deployment's image joins the configuration snapshot now

**Decided.** `config.Deployment` gains `Image` — the pinned `repo@sha256:…` the deployment
runs — mapped to the `image_digest` column that [08 §1](../specs/08-data-model.md) already
had.

**Why.** [03 §2](../specs/03-agent.md#2-desired-state-document)'s desired-state document
carries `image`, and R4-08 says the document is a *complete* end state. Without this the
document has a hole in it that nothing before R6 could fill.

The timing is not incidental. `config.Snapshot` is a hash preimage, and
[mvp §2](mvp.md#2-the-rule-that-decides-what-gets-built) puts preimages in the column that
cannot be retrofitted: adding a field to it later invalidates every revision chain a
customer already holds. Doing it now costs a struct field. Doing it after the first customer
export costs their history.

**Rejected — leave `image` empty until the backend catalog (R6) resolves it.** Correct in
the end state, and it defers a decision. It defers the *one* decision the plan says must not
be deferred, and it leaves the MVP unable to start a model at all.

## 10. The shape

| | |
| :--- | :--- |
| `internal/agent` | The node's half: `agent.toml`, the pinned HTTP client, `Enroll` |
| `internal/api/enroll.go` | `POST /api/v1/enroll` |
| `internal/api/agent.go` | mTLS identity, `GET /agent/desired`, `POST /agent/status` |
| `internal/api/pki.go` | `LoadAgentCA`, `SignAgentCertificate` |
| `internal/identity/token.go` | `RedeemJoinToken` |
| `internal/cli/node.go` | `nodary node enroll` |

`nodary node enroll` is a new verb. [10 §1](../specs/10-cli.md#1-surface) listed `node
install`, which [01 §5](../specs/01-install.md#5-node-install) defines as six steps of which
enrolment is one; the other five are components, the CNI network and the units, and they are
R4c and R5. Enrolment is separately runnable regardless, because
[02 §3](../specs/02-enrollment.md#3-certificate-lifecycle) requires re-enrolment after expiry
and that is not a reinstall. The specification gains the verb rather than the verb pretending
to be the installer.

## 11. Steps

- [x] `RedeemJoinToken` — burned in one statement, replay refused
- [x] Migration 0009: `cert_expires_at` on `node`
- [x] `LoadAgentCA` and `SignAgentCertificate`
- [x] `POST /api/v1/enroll`
- [x] mTLS on the listener; node identity from the verified client certificate
- [x] `internal/agent`: the pinned client, `agent.toml`, `Enroll`
- [x] `nodary node enroll`
- [x] `GET /api/v1/agent/desired?rev=N`
- [x] `POST /api/v1/agent/status`
- [x] Approval records the offer, and the transitions record a revision
- [x] The end-to-end test: mint → enrol → poll empty → approve → poll populated → heartbeat

## 12. What this slice changed outside itself

- [10 §1](../specs/10-cli.md#1-verbs) gains `node enroll`, and
  [01 §5](../specs/01-install.md#5-node-install) says why it is separately runnable.
- [02 §3](../specs/02-enrollment.md#3-certificate-lifecycle) gains the re-enrolment
  condition and the supersession rule — §8 above.
- [08 §1](../specs/08-data-model.md) gains `cert_expires_at` on `node`.
- **A defect found on the way through.** `GET /api/v1/audit` returned Go's exported field
  names — `Seq`, `TS`, `IntentHash` — while `GET /api/v1/audit/export` returned the
  canonical `seq`, `ts`, `intent_hash` that the hash is taken over. Same server, same
  records, two vocabularies, and a client reading one could not match a field in the other.
  `Record` now marshals through `members()`, which is already documented as the only place
  those names exist.

## 13. Open items

- R4-04 is closed here; the guardrail group (R4-13 – R4-17) is R4b, and R4-14 – R4-17 are
  not in the MVP at all · [mvp §6](mvp.md#6-what-an-mvp-install-cannot-claim)
- `probeGPUs` shells out to `nvidia-smi` and has no test, because a test would either need a
  GPU or would assert against a stub of our own writing. The reasoning for asking the driver
  rather than the filesystem is in the code, and the spike measured it.
