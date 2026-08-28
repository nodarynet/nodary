# 02 — Enrollment & trust

The security-critical path. Designed rather than inherited.

## 1. Flow

1. An administrator mints a **join token**: `nodary token join --ttl 1h --uses 1`. Format `nodary_jt_<random>`. Minting is audited.
2. The node pins the control plane by **CA fingerprint**, printed by `nodary server install` and carried out of band to the node by the operator. The agent fetches the CA certificate on first contact and refuses it unless the fingerprint matches. `--ca-fingerprint` is **required** for a network install; an offline install takes the CA from the bundle, where the release signature already covers it.
3. The agent generates a keypair and sends a CSR with the join token to `POST /api/v1/enroll` over TLS, together with what it is offering — GPU indices, deployment ceiling, permitted backends ([12](12-node-guardrails.md#4-reported-inventory)).
4. The server validates the token, decrements its remaining uses, issues a **client certificate** (90-day default lifetime), and records the node as `pending`.
5. All subsequent agent traffic is mTLS. The join token is burned and is never reusable.
6. **An administrator approves the node** — `nodary node approve <name>` — before it is eligible for any deployment.

Enrollment is a **mutual agreement**. The administrator approves the node; the node's
advertised offer and constraints are recorded in the same audit record. Neither side can later
claim terms the other did not see.

## 2. Why approval is a separate step

Most cluster software treats possession of a join token as sufficient to become a working
member. nodary does not. A leaked token gets a machine a certificate and a row in the node
table; it does not get it a workload, weights, or a route.

Machine identities are accounts, and are managed as accounts: created, approved, audited,
suspended, revoked. The approval record names the administrator and carries their
justification.

## 3. Certificate lifecycle

- Agents renew at two-thirds of certificate lifetime over the existing mTLS channel.
- A node offline past expiry must re-enroll with a fresh token — which requires an administrator, by design.
- `nodary node revoke <name>` invalidates the certificate immediately, stops scheduling, and instructs the agent to stop all deployments. If the agent is unreachable the revocation still takes effect at the server, and the node's certificate is refused on next contact.
- `nodary node leave` is the node-side counterpart, run on the machine itself, and does not require the control plane to be reachable ([12](12-node-guardrails.md#5-decommissioning)).

## 4. Token types

| Prefix | Kind | Lifetime | Purpose |
| :--- | :--- | :--- | :--- |
| `nodary_jt_` | Join token | Minutes to hours, N uses | Node enrollment only |
| `nodary_sk_` | Service key | Configurable, default 365d | Inference API access ([06](06-gateway.md)) |
| `nodary_pt_` | Personal token | Session-scoped or explicit | CLI and API access as a user |

All are stored as SHA-256 hashes. Plaintext is displayed exactly once, at creation. A distinct
prefix per kind makes them greppable in logs and recognisable to secret scanners.

## 5. Threat notes

| Scenario | Outcome |
| :--- | :--- |
| Join token leaks | Attacker enrolls a node; it sits `pending` with no workload. Administrator sees an unexpected node and revokes |
| Agent host compromised | Attacker holds one node's certificate. Scope is that node's deployments; it cannot mint tokens, approve nodes, or read the audit chain |
| Control plane compromised | Total. This is the trust root — treat `/etc/nodary/secret.key` and the agent CA key accordingly |
| Server certificate spoofed | Agent refuses any CA certificate whose fingerprint does not match the one supplied out of band. Defeating this means compromising the channel the operator read the fingerprint from, not the network |
| Stolen backup of `nodary.db` | Secrets at rest are encrypted with `/etc/nodary/secret.key`, which is not in the backup ([08](08-data-model.md#4-secrets-at-rest)) |
