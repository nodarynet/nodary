# Evidence and NIST SP 800-171

nodary is built for a small organization that handles Controlled Unclassified
Information and has to answer for it. This page says exactly what the software
produces, which NIST SP 800-171 Revision 2 security requirements that evidence
speaks to, and — as plainly as the rest — which requirements it has nothing to
say about.

## What this page is, and what it is not

**It shows where evidence lives. It does not discharge a requirement.**

Every one of the 110 requirements has an owner inside your organization. The
accuracy of your System Security Plan is yours, an assessment is something an
assessor performs, and no software can hand you either. A row in the table below
means one thing: *when the `regulated` policy profile is active, this is the
mechanism, and this is the artifact you would put in front of someone who asked.*

You will not find the words "compliant" or "certified" on this page, and the
machine-readable copy of this table that ships inside every evidence bundle marks
each row `evidence` rather than `satisfied` for the same reason.

## Which revision, and why it is a withdrawn one

The identifiers here are **NIST SP 800-171 Revision 2** (February 2020, updated
28 January 2021).

NIST withdrew Revision 2 on 14 May 2024, superseded by Revision 3. CMMC assesses
Level 2 against Revision 2 anyway: 32 CFR part 170 is written against those 110
requirements, and the rulemaking that would move CMMC to Revision 3 is in
progress rather than in force. So Revision 2 is what a plan cites today, and
these identifiers will renumber when that changes.

Every identifier and every quoted requirement below is transcribed from NIST's
own published requirements list for Revision 2, not recalled and not summarized.
That is worth stating because a practice identifier that is nearly right is the
single most expensive error this page could contain — it would be pasted into a
plan and read by an assessor.

## The crosswalk

| Requirement | What NIST asks for | What nodary does | Where the evidence is |
| :--- | :--- | :--- | :--- |
| **3.1.1** | Limit system access to authorized users, processes acting on behalf of authorized users, and devices (including other systems). | Local accounts with roles, and — the devices half — a node that enrolls is `pending` until an administrator approves it, and receives no desired state until then. Approval records the inventory the node offered as what was agreed to. | `identity.jsonl`, `nodes.json` |
| **3.1.2** | Limit system access to the types of transactions and functions that authorized users are permitted to execute. | Four roles — viewer, user, operator, admin — checked on every verb by one authorization function, in the core both the CLI and the HTTP API call. Neither front end carries its own copy of the table. | `identity.jsonl`, `chain.jsonl` |
| **3.1.5** | Employ the principle of least privilege, including for specific security functions and privileged accounts. | A new account is the least-privileged role unless one is named. Configuration, backend registration, node approval and account management are admin-only; running inference is not. | `identity.jsonl` |
| **3.1.7** | Prevent non-privileged users from executing privileged functions and capture the execution of such functions in audit logs. | A refused act is recorded with its reason, not merely refused — so the chain carries the attempt as well as the privileged acts that succeeded. | `chain.jsonl` |
| **3.1.8** | Limit unsuccessful logon attempts. | Failed sign-ins lock out per account and per source after a threshold, and the refusal carries a Retry-After. The lockout is before the password hash is computed and before anything is written, so it cannot be used to spend the control plane's writer or to grow the chain. | `chain.jsonl` |
| **3.1.11** | Terminate (automatically) a user session after a defined condition. | Console sessions are server-side and expire on a lifetime the active policy profile sets. A restart of the control plane ends them all, because they are held in memory deliberately. | `chain.jsonl` |
| **3.1.13** | Employ cryptographic mechanisms to protect the confidentiality of remote access sessions. | Every administrative path is TLS: the console and the HTTP API on the control plane's certificate, and the agent protocol on mutual TLS against a CA the install generates. | `nodes.json` |
| **3.3.1** | Create and retain system audit logs and records to the extent needed to enable the monitoring, analysis, investigation, and reporting of unlawful or unauthorized system activity | Every administrative act writes a record inside the same transaction that performs it, so an act that happened and was not recorded is not a state this can reach. Retention is a policy setting, and audit and usage retention are separate. | `chain.jsonl`, `verify.txt` |
| **3.3.2** | Ensure that the actions of individual system users can be uniquely traced to those users, so they can be held accountable for their actions. | Each record carries the actor's account id and how they authenticated — password, token, session, node certificate or local root — and a credential resolves to the person it was issued to. The id is stable across a rename. | `chain.jsonl`, `identity.jsonl` |
| **3.3.8** | Protect audit information and audit logging tools from unauthorized access, modification, and deletion. | Each record hashes the one before it, so an edit or a deletion breaks the chain at the point it happened. The bundle's segment verifies standalone with `sha256sum` and `minisign` and needs neither nodary nor the database it came from. | `chain.jsonl`, `verify.txt` |
| **3.3.9** | Limit management of audit logging functionality to a subset of privileged users. | Retention and pruning are admin-only and are themselves recorded acts: the chain says what was pruned and through which sequence, so a gap is a documented gap rather than an absence. | `chain.jsonl` |
| **3.4.1** | Establish and maintain baseline configurations and inventories of organizational systems (including hardware, software, firmware, and documentation) throughout the respective system development life cycles. | Every `config apply` writes a revision carrying a complete configuration snapshot and its hash, so any past baseline can be produced exactly. The hardware inventory is what each node offered at approval. | `revisions.jsonl`, `nodes.json` |
| **3.4.2** | Establish and enforce security configuration settings for information technology products employed in organizational systems. | A policy profile — `default` or `regulated` — sets what is required and what is refused, and it is enforced rather than advisory. The bundle records which profile was active when it was made. | `controls.json` |
| **3.4.3** | Track, review, approve or disapprove, and log changes to organizational systems. | The attestation ceremony, and this is the requirement it was built for. A change is rendered as a preview, hashed, approved with a justification and — under `regulated` — a re-entered authentication code, and applied only against that hash. State that moved between the preview and the apply refuses the act rather than silently applying something else. | `revisions.jsonl`, `chain.jsonl` |
| **3.4.5** | Define, document, approve, and enforce physical and logical access restrictions associated with changes to organizational systems. | Who may change what is the role table; that a change was approved, by whom and why, is the attested record. The two are the same mechanism seen from either end. | `chain.jsonl`, `revisions.jsonl` |
| **3.5.1** | Identify system users, processes acting on behalf of users, and devices. | Users, credentials issued to a named user for a named purpose — including unattended ones a script holds — and nodes identified by a certificate the control plane's own CA issued at enrollment. | `identity.jsonl`, `nodes.json` |
| **3.5.2** | Authenticate (or verify) the identities of users, processes, or devices, as a prerequisite to allowing access to organizational systems. | Passwords for people, bearer tokens for programs, and mutual TLS for nodes. An unauthenticated request is never treated as an administrator, including on the machine hosting the control plane. | `identity.jsonl`, `nodes.json` |
| **3.5.3** | Use multifactor authentication for local and network access to privileged accounts and for network access to non-privileged accounts. | TOTP, and under `regulated` it is re-entered for the act rather than inherited from the session: a cookie proves somebody signed in at some point, and a code proves a person was present for this change. An act that legitimately carried no code records why. | `chain.jsonl`, `identity.jsonl` |
| **3.5.10** | Store and transmit only cryptographically-protected passwords. | PBKDF2-SHA256 with a salt of at least 128 bits, through Go's validated cryptographic module. A credential is stored as a hash and a prefix; the plaintext is displayed once, at creation, and there is nothing to read it back from. | `identity.jsonl` |
| **3.12.2** | Develop and implement plans of action designed to correct deficiencies and reduce or eliminate vulnerabilities in organizational systems. | An advisory that has not been decided within the window the profile sets becomes a plan-of-action item by the clock rather than by somebody remembering. The decision itself is an attested act with a justification. | `remediation.jsonl`, `chain.jsonl` |
| **3.12.3** | Monitor security controls on an ongoing basis to ensure the continued effectiveness of the controls. | The egress assertion runs on the node after every deployment start and its verdict rides the heartbeat, so the control is checked continuously rather than configured once. A verdict that moves in either direction is an event in the chain, which is how a window where the control was not in force stays reviewable afterwards. | `chain.jsonl`, `nodes.json` |
| **3.12.4** | Develop, document, and periodically update system security plans that describe system boundaries, system environments of operation, how security requirements are implemented, and the relationships with or connections to other systems. | The bundle's narratives describe how this install implements the requirements above, filled with this install's own values rather than with placeholders. The plan is the organization's document; these are the paragraphs about nodary that go in it. | `controls.md` |
| **3.13.1** | Monitor, control, and protect communications (i.e., information transmitted or received by organizational systems) at the external boundaries and key internal boundaries of organizational systems. | A deployment runs on a network with no route off the machine, and the assertion that proves it runs inside that deployment's own network namespace. The boundary is enforced where it is drawn rather than described in a document. | `chain.jsonl`, `nodes.json` |
| **3.13.6** | Deny network communications traffic by default and allow network communications traffic by exception (i.e., deny all, permit by exception). | Under `regulated` the egress default is deny, and a derived image is built behind an allowlist naming the one index it may reach. What a build reached is part of its record. | `chain.jsonl` |
| **3.13.8** | Implement cryptographic mechanisms to prevent unauthorized disclosure of CUI during transmission unless otherwise protected by alternative physical safeguards. | Inference and administration both cross the network over TLS, and the agent protocol is mutual TLS. A deployment's own port is published on loopback and is not reachable from off the machine. | `nodes.json` |
| **3.13.11** | Employ FIPS-validated cryptography when used to protect the confidentiality of CUI. | Every channel ships a binary built against Go's validated FIPS 140-3 cryptographic module, running with it in service for every approved algorithm. **nodary itself is not a validated product and will not become one** — the validation belongs to the module, and a claim that blurs the two is the kind this table exists to avoid. | `manifest.json` |

The right-hand column names members of the **evidence bundle**, which any
installation can export for a reporting period:

```sh
nodary evidence export --from 2026-01-01 --to 2026-03-31 --out q1.tar.gz
```

The bundle verifies with `sha256sum` and `minisign` alone — neither nodary nor
the database it came from is needed to check it, which is the property that
makes it evidence rather than a report.

## What this is not evidence for

An index that lists only what it covers reads as though it covers everything,
and that is how requirement families nobody has looked at end up marked as
handled in a plan. So, explicitly:

- 3.2 Awareness and Training — entirely organizational.
- 3.6 Incident Response — nodary produces evidence an investigation uses; it runs no incident response process.
- 3.7 Maintenance — host and hardware maintenance is outside what nodary manages, by design.
- 3.8 Media Protection — nodary holds no removable media and does not mark, transport or sanitize any.
- 3.9 Personnel Security — screening and termination are the organization's, though revoking what a leaver held is an act nodary records.
- 3.10 Physical Protection — nothing in software.
- 3.11 Risk Assessment — nodary reports advisories against what it runs; assessing organizational risk is not in it.
- 3.14 System and Information Integrity — the advisory feed contributes to flaw remediation and is reported under 3.12.2 rather than claimed twice here.

## Two claims worth stating precisely

**FIPS.** Every channel ships a binary built against Go's validated FIPS 140-3
cryptographic module, running with it in service for every approved algorithm.
**nodary itself is not a validated product and will not become one.** The
validation belongs to the module. A vendor page that blurs those two is exactly
the sort of statement this project exists not to make.

**Request content.** nodary records that a request happened — who, when, which
model, how many tokens — and never what it said. There is no free-text field in
the metering schema to write a body into, and a test drives a canary prompt
through the gateway and searches every byte of the database, its write-ahead log
and the gateway's log for it. The one place a container's own output is kept is
a failed deployment's last hundred log lines, which stay on that deployment,
are overwritten by its next failure, and are deliberately not carried into the
audit chain that leaves your boundary inside an evidence bundle.

## If you are being assessed

Start with `verify.txt` inside the bundle: it says what the chain verification
concluded and how to repeat it without trusting us. Then `controls.json` and
`controls.md`, which carry this same table with the policy profile that was
active when the bundle was made.
