# nodary

**Run LLMs on your own GPUs, and be able to show how.**

A *notary* verifies identity, attests to acts, and keeps an official register of what was
done. nodary does that for a small fleet of GPU hosts: nothing joins without approval, nothing
changes without an attributable, justified, hash-chained record, and a deployment reaches the
network only where somebody said it could.

It is built for **a small site that handles CUI and has to answer for it** — a supplier with a
handful of GPU boxes, subject to CMMC Level 2 and NIST SP 800-171, whose obligation is to write
a System Security Plan and keep it true. **That obligation is yours and cannot be bought from a
vendor.** nodary does not assess, does not certify, does not make anyone compliant, and makes no
zero-trust claim. It enforces particular mechanisms, and it records what happened, so the
person writing your SSP is describing something they can **show** rather than something they
believe. The evidence is verifiable without trusting us — `sha256sum` and `minisign` are
enough ([13](docs/specs/13-evidence.md)).

Running a homelab instead? Same binary, same install, nothing gated. You are the community
edition rather than the target audience.

Orchestrators assume a cluster — a scheduler, a control loop, and someone to run them. nodary
assumes a handful of machines you own and administer directly, where placement is a decision
you make once and every change afterwards is recorded. No Kubernetes, no Ansible, no Helm, no
Terraform.

```sh
curl -fsSL https://nodary.net/install.sh | sh -s -- server --with-node --host <this-host>
```

installs the control plane and enrolls this GPU as its first node in one step.

Prefer being asked to remembering flags? `curl -fsSL https://nodary.net/install.sh | sh`
places the binary and stops; `sudo nodary install` then walks the whole thing as a short
conversation — install, enroll, approve, stage, register, grant and a key — running the same
verbs on your behalf. **[Getting started
→](https://nodarynet.github.io/nodary/getting-started/)** is that route;
**[administering a fleet →](https://nodarynet.github.io/nodary/administering/)** is the
verbs one at a time, for a third node, a script, or a flag the wizard never asks about.

The same binary is also on PyPI, npm and Homebrew, and those are complete install paths rather
than conveniences — `pip install nodary && nodary server install` reaches the same state
([ADR 0004](docs/adr/0004-release-artifacts-and-channels.md)). Nodes run Linux; a Windows
machine with an NVIDIA GPU joins **inside WSL2** as an ordinary Linux node
([01](docs/specs/01-install.md#windows-hosts-run-as-wsl2-nodes)). macOS builds are the operator
CLI only.

## What it does

- **Enrolls nodes** with short-lived join tokens, issues them mTLS certificates, and holds them in `pending` until an administrator approves. A leaked token alone cannot place a machine into the serving fleet.
- **Runs model servers** as systemd units against containerd, through declarative backend descriptors — vLLM and SGLang today; adding another is a TOML file, not a code change.
- **Stages weights** with resumable, verified transfers, including a fully offline path for air-gapped sites.
- **Issues and revokes tokens**, meters every request against the person who made it, and enforces per-user rate and budget limits — `rpm`, `tpm`, `daily_tokens` and `max_concurrent`, per user, per role and globally, with a `429` that names which limit was hit and when it clears.
- **Records every administrative action** in a hash-chained, tamper-evident audit log, with a required justification and a hash binding the approved preview to what was actually applied.
- **Carries policy as one reviewable object** rather than behavior scattered through code — mandatory
  re-authentication, justification floors, credential lifetimes and deny-by-default egress are in force.
  Origin allow/deny lists and retention windows are not: `nodary policy show` marks every setting nothing
  acts on yet and names the task that will enforce it, because a profile gets read as a list of controls.
- **Keeps prompts and completions out of its own records.** The metering schema is closed: no free-text body field exists to write into, a test fails if content reaches the database or a log, and LiteLLM's request logging is pinned off with the pinning asserted ([ADR 0006](docs/adr/0006-cui-boundary-and-fips.md)).

## Editions

One binary. Everything that *runs* the fleet is Apache 2.0; the commercial edition sells what
turns records into a deliverable a human assessor reads. An unlicensed install still carries
every commercial verb and explains what it would produce, rather than hiding it
([ADR 0005](docs/adr/0005-editions-and-the-advisory-feed.md)).

| | Apache 2.0 | Commercial |
| :--- | :---: | :---: |
| Control plane, agent, gateway, backends | ✔ | |
| The hash chain, `audit verify`, `audit export` | ✔ | |
| Enrollment, staging, egress isolation | ✔ | |
| Both policy profiles | ✔ | |
| `nodary evidence export` — the signed bundle | | ✔ |
| The control index and SSP narratives | | ✔ |
| The signed advisory feed, and `nodary advisory check` against it | mechanism | content |

In one sentence: **we do not sell security, we sell the paperwork.** The feed is a report of
what public sources say about the digests nodary pins, at the time it was generated — not a
warranty, and not a substitute for vulnerability management. That statement ships inside every
revision, not only here.

## Design in one paragraph

A control plane owns all state in a single SQLite file. Node agents hold an outbound
long-poll to it, receive a desired-state document, and reconcile toward it: staging weights,
writing systemd units, starting containers, reporting status. The control plane never dials a
node, so nodes need no inbound firewall rules and no listening SSH. Operators reach the system
over SSH and run `nodary` verbs on the host, or through the HTTP API; both call the same core
functions, and every mutating call passes through the audit layer.

## Documentation

| | |
| :--- | :--- |
| **[Documentation site](https://nodarynet.github.io/nodary/)** | Getting started — install to a served, metered model |
| [docs/specs/](docs/specs/) | The specifications — what every component is required to do, numbered 00–13 |
| [docs/adr/](docs/adr/) | Decision records — why it's built this way, and what was rejected |
| [docs/tasks/](docs/tasks/) | The implementation tracker — what's done, what's next; the specs are authoritative and the tracker follows them |

## Verifying a release

Every release artifact is signed. The release public key fingerprint is published here so it
can be checked against a source other than the one serving the download:

```
minisign  RWRYtHqer6FbV8fMD5CEK+XBDBiX++arPJsueLpwXAowfcYBj6bwEWJD
openssl   SHA256:ec401b74444511fa2ee060cfbb39e1411e77884dfab2223576509e1396457900
```

`install.sh` verifies the signature and digest before it will place anything, and has no
override flag ([01](docs/specs/01-install.md#2-the-installsh-contract)).

## Status

**The MVP route is complete and verified as root on real hardware**, not only in tests: a
control plane and a GPU node install end to end, a node enrolls and is approved, weights are
staged and verified, a model is deployed onto an isolated network with no route off the box,
and served through the gateway — metered, with one usage row recording counts and no prompt
text anywhere in the database. `nodary doctor` diagnoses a host in one pass, including a live
re-run of the egress assertion. The route is [docs/plans/mvp.md](docs/plans/mvp.md).

**What it cannot do yet.** The record-keeping is ahead of the enforcement, and the difference
matters more here than in an ordinary roadmap gap: a capability described as enforced, which is
really an object the system stores and displays, hands an SSP author language for a control that
is not in force. So the list is here on the front page rather than only in a plan.

| Not yet enforced | State | Lands in |
| :--- | :--- | :--- |
| Model origin allow/deny lists | parsed, validated and diffed; checked nowhere | [R4-32](docs/tasks/R4-agent.md) |
| Retention windows | displayed; nothing prunes | [R2-14](docs/tasks/R2-control-plane.md), [R3-13](docs/tasks/R3-gateway.md) |
| Node guardrails | `node.toml` is parsed and reported, and enforced nowhere | [R4-14 – R4-16](docs/tasks/R4-agent.md) |

| Not built | Lands in |
| :--- | :--- |
| Backup, restore, upgrade, uninstall, the offline bundle | [R2-37](docs/tasks/R2-control-plane.md), [R5-13 – R5-17](docs/tasks/R5-install.md) |
| A network audit sink — ship `audit.jsonl` to WORM storage yourself until then | [R2-41](docs/tasks/R2-control-plane.md) |
| Remote administration: `--server` is specified and unimplemented, so every administrator needs root on the control plane and privileged acts attribute to `root`/`local` | [R2-21 – R2-32](docs/tasks/R2-control-plane.md) |
| A UI of any kind | [R7](docs/tasks/R7-ui-readonly.md), [R8](docs/tasks/R8-ui-mutating.md) |
| A FIPS-validated artifact — CI proves the tree builds and passes under `GODEBUG=fips140=on`, and ships nothing | [R5-25/26](docs/tasks/R5-install.md) |
| OIDC, and backends beyond vLLM and SGLang | — |

| | | |
| :--- | :--- | :--- |
| **R0** Release pipeline | 26 of 26 | one signed binary through four channels, tamper rejection tested |
| **R1** Core, audit, identity | 38 of 38 | the hash chain, attestation, policy profiles, roles, TOTP |
| **R2** Control plane | 29 of 42 | schema, revisions, HTTP API, shared core, TLS/PKI, fleet reads (`node list`/`show`), `model register` |
| **R3** Gateway | 12 of 16 | the OpenAI surface, service keys, route allowlist, metering, throttling and quota, LiteLLM kept in sync automatically |
| **R4** Agent | 28 of 41 | enrollment, pinning, mTLS, desired state, heartbeat, guardrails (parsed and reported, not enforced), local and remote staging with restage/unstage, reconcile, health-gated ready, egress isolation |
| **R5** Install | 18 of 32 | both installs end to end, `nodary install` (the interactive route), layout and ownership, the setup link, `--with-node`, preflight, `doctor` |
| **R6** Backends | 4 of 14 | descriptor schema, argument translation, container environment (incl. WSL2); vLLM and SGLang |
| **R9** Evidence | 14 of 21 | the signed bundle, verifiable with `sha256sum` and `minisign` alone; the advisory feed's format and `advisory check` |

```sh
make check           # gofmt, vet, tests
make packages        # cross-compile, then build wheels and npm packages
make test-install    # install.sh end to end, including tamper rejection
make test-packages   # the built wheels and npm packages install and run
```

## License

Apache 2.0.
