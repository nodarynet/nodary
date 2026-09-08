# nodary

**Run LLMs on your own GPUs, and be able to show how.**

A *notary* verifies identity, attests to acts, and keeps an official register of what was
done. nodary does that for a small fleet of GPU hosts: nothing joins without approval, nothing
changes without an attributable, justified, hash-chained record, and a deployment reaches the
network only where somebody said it could.

It is built for **a small site that handles CUI and has to answer for it** — a supplier with a
handful of GPU boxes, subject to CMMC Level 2 and NIST SP 800-171, whose obligation is to write
a System Security Plan and keep it true.

**That obligation is yours and cannot be bought from a vendor.** nodary does not assess, does
not certify, does not make anyone compliant, and makes no zero-trust claim. No practice is
discharged by installing it. What it does is narrower and worth saying exactly: it enforces
particular mechanisms, and it records what happened, so the person writing your SSP is
describing something they can **show** rather than something they believe. The evidence is
verifiable without trusting us — `sha256sum` and `minisign` are enough
([13](docs/specs/13-evidence.md)).

Running a homelab instead? Same binary, same install, nothing gated. You are the community
edition rather than the target audience.

Orchestrators assume a cluster — a scheduler, a control loop, and someone to run them. nodary
assumes a handful of machines you own and administer directly, where placement is a decision
you make once and every change afterwards is recorded.

No Kubernetes. No Ansible. No Helm. No Terraform. No git-tracked manifest.

```sh
# control plane
curl -fsSL https://nodary.net/install.sh | sh -s -- server

# each GPU node — address and token printed by the command above
nodary node install \
    --server https://nodary.example.internal:8443 \
    --token nodary_jt_… --ca-fingerprint sha256:…
```

The same binary is also on PyPI, npm and Homebrew, and those are complete install paths rather
than conveniences — `pip install nodary && nodary server install` reaches the same state
([ADR 0004](docs/adr/0004-release-artifacts-and-channels.md)).

Nodes run Linux. A Windows machine with an NVIDIA GPU joins **inside WSL2**, where it is an
ordinary Linux node — same binary, same command, CUDA passed through from the host driver
([01](docs/specs/01-install.md#windows-hosts-run-as-wsl2-nodes)). macOS builds are the operator
CLI only.

## What it does

- **Enrolls nodes** with short-lived join tokens, issues them mTLS certificates, and holds them in `pending` until an administrator approves. A leaked token alone cannot place a machine into the serving fleet.
- **Runs model servers** as systemd units against containerd. vLLM, SGLang, llama.cpp and TensorRT-LLM are supported through declarative backend descriptors; adding another is a TOML file, not a code change.
- **Stages weights** with resumable, verified transfers, including a fully offline path for air-gapped sites.
- **Issues and revokes tokens**, meters every request against the person who made it, and enforces per-user rate and budget limits.
- **Records every administrative action** in a hash-chained, tamper-evident audit log, with a required justification and a hash binding the approved preview to what was actually applied.
- **Enforces policy profiles** — origin allow/deny lists, mandatory re-authentication, deny-by-default egress, retention windows — as one reviewable object rather than behaviour scattered through code.
- **Keeps prompts and completions out of its own records.** The metering schema is closed: no free-text body field exists to write into, a test fails if content reaches the database or a log, and LiteLLM's request logging is pinned off with the pinning asserted ([ADR 0006](docs/adr/0006-cui-boundary-and-fips.md)).

## Editions

One binary. Everything that *runs* the fleet is Apache 2.0; the commercial edition sells what
turns records into a deliverable a human assessor reads. An unlicensed install still carries
every commercial verb and explains what it would produce, rather than hiding it
([ADR 0005](docs/adr/0005-editions-and-the-advisory-feed.md)).

| | Apache 2.0 | Commercial |
| :--- | :--- | :--- |
| Control plane, agent, gateway, backends | ✔ | |
| The hash chain, `audit verify`, `audit export` | ✔ | |
| Enrolment, staging, guardrails, egress isolation | ✔ | |
| Both policy profiles, the FIPS build, OIDC, the SIEM sink | ✔ | |
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

## Specifications

| | Document |
| :--- | :--- |
| 00 | [Overview](docs/specs/00-overview.md) — architecture, scope, non-goals |
| 01 | [Installation](docs/specs/01-install.md) — artifacts, channels, roles, upgrade, uninstall |
| 02 | [Enrollment & trust](docs/specs/02-enrollment.md) — join tokens, mTLS, approval |
| 03 | [Agent & runtime](docs/specs/03-agent.md) — protocol, systemd units, egress isolation |
| 04 | [Backends](docs/specs/04-backends.md) — pluggable model servers |
| 05 | [Catalog & weights](docs/specs/05-catalog.md) — provenance, staging |
| 06 | [Gateway](docs/specs/06-gateway.md) — auth, metering, throttling |
| 07 | [Identity, audit & policy](docs/specs/07-identity-audit.md) |
| 08 | [Data model](docs/specs/08-data-model.md) |
| 09 | [HTTP API](docs/specs/09-api.md) |
| 10 | [CLI reference](docs/specs/10-cli.md) |
| 11 | [Failure modes](docs/specs/11-failure-modes.md) |
| 12 | [Node guardrails](docs/specs/12-node-guardrails.md) — local limits, maintenance windows, decommissioning |
| 13 | [Evidence & assessment](docs/specs/13-evidence.md) — the signed bundle an assessor reads |

### Decisions

| | Record |
| :--- | :--- |
| 0001 | [No orchestrator](docs/adr/0001-no-orchestrator.md) — systemd and containerd instead of Kubernetes |
| 0002 | [Go, redistributed through package-manager wrappers](docs/adr/0002-go-with-package-manager-wrappers.md) |
| 0003 | [LiteLLM as the data plane](docs/adr/0003-litellm-as-data-plane.md) |
| 0004 | [Release artifacts and install channels](docs/adr/0004-release-artifacts-and-channels.md) — one binary, four channels |
| 0005 | [Editions, the licence key, and the advisory feed](docs/adr/0005-editions-and-the-advisory-feed.md) — the mechanism is free, the proving is paid |
| 0006 | [The CUI boundary and the FIPS build](docs/adr/0006-cui-boundary-and-fips.md) — what nodary may hold, and the crypto that holds it |
| 0007 | [The component manifest as an independent artifact](docs/adr/0007-independent-component-manifest.md) — patch on the customer's timeline, not ours |
| 0008 | [containerd, not podman](docs/adr/0008-container-runtime.md) — measured on security and deployment |

### Implementation

[docs/tasks/](docs/tasks/) tracks the work derived from the specifications above — the
milestone breakdown, what is done, and what is next. The specifications are authoritative;
the tracker follows them.

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

**The MVP route is complete.** A single command installs a control plane, prints a one-time
link that creates the first administrator with a password nobody else ever knows, and stages
the runtime every GPU host bootstraps from. A node enrols, speaks the agent protocol, and
reconciles itself onto its desired state through systemd. The gateway authenticates,
authorises, proxies and meters. The evidence bundle is signed, and the advisory feed has a
format and a verb that reads it.

**Verified as root on real hardware**, not only in tests: 36 checks with 0 failures, including
a live container on the isolated network with the probe run inside its namespace — no default
route, no DNS, no reachable address — while its published port still answered on `127.0.0.1`.
That run found sixteen defects no unit test could have, and each one is recorded where it
happened.

| | | |
| :--- | :--- | :--- |
| **R0** Release pipeline | done | one signed binary through four channels, tamper rejection tested |
| **R1** Core, audit, identity | done | the hash chain, attestation, policy profiles, roles, TOTP |
| **R2** Control plane | 28 of 42 | schema, revisions, the HTTP API, the shared core, TLS and the PKI |
| **R9** Evidence | 14 of 20 | the signed bundle, verifiable with `sha256sum` and `minisign` alone; the advisory feed's format and `advisory check` |
| **R4** Agent | 17 of 37 | enrolment, pinning, mTLS, desired state, heartbeat, guardrails, staging, reconcile, units, health, egress isolation |
| **R6** Backends | 2 of 12 | the descriptor schema and argument translation, vLLM and SGLang |
| **R3** Gateway | 9 of 16 | the OpenAI surface, service keys, the route allowlist, metering, LiteLLM |
| **R5** Install | 13 of 27 | both installs end to end, the layout and its ownership, the setup link, `--with-node`, preflight, `doctor` |

What works today: `nodary server install && nodary server start` brings up a TLS control
plane; users, tokens, policy profiles and configuration revisions are administered from the
CLI or the API, and every mutation is previewed, justified, hash-chained and exportable as an
evidence bundle an assessor can verify without nodary installed. A GPU host runs `nodary node
enroll`, pins the control plane by a fingerprint carried out of band, receives a client
certificate, and long-polls its desired state — and receives nothing until an administrator
approves it. `nodary agent plan` renders exactly what that node would run — the argv translated
through the backend descriptor, the unit's environment file, and a verdict on weights verified
byte by byte against a manifest stock `sha256sum` can also check — and `nodary agent run`
reconciles it: writing the environment file, loading `nodary-model@.service`, starting the
instance, polling its health, and reporting inventory, staging and unit state back. After every
start it asserts the deployment has no route off-box, cannot resolve a name, and cannot reach
an external address — with a control run on the host, so an assertion that passed for the wrong
reason reports `inconclusive` rather than compliant.

A client then calls `/v1/chat/completions` with a service key, is checked against the routes it
has been granted, and is proxied through LiteLLM — which nodary configures with request logging
pinned off and asserts before use. Every request produces one usage row of counts, and none of
it records what the request said: a canary prompt is sent through the gateway and every byte of
the database, its write-ahead log and the gateway's log is searched for it.

`nodary server install` resolves containerd, `nerdctl`, the CNI plugins and runc against the
embedded manifest, verifying each digest before it lands, and then serves that cache to nodes
over the same mTLS the agent protocol uses — so a GPU host bootstraps without reaching the
internet at all. `nodary node install` fetches from it, places the runtime, creates the
isolated network, enrols, and starts the agent; `--with-node` does both on one machine and
waits for the control plane's own port before enrolling into it.

The install ends with a one-time URL, valid for fifteen minutes, single-use, that creates the
first administrator. **No default password ever exists** — a generated one printed at install
is a default until somebody changes it, and an open `/setup` is a default that lasts until
somebody notices.

`nodary doctor` diagnoses a host in one list — platform, systemd, cgroup v2, driver floor, GPU
enumeration, disk, swap, LSM, certificate expiry, clock skew against the control plane — and
re-runs the egress assertion rather than trusting that it passed when the deployment started.

What does not, stated as plainly: **no real model has been served end to end yet.** The runtime
is placed and a container starts on the isolated network, but the path from a staged weight to
a vLLM process answering a completion has not been run. Throttling is recorded and not
enforced. Only vLLM and SGLang have descriptors — llama.cpp and TensorRT-LLM need descriptor
features that do not exist, and shipping one anyway would claim a backend the binary cannot
run. There is no UI. The offline bundle, upgrade and uninstall are unbuilt, the control index
ships as a stub that says `"status": "unmapped"` for every entry rather than guessing at a
mapping somebody would paste into an SSP, and the advisory feed has a format and a reader but
no decision workflow behind it. The route so far is [docs/plans/mvp.md](docs/plans/mvp.md).

```sh
make check           # gofmt, vet, tests
make packages        # cross-compile, then build wheels and npm packages
make test-install    # install.sh end to end, including tamper rejection
make test-packages   # the built wheels and npm packages install and run
```

## License

Apache 2.0.
