# nodary

**One control plane - All of your GPU nodes.**

nodary manages LLM serving across your GPU hosts from one central control point, with controls
and logging over users, usage and models. It installs with a single command, enrolls nodes
with a token, runs model servers under systemd, and puts identity, metering, throttling and a
tamper-evident audit trail in front of them.

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

## Why the name

A *notary* verifies identity, attests to acts, and keeps an official register of what was
done. That is what nodary does for a fleet of GPU nodes: nothing joins without approval,
nothing changes without an attributable, justified, hash-chained record.

## What it does

- **Enrolls nodes** with short-lived join tokens, issues them mTLS certificates, and holds them in `pending` until an administrator approves. A leaked token alone cannot place a machine into the serving fleet.
- **Runs model servers** as systemd units against containerd. vLLM, SGLang, llama.cpp and TensorRT-LLM are supported through declarative backend descriptors; adding another is a TOML file, not a code change.
- **Stages weights** with resumable, verified transfers, including a fully offline path for air-gapped sites.
- **Issues and revokes tokens**, meters every request against the person who made it, and enforces per-user rate and budget limits.
- **Records every administrative action** in a hash-chained, tamper-evident audit log, with a required justification and a hash binding the approved preview to what was actually applied.
- **Enforces policy profiles** — origin allow/deny lists, mandatory re-authentication, deny-by-default egress, retention windows — as one reviewable object rather than behaviour scattered through code.

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

### Decisions

| | Record |
| :--- | :--- |
| 0001 | [No orchestrator](docs/adr/0001-no-orchestrator.md) — systemd and containerd instead of Kubernetes |
| 0002 | [Go, redistributed through package-manager wrappers](docs/adr/0002-go-with-package-manager-wrappers.md) |
| 0003 | [LiteLLM as the data plane](docs/adr/0003-litellm-as-data-plane.md) |
| 0004 | [Release artifacts and install channels](docs/adr/0004-release-artifacts-and-channels.md) — one binary, four channels |

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

Specification complete. Implementation is at **R0** — the release pipeline, ahead of the
milestones in [00-overview](docs/specs/00-overview.md#8-milestones).

R0 ships a real binary through every channel, implementing `nodary version` and
`nodary components list|verify`; every other verb reports that it is not yet implemented. It
exists to prove the distribution path end to end — cross-compilation, signing, verification,
wheel tags and npm platform guards — while the stakes are zero.

```sh
make check           # gofmt, vet, tests
make packages        # cross-compile, then build wheels and npm packages
make test-install    # install.sh end to end, including tamper rejection
make test-packages   # the built wheels and npm packages install and run
```

## License

Apache 2.0.
