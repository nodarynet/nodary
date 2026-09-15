<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/assets/nodary-dark.svg">
  <img src="docs/assets/nodary.svg" alt="nodary" width="320">
</picture>

![CI](https://github.com/nodarynet/nodary/actions/workflows/ci.yml/badge.svg)
![PyPI](https://img.shields.io/pypi/v/nodary)
![npm](https://img.shields.io/npm/v/nodary)
![Go](https://img.shields.io/badge/Go_1.25%2B-00ADD8?logo=go&logoColor=white)
![License](https://img.shields.io/badge/Apache-2.0-blue.svg)

## Serve LLMs on your own compute — with receipts

nodary serves LLMs across the GPUs you own and keeps an append-only,
hash-chained record of what changed and who did it — a *notary* for a small fleet
of GPU boxes. Nothing joins without approval; nothing changes without a record
you can show.

No Kubernetes, no Ansible, no Helm, no Terraform — just a handful of machines
you administer directly.

It is built for **a small site that handles CUI and has to answer for it** — a
supplier with a handful of GPU boxes, subject to CMMC Level 2 and NIST SP 800-171,
whose obligation is to write a System Security Plan and keep it true. **That
obligation is yours and cannot be bought from a vendor.** nodary does not assess,
does not certify, does not make anyone compliant, and makes no zero-trust claim. It
enforces particular mechanisms and records what happened, so the person writing your
SSP is describing something they can **show** rather than something they believe —
verifiable without trusting us, with `sha256sum` and `minisign`
([13](dev/specs/13-evidence.md)).

Running a homelab instead? Same binary, same install, nothing gated. You are the
community edition rather than the target audience.

## Quick start

The default is a short conversation. Place the binary, then let `nodary install` ask a
handful of questions and run the same verbs on your behalf — install, enroll, approve,
stage, register, grant and a key. Every default is the answer you want for a first
single-machine install, so you can mostly press enter:

```sh
curl -fsSL https://nodary.net/install.sh | sh     # place the binary and stop
sudo nodary install                               # then walk it as a conversation
```

**[Getting started →](https://nodarynet.github.io/nodary/getting-started/)** is that route,
step by step.

**Prefer flags to a conversation?** The same install runs non-interactively in one line —
for a script or a CI pipeline:

```sh
curl -fsSL https://nodary.net/install.sh | sh -s -- server --with-node --host <this-host>
```

installs the control plane and enrolls this GPU as its first node in one step.
**[Administering a fleet →](https://nodarynet.github.io/nodary/administering/)** is the
verbs one at a time — a third node, a script, or a flag the wizard never asks about.

## How it works

```
                          ┌──────────────────────── control plane host ──┐
   IDE / CLI ──HTTPS──►   │  nodary-gateway  auth, quota, metering       │
                          │        │                                     │
                          │        ▼                                     │
                          │  LiteLLM         OpenAI-compat, routing      │
                          │        │                                     │
                          │  nodary-server   state, API, UI, enrollment  │
                          │  prometheus + grafana                        │
                          │  /var/lib/nodary/nodary.db                   │
                          └────────┬─────────────────────────────────────┘
                                   │ mTLS, agent-initiated (outbound only)
              ┌────────────────────┼────────────────────┐
              ▼                    ▼                    ▼
       ┌─── node ─────┐     ┌─── node ─────┐     ┌─── node ─────┐
       │ nodary-agent │     │ nodary-agent │     │ nodary-agent │
       │ containerd   │     │ containerd   │     │ containerd   │
       │ model units  │     │ model units  │     │ model units  │
       │ dcgm-exporter│     │ dcgm-exporter│     │ dcgm-exporter│
       └──────────────┘     └──────────────┘     └──────────────┘
```

A control plane owns all state in a single SQLite file. Node agents hold an
outbound long-poll to it, receive a desired-state document, and reconcile toward
it — staging weights, writing systemd units, starting containers, reporting
status. The control plane never dials a node, so nodes need no inbound firewall
rules and no listening SSH. Operators reach the system over SSH and run `nodary`
verbs on the host, or through the HTTP API; both call the same core functions, and
every mutating call passes through the audit layer.

## Features

- **Enrolls nodes behind a human gate.** Short-lived join tokens, mTLS
  certificates, and a `pending` hold until an administrator approves — a leaked
  token alone cannot place a machine into the serving fleet.
- **Runs model servers as systemd units** against containerd, through declarative
  backend descriptors — vLLM, SGLang and llama.cpp today; adding
  another is a TOML file, not a code change. llama.cpp serves GGUF and runs where VRAM is short.
  Which of them a node is offered follows the GPU it has: see
  [which backend runs on which GPU](#which-backend-runs-on-which-gpu).
- **Stages weights with verified transfers** — resumable, including a fully offline
  path for air-gapped sites.
- **Issues, revokes and meters.** Every request is metered against the person who
  made it, with per-user, per-role and global rate and budget limits (`rpm`,
  `tpm`, `daily_tokens`, `max_concurrent`) and a `429` that names which limit was
  hit and when it clears.
- **Attributes every administrative action to a person.** An administrator runs
  `nodary login` once per appliance and then `--server` on the verbs, so the chain
  names the account that acted rather than whoever had root on the control plane.
- **Records every administrative action** in a hash-chained, tamper-evident log,
  with a required justification and a hash binding the approved preview to what was
  actually applied. A daily `nodary prune` applies retention as an audited act that
  names the range it removed, and the surviving chain verifies against the cut.
- **Ships the chain off the box it protects.** A compromised control plane can
  rewrite its own database consistently; it cannot rewrite a copy that has already
  left. Records deliver to a JSONL file and any NDJSON endpoint — Splunk, Elastic,
  or a shipper in front of one — asynchronously, so a wedged SIEM never delays a
  mutation, and `nodary audit verify --mirror` validates the copy on a machine that
  never saw the database.
- **Carries policy as one reviewable object.** Mandatory re-authentication,
  justification floors, credential lifetimes, retention windows, origin allow/deny
  and deny-by-default egress are in force in a single profile; `nodary policy show`
  marks every setting nothing acts on yet and names the task that will enforce it.
- **Keeps prompts and completions out of its own records.** The metering schema is
  closed: no free-text body field exists to write into, a test fails if content
  reaches the database or a log, and LiteLLM's request logging is pinned off with
  the pinning asserted ([ADR 0006](dev/adr/0006-cui-boundary-and-fips.md)).

## Install

The one-liner above is the primary path. The same binary is a complete install in
every channel rather than a convenience — `pip install nodary && nodary server
install` reaches the same state ([ADR 0004](dev/adr/0004-release-artifacts-and-channels.md)).

| Channel | Command |
| :--- | :--- |
| curl | `curl -fsSL https://nodary.net/install.sh \| sh` |
| pip | `pip install nodary` |
| npm | `npm i -g nodary` |
| Homebrew | macOS, via the [`nodarynet/homebrew-tap`](https://github.com/nodarynet/homebrew-tap) tap |

Nodes run Linux. A Windows machine with an NVIDIA GPU joins **inside WSL2** as an
ordinary Linux node ([01](dev/specs/01-install.md#windows-hosts-run-as-wsl2-nodes)).
macOS builds are the operator CLI only.

### Which backend runs on which GPU

Read this before you buy the card, not after. A node's GPU vendor is detected at
enrollment, and `nodary model register` offers what that silicon can actually run
rather than a list you have to check yourself.

| Your GPU | Backends offered | Recommended |
| :--- | :--- | :--- |
| **NVIDIA** | SGLang, vLLM, llama.cpp | SGLang |
| **AMD** — Radeon, Instinct, APU | llama.cpp on Vulkan | llama.cpp |
| **Intel** — Arc, integrated | llama.cpp on Vulkan | llama.cpp |
| Anything else exposing a DRM render node | llama.cpp on Vulkan | llama.cpp |

**AMD and Intel are served through Vulkan, not ROCm or XPU, and that is a
decision rather than a gap.** Both vendors do publish images for the other two
backends, and nodary pins neither: there is no single "vLLM on AMD" image but a
matrix of `rdna`, `cdna` and per-`gfx` builds, no "SGLang on AMD" image but
Instinct-only `mi30x`/`mi35x` tags with no consumer Radeon build at all, and both
come from publishers other than the projects that write the software — 10–33 GB
each, against 0.1 GB for the Vulkan llama.cpp image that reaches the same cards.
The reasoning is in [R6b](dev/plans/R6b-the-silicon-matrix.md).

If you own the hardware that makes that trade the other way — an Instinct box
where ROCm's throughput is the whole point — the route is a backend descriptor of
your own, which is a TOML file naming an image you trust
([04 §9](dev/specs/04-backends.md#9-registering-a-backend)). nodary will offer it
on the silicon it declares. What nodary will not do is pin those images on your
behalf and stand behind them.

A backend placed on silicon it does not declare is **refused by name**, at the
moment you register it, rather than discovered as a container that starts on the
node and exits looking for CUDA.

## Editions

One binary. Everything that *runs* the fleet is Apache 2.0; the commercial edition
sells what turns records into a deliverable a human assessor reads. An unlicensed
install still carries every commercial verb and explains what it would produce,
rather than hiding it ([ADR 0005](dev/adr/0005-editions-and-the-advisory-feed.md)).

| | Apache 2.0 | Commercial |
| :--- | :---: | :---: |
| Control plane, agent, gateway, backends | ✔ | |
| The hash chain, `audit verify`, `audit export` | ✔ | |
| Enrollment, staging, egress isolation | ✔ | |
| Both policy profiles | ✔ | |
| `nodary evidence export` — the signed bundle | | ✔ |
| The control index and SSP narratives | | ✔ |
| The signed advisory feed, and `nodary advisory check` against it | mechanism | content |

In one sentence: **we do not sell security, we sell the paperwork.** The feed is a
report of what public sources say about the digests nodary pins, at the time it was
generated — not a warranty, and not a substitute for vulnerability management. That
statement ships inside every revision, not only here.

## Verifying a release

Every release artifact is signed. The release public key fingerprint is published
here so it can be checked against a source other than the one serving the download:

```
minisign  RWRYtHqer6FbV8fMD5CEK+XBDBiX++arPJsueLpwXAowfcYBj6bwEWJD
openssl   SHA256:ec401b74444511fa2ee060cfbb39e1411e77884dfab2223576509e1396457900
```

`install.sh` verifies the signature and digest before it will place anything, and
has no override flag ([01](dev/specs/01-install.md#2-the-installsh-contract)).

## Status

The MVP route is complete and verified as root on real hardware — a control plane
and a GPU node install end to end, a node enrolls and is approved, weights are
staged and verified, and a model serves through the gateway, metered, with no
prompt text anywhere in the database.

**[Where the implementation stands →](dev/status.md)** is the whole picture: what
is built, what is not built at all, what is built and not yet proved on hardware,
and the per-milestone counts. The route itself is [dev/plans/mvp.md](dev/plans/mvp.md).

## Checks

```sh
make check           # gofmt, vet, tests
make packages        # cross-compile, then build wheels and npm packages
make test-install    # install.sh end to end, including tamper rejection
make test-packages   # the built wheels and npm packages install and run
```

## Documentation

| | |
| :--- | :--- |
| **[Documentation site](https://nodarynet.github.io/nodary/)** | Getting started — install to a served, metered model |
| [dev/specs/](dev/specs/) | The specifications — what every component is required to do, numbered 00–13 |
| [dev/adr/](dev/adr/) | Decision records — why it's built this way, and what was rejected |
| [dev/tasks/](dev/tasks/) | The implementation tracker — what's done, what's next; the specs are authoritative and the tracker follows them |

## License

Apache 2.0.
