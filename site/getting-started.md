# Getting started

One GPU box, from bare metal to a model answering `/v1/chat/completions` — metered, on a
network with no route off the machine, with every step recorded. Two commands and a short
conversation.

!!! note "You'll need"
    A Linux host with an NVIDIA GPU and driver installed — or Windows with an NVIDIA GPU,
    which joins [inside
    WSL2](https://github.com/nodarynet/nodary/blob/main/docs/specs/01-install.md#windows-hosts-run-as-wsl2-nodes)
    as an ordinary Linux node. Run the install through `sudo` rather than as root directly:
    it drops back to your own account to download weights, and it needs to know which
    account that is.

## 1. Place the binary

```sh
curl -fsSL https://nodary.net/install.sh | sh
```

`install.sh` is deliberately small. It detects your OS and architecture, downloads the
signed binary, **verifies the signature and then the SHA-256** — neither is optional and
there is no skip flag — places it under `/opt/nodary/`, and stops. Nothing is configured
and no service is started yet.

## 2. Run the install

```sh
sudo nodary install
```

This asks a handful of plain questions and runs the verbs itself. Every default is the
answer you want for a first single-machine install, so you can mostly press enter.

```console
nodary — accountable GPU inference

Is this machine the control plane, a GPU node joining one, or both?
  1) Both — single box (recommended to start)
  2) Control plane only
  3) GPU node, joining a control plane elsewhere
> 1
Address other machines will reach this one at [127.0.0.1]:
```

The address is what *other* machines will use to reach this one, so for a box you're
sitting at, the default is right. It goes into the control plane's TLS certificate, which
is why it's asked before anything is generated rather than patched afterwards.

The control plane, its certificate, containerd, the isolated network and the agent all
install here, and this machine enrolls itself as a node. Then:

```console
Approve fractal now? [Y/n]
Stage and register a model now? [y/N] y
Model (HuggingFace org/name): Qwen/Qwen2.5-0.5B-Instruct
Weights for Qwen/Qwen2.5-0.5B-Instruct
  1) Download and stage them now (recommended)
  2) Already staged under the models directory on this node
  3) I already have a manifest (from stage-model.sh, run elsewhere)
> 1
HuggingFace token (only for a gated repository — Gemma, Llama, Mistral — leave blank otherwise):
GPU index [0]:
Port [8001]:
Create a user who can call it? [Y/n]
  Name [you]:
  Role [operator]:
Mint you a service key now? [Y/n]
```

Note that **"stage and register a model" defaults to no.** It is the one step that reaches
the network and downloads gigabytes, so it is the one answer you have to give deliberately.

The download runs as *your* account, never as root — the install grants you write access to
the models directory first, then drops privileges to fetch. A gated repository (every
Gemma, Llama and Mistral release) needs a HuggingFace token at that prompt; the token goes
into the environment of the download, not onto a command line where `ps` would show it.

The run ends by printing, in order:

- **A one-time setup link**, valid for fifteen minutes, that creates the first
  administrator. **Open it now** — see step 3.
- **The CA fingerprint** and **a join token**, for adding a second GPU host later.
- **A service key**, `nodary_sk_…`, shown exactly once. It is stored only as a hash, so
  nobody — including nodary — can read it back. Copy it.

## 3. Set the administrator password

Open the setup link in a browser and choose a password. Nobody, including the install that
just ran, ever knows it: there is no default password to forget to change, and none was
typed into your terminal or written to a log.

## 4. Call it

`nodary node show <name>` follows the deployment from `starting` to `ready`. Once it's
ready, the gateway is already up and metering:

```sh
curl http://127.0.0.1:8086/v1/chat/completions \
    -H "Authorization: Bearer nodary_sk_…" \
    -H "Content-Type: application/json" \
    -d '{"model": "qwen2.5-0.5b-instruct", "messages": [{"role": "user", "content": "hello"}]}'
```

Then:

```sh
sudo nodary usage show
```

shows that request as counts — a user, a model, prompt and completion tokens — and nothing
of what was said. There is no field in the metering schema that could hold prompt or
completion text, and a test fails the build if a path from a request body to storage ever
appears.

## Two machines instead of one

The same command, answered differently. On the control-plane host choose **2) Control plane
only**; it prints a join token and a CA fingerprint. On each GPU host, run the same two
commands and choose **3) GPU node**, and it asks for those three values:

```console
Control plane URL (https://host:8443): https://10.0.0.5:8443
Join token (from `nodary token join` on the control plane): …
CA fingerprint (sha256:…, printed by `server install`): sha256:…
```

The node enrolls and waits, `pending`, until an administrator approves it — a leaked join
token alone cannot put a machine into the serving fleet. The wizard offers to approve it
for you if you're running on the control plane; from a GPU host you'll approve it with
`nodary node approve` on the control plane, which is [the next
guide](administering.md#approving-a-node).

## When you outgrow the wizard

`nodary install` is the on-ramp, not the only ramp. A fleet grows past what one interactive
session can drive — a third node, a scripted deployment, a CI pipeline, a flag the wizard
never asks about — and those need arguments rather than a conversation.

Everything above is the same verbs you'd otherwise run yourself, in the same order.
**[Administering a fleet →](administering.md)** covers them one at a time, plus the things
the wizard deliberately leaves alone: staging weights by hand or from an air-gapped
machine, changing what's deployed, routes and access grants, and reading the audit chain.

## Verifying a release

The release public key fingerprint is published here so it can be checked against a source
other than the one serving the download:

```text
minisign  RWRYtHqer6FbV8fMD5CEK+XBDBiX++arPJsueLpwXAowfcYBj6bwEWJD
openssl   SHA256:ec401b74444511fa2ee060cfbb39e1411e77884dfab2223576509e1396457900
```

To check the script itself before running it, rather than piping it to a shell:

```sh
curl -fsSLO https://nodary.net/install.sh
curl -fsSLO https://nodary.net/install.sh.minisig
minisign -Vm install.sh -P "$(cat nodary-release.pub)"
sh install.sh
```

## Next

- [`nodary doctor`](https://github.com/nodarynet/nodary/blob/main/docs/specs/10-cli.md#3-nodary-doctor)
  diagnoses a host in one pass — driver, GPU enumeration, certificate expiry, and a live
  re-run of the egress assertion.
- [Administering a fleet](administering.md) — the verbs, one at a time.
- The [CLI reference](https://github.com/nodarynet/nodary/blob/main/docs/specs/10-cli.md)
  covers every verb.
- The [specifications](https://github.com/nodarynet/nodary/tree/main/docs/specs) are what
  every component is required to do; the [decision records](https://github.com/nodarynet/nodary/tree/main/docs/adr)
  say why.
