# Getting started

This walks one GPU box from bare metal to a model answering `/v1/chat/completions`,
metered, on an isolated network, with every step recorded. It's the single-machine
path — control plane and GPU node together — which is the fastest way to see the whole
shape of the product. [Below](#running-the-control-plane-and-the-gpu-node-separately)
covers splitting them onto two machines.

!!! note "You'll need"
    A Linux host (or Windows with an NVIDIA GPU, which joins [inside
    WSL2](https://github.com/nodarynet/nodary/blob/main/docs/specs/01-install.md#windows-hosts-run-as-wsl2-nodes)
    as an ordinary Linux node) with an NVIDIA GPU and driver installed, and root — every
    command below runs as root or via `sudo`.

## 1. Install, and bring up the control plane and this node together

```sh
curl -fsSL https://nodary.net/install.sh | sh -s -- server --with-node --host <this-host's-address>
```

`install.sh` downloads the signed binary, verifies it against the [published
fingerprint](#verifying-a-release), and installs it. `--with-node` then installs
the control plane *and* enrolls this same machine as a GPU node in one step — the control
plane, its TLS certificate, containerd, the isolated network, and the agent, all in one
run. `--host` is whatever address other machines (or you, later) will reach this one at;
for a single box you're sitting at, `--host 127.0.0.1` is fine.

The run ends by printing three things — keep the terminal output:

- **A one-time setup link**, valid for fifteen minutes, that creates the first
  administrator. Open it in a browser and set a password. Nobody, including this
  install, ever knows it — there is no default password to forget to change.
- **The CA fingerprint**, `sha256:…`, for enrolling additional nodes later.
- **A join token**, for the same.

## 2. Approve the node

A node that enrolls is held `pending` until an administrator says yes — a leaked join
token alone can't place a machine into the serving fleet. Confirm it's there, then approve
it:

```sh
sudo nodary node list
sudo nodary node approve <node-name>
```

`node list` names what an operator has to act on, not just what exists — a pending node,
one that's gone quiet, one offering no GPU. `node show <name>` gives the detail on one:
hardware, what it's offering, what's placed on it.

## 3. Get a model's weights onto the node

nodary doesn't download weights for you yet — the air-gapped path is first-class, not a
fallback, so placing weights is always a deliberate, verifiable act. `scripts/stage-model.sh`
does the download:

```sh
sudo ./scripts/stage-model.sh Qwen/Qwen2.5-0.5B-Instruct
```

A repository that requires accepting a license on huggingface.co first (every Gemma, Llama
and Mistral release) needs a token: `sudo HF_TOKEN=hf_… ./scripts/stage-model.sh …`.

## 4. Register it

This is the step that turns files on disk into a model a client can call — it digests the
weights, writes the manifest they're checked against, pins the exact container image this
build was tested with, and grants a user access to the route it creates (routes are
deny-by-default: nobody may call one until granted):

```sh
sudo nodary user add alice --role operator --justify "first user"
sudo nodary model register Qwen/Qwen2.5-0.5B-Instruct \
    --node <node-name> --gpu 0 --port 8001 \
    --grant alice --justify "first model"
```

`nodary node show <node-name>` follows the deployment from `starting` to `ready`.

## 5. Create a key, and call it

```sh
sudo nodary token create --user alice --kind sk --justify "alice's client"
```

That prints the key once — `nodary_sk_…` — and states plainly which routes it may call.
Use it against the gateway, which is already up and metering:

```sh
curl http://127.0.0.1:8080/v1/chat/completions \
    -H "Authorization: Bearer nodary_sk_…" \
    -H "Content-Type: application/json" \
    -d '{"model": "qwen2.5-0.5b-instruct", "messages": [{"role": "user", "content": "hello"}]}'
```

```sh
sudo nodary usage show
```

shows the request as counts — a user, a model, prompt and completion tokens — and nothing
of what was said. No prompt or completion text ever reaches nodary's own storage.

## Running the control plane and the GPU node separately

Drop `--with-node` from step 1 to install only the control plane. On each GPU box:

```sh
curl -fsSL https://nodary.net/install.sh | sh -s -- node \
    --server https://<control-plane-host>:8443 \
    --token <join-token> \
    --ca-fingerprint <sha256:…>
```

using the token and fingerprint the control plane install printed. `nodary token join`
mints additional join tokens; each one expires in an hour and can enroll one node.
Everything from step 2 onward is the same.

## Verifying a release

```text
minisign  RWRYtHqer6FbV8fMD5CEK+XBDBiX++arPJsueLpwXAowfcYBj6bwEWJD
openssl   SHA256:ec401b74444511fa2ee060cfbb39e1411e77884dfab2223576509e1396457900
```

`install.sh` verifies the signature and digest before it will place anything, and has no
override flag.

## Next

- [`nodary doctor`](https://github.com/nodarynet/nodary/blob/main/docs/specs/10-cli.md#3-nodary-doctor)
  diagnoses a host in one pass — driver, GPU enumeration, certificate expiry, and a live
  re-run of the egress assertion.
- The [CLI reference](https://github.com/nodarynet/nodary/blob/main/docs/specs/10-cli.md)
  covers every verb.
- The [specifications](https://github.com/nodarynet/nodary/tree/main/docs/specs) are what
  every component is required to do; the [decision records](https://github.com/nodarynet/nodary/tree/main/docs/adr)
  say why.
