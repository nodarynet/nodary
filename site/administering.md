# Administering a fleet

[`nodary install`](getting-started.md) is the on-ramp, not the only ramp. It asks a fixed
set of questions and runs the same verbs below in the same order — which is exactly what you
want the first time, and not what you want for the third node, a scripted rebuild, a CI
pipeline, or any flag the conversation never offers.

This page is those verbs, one at a time.

!!! note "Every command here runs on the control-plane host"
    `--server URL` is specified and **not yet implemented**, so every `nodary` verb operates
    on the local SQLite database. Administering a fleet today means a shell on the control
    plane. A CLI invocation with no credentials file resolves to a local-root principal with
    full authority, and the audit record reads `actor: root, method: local` — so on a team
    where several people administer, privileged acts attribute to the machine rather than to
    a person until that lands.

## Installing without the wizard

The control plane, and this same machine as its first GPU node:

```sh
curl -fsSL https://nodary.net/install.sh | sh -s -- server --with-node --host <this-host's-address>
```

Drop `--with-node` to install only the control plane. `--host` is the address other machines
will reach this one at; it goes into the TLS certificate. The run prints a one-time setup
link (fifteen minutes, creates the first administrator, and no password is ever typed into
a terminal), the CA fingerprint, and a join token.

On each GPU box:

```sh
curl -fsSL https://nodary.net/install.sh | sh -s -- node \
    --server https://<control-plane-host>:8443 \
    --token <join-token> \
    --ca-fingerprint <sha256:…>
```

`nodary token join` mints more join tokens. Each expires in an hour and enrolls one node by
default; `--uses` and `--expires` change that, within the active profile's
`token_max_ttl_days` ceiling.

## Approving a node

A node that enrolls is held `pending` until an administrator says yes — a leaked join token
alone cannot place a machine into the serving fleet.

```sh
sudo nodary node list
sudo nodary node approve <node-name> --justify "second GPU host for the research team"
```

`node list` names what an operator has to act on rather than only what exists: a pending
node, one that has gone quiet, one offering no GPU. `node show <name>` gives the detail on
one — hardware, what it is offering, what is placed on it, and anything it has **refused**.

The rest of the node lifecycle:

```sh
sudo nodary node drain <name>      # stop scheduling onto it, leave what is running
sudo nodary node revoke <name>     # refuse its certificate, remove it from routes
sudo nodary node leave              # run on the node itself: stop and remove local state
sudo nodary node verify-egress <name>
```

`verify-egress` runs a probe inside a live deployment's network namespace and asserts that a
route off-box, a DNS lookup and a connection to a known-external address all fail. It also
runs a control probe on the host, and reports `inconclusive` rather than `compliant` when
the host itself reaches nothing — which is the honest answer on a genuinely air-gapped site,
and worth knowing before you rely on it as your isolation evidence.

## Placing weights

nodary does not download weights for you by default. The air-gapped path is first-class
rather than a fallback, so placing weights is a deliberate, verifiable act, and no part of
it touches the network as root.

The models directory (`/var/lib/nodary/models`) is owned by the `nodary` service account,
which is what needs to read it later. The privileged part is granting *yourself* write
access to it, once. Two steps, not one — owning a directory's group is not the same as being
in that group, and the second is what your shell actually checks:

```sh
sudo usermod -aG nodary "$USER"
sudo install -d -o "$USER" -g nodary -m 2750 /var/lib/nodary/models
newgrp nodary
```

`newgrp` starts a shell with that membership active immediately. Without it `usermod` does
not take effect until you log out and back in, and the next command refuses you with nothing
having visibly changed.

That is a permission grant, not a download — nothing has reached the network. From here
everything runs as yourself:

```sh
curl -fsSL https://raw.githubusercontent.com/nodarynet/nodary/main/scripts/stage-model.sh \
    | bash -s -- Qwen/Qwen2.5-0.5B-Instruct
```

A repository that requires accepting a license on huggingface.co first — every Gemma, Llama
and Mistral release — needs a token, set for the script and not for `curl`:

```sh
curl -fsSL https://raw.githubusercontent.com/nodarynet/nodary/main/scripts/stage-model.sh \
    | HF_TOKEN=hf_… bash -s -- google/gemma-3-1b-it
```

It downloads the files, writes `nodary-manifest.sha256` beside them, and prints the exact
`nodary model register` command to run next.

??? note "Placing weights some other way"
    Any tool works — `huggingface-cli download`, `git lfs clone`, or copying files in over
    `scp`. The only requirement is the layout `nodary model register` expects: every file
    **flat**, with no `blobs/`, `refs/` or `snapshots/`, directly under
    `/var/lib/nodary/models/hub/models--<org>--<name>/`. `config.json` has to sit at that top
    level, because the agent points a backend's `--model` at the directory itself.

## Letting the node fetch its own copy

Everything above places weights on *this* box, which only matters when this box is also the
node. From any other machine — an admin laptop with no `nodary` on it at all — the same
script pointed at a scratch directory gets you a manifest:

```sh
curl -fsSL https://raw.githubusercontent.com/nodarynet/nodary/main/scripts/stage-model.sh \
    | bash -s -- Qwen/Qwen2.5-0.5B-Instruct --models-dir /tmp/qwen
```

The download still has to happen somewhere to hash it, but not permanently. Keep only
`/tmp/qwen/hub/models--Qwen--Qwen2.5-0.5B-Instruct/nodary-manifest.sha256` and `rm -rf
/tmp/qwen` once it is copied out — a few kilobytes travel to the control plane, not the
weights:

```sh
sudo nodary model register Qwen/Qwen2.5-0.5B-Instruct \
    --source remote --manifest /tmp/qwen/hub/models--Qwen--Qwen2.5-0.5B-Instruct/nodary-manifest.sha256 \
    --node fractal --gpu 0 --port 8001 --grant alice --justify "first model"
```

The agent on that node downloads its own copy directly from HuggingFace, verified against
the same manifest, across as many reconcile cycles as it takes and resumable if the agent
restarts partway through. `nodary node show fractal` shows it moving `staging → staged` with
the byte count climbing against the total.

If a transfer lands corrupt — bad media, a flaky link — that state is **terminal on
purpose**: nothing silently retries, because a staging loop that heals itself hides the
thing you needed to know. `nodary model restage <repo> --node <name>` is the explicit
unstick, and `nodary model unstage` is the inverse of this whole section: once nothing
deploys a model on a node, it removes the weights and reclaims the disk.

## Registering a model

The step that turns files on disk into a model a client can call. It digests the weights,
writes the manifest they are checked against, pins the exact container image this build was
tested with, and grants a user access to the route it creates — routes are deny-by-default,
so nobody may call one until granted:

```sh
sudo nodary user add alice --role operator --justify "first user"
sudo nodary model register Qwen/Qwen2.5-0.5B-Instruct \
    --node <node-name> --gpu 0 --port 8001 \
    --grant alice --justify "first model"
```

`nodary node show <node-name>` follows the deployment from `starting` to `ready`.

## Changing what is deployed

```sh
sudo nodary model disable <repo> [--node <name>]   # stop it, leave the weights in place
sudo nodary model enable  <repo> [--node <name>]   # bring it back, no re-download
sudo nodary model restart <repo> --node <name>     # cycle a healthy deployment
```

`disable` and `enable` are declarative — they set a field in the configuration snapshot, so
they appear in `config diff` and in a revision like any other change. `restart` is a
one-shot request rather than a state: it is consumed by the node's next heartbeat and
acknowledged, because the desired-state protocol has no imperative commands in it.

## Keys, routes and access

```sh
sudo nodary token create --user alice --kind sk --justify "alice's client"
```

That prints the key once — `nodary_sk_…` — states plainly which routes it may call, and
stores only a hash. `--expires` accepts `90d`, `12h` or `never`, and is refused above the
active profile's `token_max_ttl_days`; `never` is refused under every profile.

```sh
sudo nodary route list
sudo nodary route show <route>
sudo nodary route set <route> --add <deployment-id>,<deployment-id> --remove <deployment-id>
sudo nodary limits set --kind user --subject alice --rpm 60 --daily-tokens 1000000
```

!!! warning "Limits are recorded, not enforced"
    `limits set` writes them, `config export` carries them and `policy diff` reasons about
    whether a change loosens them — and the gateway does not read them. `--kind` also takes
    `role` and `global`. There is no token
    bucket, no concurrency cap and no `429` path yet
    ([R3-08/09/10](https://github.com/nodarynet/nodary/blob/main/docs/tasks/R3-gateway.md)).

## Policy

```sh
sudo nodary policy show
sudo nodary policy diff regulated
sudo nodary policy apply regulated --justify "moving the pilot to regulated"
```

`policy show` marks every setting nothing acts on yet and names the task that will enforce
it, so the profile can be read as a list of controls rather than a list of numbers. Eight of
its sixteen settings are marked today. Two more are **invariants** — `require_signed_artifacts`
and `egress_default` are refused at parse if set to anything else, and the mechanisms behind
them run unconditionally.

`policy diff` reports which settings a candidate profile would **loosen** before you apply
it. Loosening is permitted; doing it silently is not.

## The record

```sh
sudo nodary audit list --action model. --from 2026-09-01
sudo nodary audit list --actor alice --limit 100
sudo nodary audit verify
sudo nodary audit export --from 2026-09-01 --to 2026-09-30
```

`--action` matches exactly, or a whole family when it ends in a dot — `model.` selects
`model.register`, `model.disable` and the rest. `audit export` takes `--from-seq` as well, to
resume a destination that fell behind rather than re-sending everything.

`audit verify` re-hashes the stored chain and names the sequence number where it breaks,
exiting non-zero. It refuses a record whose stored JSON is merely *decodable* rather than
canonical, which closes the obvious forgery: a trailing second document that decodes to the
same map and would re-hash clean.

!!! note "The chain has no anchor outside this machine"
    A compromised control plane can rewrite the whole chain consistently, and the signed
    evidence bundle does not close that — its signing key is sealed on the same host. Until
    the network sink lands
    ([R2-41](https://github.com/nodarynet/nodary/blob/main/docs/tasks/R2-control-plane.md)),
    point a log shipper at `/var/log/nodary/audit.jsonl` into WORM storage. Records carry
    `seq` and `hash`, so a receiver dedupes and detects gaps without trusting the sender, and
    `nodary audit verify --mirror` validates the copy on a machine that has never seen the
    database.

## Checking a host

```sh
sudo nodary doctor
```

Driver, GPU enumeration, containerd, the isolated network, certificate expiry, and a live
re-run of the egress assertion — in one pass.

!!! warning "Agent certificates expire at 90 days and nothing renews them"
    Every node enrolled in one window expires in one window, and the control plane loses the
    fleet at once. Running deployments keep serving, so the failure is quiet: what is lost is
    visibility and control. Recovery is re-enrollment with a fresh join token. `nodary
    doctor` reports the expiry, so diarize it until
    [R4-05](https://github.com/nodarynet/nodary/blob/main/docs/tasks/R4-agent.md) lands.

## Next

- The [CLI reference](https://github.com/nodarynet/nodary/blob/main/docs/specs/10-cli.md)
  covers every verb and every flag.
- The [specifications](https://github.com/nodarynet/nodary/tree/main/docs/specs) are what
  every component is required to do; the
  [decision records](https://github.com/nodarynet/nodary/tree/main/docs/adr) say why.
- The [implementation tracker](https://github.com/nodarynet/nodary/tree/main/docs/tasks)
  is what is done and what is next.
