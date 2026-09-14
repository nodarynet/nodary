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
sudo nodary node verify-egress <deployment-id>   # on the node itself
```

`verify-egress` runs a probe inside a live deployment's network namespace and asserts that a
route off-box, a DNS lookup and a connection to a known-external address all fail. It also
runs a control probe on the host, and reports `inconclusive` rather than `compliant` when
the host itself reaches nothing — which is the honest answer on a genuinely air-gapped site,
and worth knowing before you rely on it as your isolation evidence.

It runs **on the node**, because the namespace it enters only exists there. You do not have to
go to the node to read the answer: the agent asserts isolation after every deployment start and
reports the verdict, so the control plane always holds the last one.

```sh
nodary node show <name>                  # an EGRESS column, per deployment
curl .../v1/nodes/<name>/verify-egress   # the same verdicts, with their timestamps
```

That endpoint is a **read of what the node reported**, not a probe run from the control plane —
so it answers even for a node that has gone quiet, and tells you when it last checked in so you
can judge how much the answer is worth. A node counts as compliant only when every deployment
on it does; one deployment with a way off the box is the node's verdict, and a deployment that
has never run has been asked nothing and is not rounded up to compliant.

All three checks cover **IPv4 and IPv6**. That matters more than it sounds: the isolated
bridge refuses IPv6 outright, because a container on a dual-stack network can pick up a global
address and a default route from a router advertisement without anything asking it to. The
route check reads both of the kernel's tables, so that namespace is reported as what it is.

## What a node will and will not take

A GPU host is rarely *only* a nodary node. It drives a display, it hosts something else at 3pm
on a Tuesday, and one of its cards is not on offer. `/etc/nodary/node.toml` is where the
machine's owner says so, and it is read on the node rather than sent from the control plane.

```toml
[limits]
gpu_indices       = [1, 2, 3]   # of 4 present — GPU 0 drives the display
max_vram_fraction = 0.90
max_deployments   = 2

[allow]
backends = ["vllm"]
```

These are not a consent boundary — you own both ends. They are rails against your own
mistakes, and against a control plane that is misconfigured or being driven by somebody who
has forgotten what else that machine does.

`gpu_indices` narrows what the node *advertises*, so the control plane is never told the
fourth card exists. The rest are checked against the desired state on every reconcile, and
anything outside them is refused and reported — `nodary node show <name>` prints the reason
against the node. Nothing is retried: a limit being hit repeatedly is something you should
see, not something the fleet should grind against.

!!! warning "Editing this file never stops a running model on the spot"
    Narrow a limit under a deployment that is already serving and it keeps serving, reported
    as `out_of_policy` rather than refused. That is deliberate — a guardrail that could
    terminate a model mid-request is one nobody would dare edit, which makes it no guardrail
    at all. Closing the gap is yours to do: widen the limit again, or stop the deployment
    with `nodary model disable`.

### The maintenance window

`window.maintenance` is **when** the gap above gets closed for you, and it is the only thing
it does:

```toml
[window]
maintenance = "sat 02:00-06:00 UTC"
```

A deployment left `out_of_policy` by an edit to this file keeps serving until the window opens,
and is stopped then. A node that declares no window keeps it serving indefinitely, which is the
behavior you get with no `[window]` section at all.

It confines **nothing else**. `nodary node drain`, `nodary model disable` and `nodary model
restart` act immediately whatever the clock says: those are explicit decisions you are making
now, usually because something is already wrong, and a node you are draining because it is
failing should not keep serving until Saturday. The window schedules the disruption nobody
asked for, not the ones you did.

Two things to know when you write one:

- **The zone has to be one this host resolves.** `UTC` always does. `EST`, `CET` and `MST` do;
  `PST` and `AEST` do **not** and are refused when the file loads, rather than parsing cleanly
  and then matching no minute of any week.
- **A window may cross midnight.** `sat 22:00-02:00 UTC` is Saturday evening and the small
  hours of Sunday. One that opens and closes at the same minute is refused as the typo it is.

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

That whole sequence works from your own machine, with `--server` on the register step — which
is the shape this path is for. The manifest is a few kilobytes and the weights never touch
your laptop at all:

```sh
nodary model register Qwen/Qwen2.5-0.5B-Instruct \
    --source remote --manifest ./nodary-manifest.sha256 \
    --node fractal --gpu 0 --grant alice \
    --server https://nodary.example.internal:8443 \
    --justify "OPS-4142: qwen on fractal"
```

The agent on that node downloads its own copy directly from HuggingFace, verified against
the same manifest, across as many reconcile cycles as it takes and resumable if the agent
restarts partway through. `nodary node show fractal` shows it moving `staging → staged` with
the byte count climbing against the total.

### What the node needs to fetch it

Two settings, both on the node, both in the same place — a drop-in on the agent's unit,
since neither belongs in configuration the control plane replicates to every node:

```sh
sudo systemctl edit nodary-agent
```

```ini
[Service]
Environment=HF_TOKEN=hf_...
Environment=HTTPS_PROXY=http://proxy.corp.example:3128
```

```sh
sudo systemctl restart nodary-agent
```

The restart is not optional: both are read when the agent starts. `HF_TOKEN` is needed for
exactly the repositories that needed one when you built the manifest — every Gemma, Llama
and Mistral release — and is one token per node, not per model. `HTTPS_PROXY` is only for
sites that reach the internet through a proxy; leave the line out otherwise.

The download itself does **not** run inside the agent. It runs as its own transient unit,
`nodary-stage-<model>.service`, which lives only as long as the transfer and exits before
anything starts serving. That is where to look while one is running:

```sh
systemctl list-units 'nodary-stage-*'      # what is downloading right now
journalctl -u 'nodary-stage-*' -n 50       # why one stopped
```

Running it separately is mostly about what it is *not* doing: several gigabytes of somebody
else's bytes are no longer being pulled and hashed inside the long-lived root process that
holds this node's certificate and key.

That unit runs under an IP filter, which is worth knowing about before you diagnose a
download that will not start:

| | |
| :--- | :--- |
| **Allowed** | the public internet, this host's resolvers from `/etc/resolv.conf`, and your `HTTPS_PROXY` if you set one |
| **Denied** | private ranges, CGNAT, loopback, and link-local — which includes `169.254.169.254`, the cloud metadata endpoint |

The shape of that is deliberate, and it is the opposite of what you might expect. Weights
come from a CDN whose addresses rotate under short TTLs and which a fetch is *redirected* to
rather than addressed at, so an allowlist of destinations would break a large transfer
partway through and look exactly like a network outage. Narrowing the other side costs the
download nothing and removes what was worth removing: it cannot reach your control plane,
your other nodes, the rest of your network, or the metadata service that hands out cloud
role credentials to anything that asks.

If it is your *own* egress firewall blocking the transfer, nodary cannot tell you anything
more specific than a connection error. Opening a path for `huggingface.co` and the CDN host
it redirects to is the direct answer, and a proxy is usually the easier one.

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

### Provenance

`--origin-org` and `--origin-country` declare where the weights came from, and `--license`
records which license they carry. The license is **recorded and never interpreted**; the origin
is a control:

```sh
sudo nodary model register Qwen/Qwen2.5-0.5B-Instruct \
    --node <node-name> --gpu 0 --port 8001 \
    --origin-org Qwen --origin-country CN \
    --license apache-2.0 \
    --grant alice --justify "first model"
```

A profile's `model_origin_allowlist` and `model_origin_denylist` are checked against both
fields, case-insensitively, and a denied model is **refused at registration** with the attempt
written to the audit chain — the actor, the model, and the origin it claimed. The check sits
where `model register` and `config apply` meet, so a hand-written document is not a way around
the verb.

Two rules worth knowing before you write a profile:

- An **empty allowlist means any origin**. A non-empty one means a model that declares no
  origin is refused too, because otherwise the control is bypassed by leaving the flag off.
- The **denylist wins**. An origin on both lists is denied.

### Serving a GGUF with llama.cpp

`--backend llama-cpp` changes where the weights go and what to put there. vLLM and SGLang take
a HuggingFace cache; llama.cpp takes **one** GGUF file, so the model's directory is the
flattened id rather than `hub/models--…`:

```sh
sudo install -d -o "$USER" -g nodary -m 2750 /var/lib/nodary/models/Qwen--Qwen2.5-0.5B-Instruct
cp qwen2.5-0.5b-instruct-q4_k_m.gguf /var/lib/nodary/models/Qwen--Qwen2.5-0.5B-Instruct/

sudo nodary model register Qwen/Qwen2.5-0.5B-Instruct \
    --backend llama-cpp --node <node-name> --gpu 0 --port 8001 \
    --grant alice --justify "a GGUF from the shelf"
```

You do not say which layout — the backend declares it, and `model register` follows. Point it
at the wrong directory and it says where it looked.

**One file, and it must be one.** A GGUF split into shards is refused rather than guessed at:
llama.cpp takes the first shard, and a build that picked one for you would serve the wrong
weights in silence the day the naming differs. Merge the shards with `llama-gguf-split --merge`
and register the result.

Two options are worth knowing. `--gpu-memory` does not apply — llama.cpp does not reserve a
fraction of VRAM, it places a number of layers — so use `gpu_layers` through the deployment's
params, which the descriptor names. And llama.cpp will serve with **no GPU at all**, slowly,
which no other backend here does.

!!! note "The image is NVIDIA's build"
    The pinned image is `server-cuda` from the project's own publication at
    `ghcr.io/ggml-org/llama.cpp`. That repository also ships `server-vulkan`, `server-intel`
    and a CPU-only `server`, which are the route to hosts that are not NVIDIA — but preflight,
    GPU enumeration, CDI device naming and the `--gpus` flag all resolve through `nvidia-smi`
    and `nvidia-ctk`, so a non-NVIDIA node cannot install yet regardless of the image. That
    seam is not built.

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

`--kind` takes `user`, `role` or `global`. **Every applicable limit binds and the most
restrictive wins** — a user is subject to their own limit, their role's and the global one at
once, so a generous per-user limit does not raise anybody above a tight global ceiling. That
is what makes a global cap a cap; the cost is that per-user limits can only tighten.

Exceeding one returns `429` with `Retry-After` and a body naming which limit was hit, whose it
is, what is already spent and when it clears. A refused request is recorded in `usage` with
status 429 — throttling is telemetry about the system, not an administrative act, so it never
reaches the audit chain.

!!! note "Two edges worth knowing"
    `tpm` is charged **after** a response, because a request's token count does not exist
    until then — so one very large response can leave the bucket empty for a while. And a
    daily budget is checked against what is already spent, so it can be exceeded by at most
    one request. Both are inherent rather than shortcuts: there is no way to charge for
    tokens before they are produced.

## Metering and chargeback

```sh
sudo nodary usage show --group_by node --from 2026-09-01
sudo nodary usage show --group_by user --model acme/tiny-31b
sudo nodary usage show --user alice --format json
```

One row is written per inference request, carrying the person, the credential, the route, the
model, the deployment, the node, token counts, latency and status — and **no request or
response content**. There is no field for it: the schema is closed, and a test fails the build
if a path from a request body to storage appears.

A route can have several members and LiteLLM is what picks one, so the deployment a request
actually ran on is knowable only from LiteLLM. `gateway sync` writes each member's deployment
id into the rendered configuration, and the gateway reads it back off every response — which is
what makes `--group_by node` a real answer rather than an empty table. From the deployment the
GPUs follow, so per-GPU chargeback is a join away.

!!! note "A request that cannot be attributed says so"
    If the response carries no deployment id, the row records none rather than guessing at the
    route's first member. A number billed against a GPU that did not run the work is worse than
    a number that names no GPU.

A throttled request is a usage row too, with status `429` and no tokens — refusals are visible
in the same place as the traffic that caused them. Changing a limit is an audit record, not a
usage row: one is a thing the system did, the other a thing a person decided.

## Policy

```sh
sudo nodary policy show
sudo nodary policy diff regulated
sudo nodary policy apply regulated --justify "moving the pilot to regulated"
```

`policy show` marks every setting nothing acts on yet and names the task that will enforce
it, so the profile can be read as a list of controls rather than a list of numbers. Three of
its seventeen settings are marked today. Two more are **invariants** — `require_signed_artifacts`
and `egress_default` are refused at parse if set to anything else, and the mechanisms behind
them run unconditionally.

`policy diff` reports which settings a candidate profile would **loosen** before you apply
it. Loosening is permitted; doing it silently is not.

Tightening the origin lists under a model already registered does **not** stop it. `policy
apply` names every model the candidate profile would deny, its origin, and what is serving it
— in the preview you approve, not after — and leaves them running:

```
tight now denies 1 already-registered model. Nothing was stopped:
  acme/tiny — origin acme (CN), serving as tiny-fractal
  Stopping one is your decision and is audited: `nodary model disable <id>`.
```

Pulling a model out from under its users is an operator's decision, so the profile flags it and
you make it.

## Accounts and sign-in

Five failed sign-ins in fifteen minutes locks out for fifteen, counted against both the
username and the connecting address — so neither walking a user list nor hammering one
account gets anywhere. The lockout applies to the correct password too; that is the point of
one.

Every failure reads the same to the person trying: an unknown account, a suspended one, one
with no password set and a wrong password are indistinguishable, and take the same time to
answer. The real reason is in the audit record, where an operator investigating can see it
and an attacker cannot.

```sh
sudo nodary audit list --action auth.login
```

!!! note "Lockouts do not survive a control-plane restart"
    They are held in memory. An attacker who can restart the control plane already has root
    on the machine holding the audit chain and does not need to guess passwords, and
    persisting them would put a write on every failed attempt — on the single connection this
    design exists to keep free.

## Administering from your own machine

Every command on this page so far has been `sudo nodary …` on the control-plane host. That
works, and it has one cost you can see in the chain: the record says the act was performed by
`root`, by the method `local`. If three people share that shell, the chain cannot tell you
which of them approved a node.

`--server` is the other road. An administrator mints you a personal token:

```sh
sudo nodary token create --user alice
```

That token is printed once and is never readable again. On your own machine, store it against
the appliance it belongs to:

```sh
nodary login --server https://nodary.example.internal:8443 \
  --ca-fingerprint sha256:…
```

It reads the token on stdin — paste it at the prompt, or pipe it in — checks it against the
control plane before writing anything, and saves it in `~/.nodary/credentials`, mode 0600.
The fingerprint is the one `nodary server install` printed and `nodary server status`
reprints, and it is the same value your nodes pin. It is required the first time and
remembered afterwards.

Then the verbs take `--server`:

```sh
nodary node list    --server https://nodary.example.internal:8443
nodary node approve gpu-02 --server https://nodary.example.internal:8443 \
  --justify "new GPU host, ticket OPS-4120"
```

The ceremony is the same one, and it is decided by the control plane rather than by your
laptop: the change is previewed and hashed there, you confirm what you are shown, and the
hash travels back with the act so what is applied is what was on the screen. A policy profile
that demands a TOTP code asks for it here too. The difference is the record:

```
actor    alice            method  token
```

**A verb that does not yet take `--server` refuses it.** It does not quietly act on the
machine you are standing on. These do, today:

| | |
| :--- | :--- |
| Fleet | `node list`, `node show`, `node approve\|drain\|revoke` |
| Models and routing | `model register\|enable\|disable\|restart\|restage\|unstage`, `route list\|show\|set`, `limits show\|set` |
| Accounts | `user add\|list\|show\|suspend\|delete`, `token list\|create\|revoke` |
| Records | `audit list`, `usage show` |
| Configuration | `config show\|export\|list\|diff\|verify\|apply\|rollback` |
| Policy | `policy show\|diff\|apply` |
| Backup | `backup create` |
| Backends | `backend list\|show` |

So the loop closes: an administrator with a credential can mint the next administrator's,
without anybody opening a shell on the control plane.

```sh
nodary token create --user bob --name laptop --expires 30d \
  --server https://nodary.example.internal:8443 \
  --justify "bob is joining the platform team"
```

So a site that keeps its configuration in version control applies it from wherever that
lives:

```sh
nodary config diff -f fleet.toml --server https://nodary.example.internal:8443
nodary config apply -f fleet.toml --server https://nodary.example.internal:8443 \
  --justify "OPS-4131: second replica for gemma"
```

The file itself is what crosses the wire, so the control plane parses the document it is
about to apply and the preview you approve is its reading of your file, not your machine's.

The posture works the same way. A built-in profile travels as its name — the control plane
already has it — and a profile you wrote travels as the file:

```sh
nodary policy diff regulated --server https://nodary.example.internal:8443
nodary policy apply ./site-posture.toml --server https://nodary.example.internal:8443 \
  --justify "OPS-4140: adopting the site posture"
```

Two things are reported before and after that are worth watching for. Anything the new
profile *relaxes* is printed first, before the confirmation, because a posture loosened
quietly is the one that goes unnoticed. And anything the new profile now refuses that is
already registered is printed after — computed on the control plane, since the catalog is
there and not on your laptop. Nothing is stopped: the models keep serving, and turning one
off stays your decision and an audited one.
One difference worth knowing: the gateway's rendering is a file on the control-plane host, so
a route change applied from here goes live when that host's sync timer next runs — within a
minute — rather than immediately. The command says so when it happens.

What is still a shell on the control plane: `model register` and the staging verbs, `backup`,
`policy apply`, and everything that installs or diagnoses a host. `nodary logout --server …` forgets one appliance's credential;
the token itself stays valid until somebody runs `nodary token revoke`, which is the audited
act that ends it for everyone.

!!! note "`--server` and `--db` are refused together"
    They name different control planes, and resolving that quietly — remote wins, `--db`
    ignored — is how you end up certain you read one database while reading another.

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

!!! note "The anchor has to be off this machine"
    A compromised control plane can rewrite the whole chain consistently, and the signed
    evidence bundle does not close that — its signing key is sealed on the same host. What
    does is a copy that left the machine before anyone had a reason to rewrite it. Records
    carry `seq` and `hash`, so a receiver dedupes and detects gaps without trusting the
    sender, and `nodary audit verify --mirror` validates the copy on a machine that has never
    seen the database.

### Shipping records to a SIEM

Uncomment the `[audit]` block in `/etc/nodary/server.toml`:

```toml
[audit]
sinks      = "file:/var/log/nodary/audit.jsonl,https://splunk.internal:8088/services/collector"
on_failure = "warn"
```

Keep the `file:` sink alongside the network one. It costs nothing, and it is what
`audit export --from-seq` re-reads when a destination falls behind.

The credential goes in `/etc/nodary/audit-sink.token`, not in `server.toml` — that file gets
read and pasted while diagnosing things. It holds the **whole `Authorization` header value**,
so every destination is the same mechanism:

```sh
printf 'Splunk 8f3a-…' | sudo tee /etc/nodary/audit-sink.token >/dev/null
sudo chmod 600 /etc/nodary/audit-sink.token
```

`Bearer …` and `ApiKey …` work the same way. The file is re-read for every batch, so rotating
the credential needs no restart.

Four things worth knowing:

- **Delivery never delays a change.** Records are posted by a background worker, one JSON
  document per line. A SIEM that is down or slow costs nothing at the prompt.
- **A backlog is dropped, not queued.** The database is the authoritative copy and holding an
  unbounded spool in the control plane would be a second thing to go wrong. When a destination
  falls behind, catch it up with `nodary audit export --from-seq N`.
- **`on_failure = "block"` refuses the next mutation while a sink is failing.** It cannot
  refuse the one that failed — that record is already committed. `warn` is the default, and is
  the right answer for 800-171 3.3.4, which asks for an alert on an audit logging failure and
  not a halt.
- **Plaintext `http` is refused except to `127.0.0.1`.** Audit records say who did what, when,
  and to which object. A local shipper that owns the TLS itself is the ordinary deployment and
  is allowed; a plaintext URL to another host is not.

### If you have no SIEM

You already have something, and the default already uses it: with nothing configured, records
go to `/var/log/nodary/audit.jsonl`. They are hash-linked, and a *fragment* of the chain — a
rotated file, an `audit export --from-seq`, a copy on a USB stick — verifies against an anchor
rather than needing to begin at the first record ever written. So `nodary audit verify --mirror`
works on a file that has been rotated, split, or carried off the machine by hand.

What that does not give you is anything **off-box**. The mirror is on the same disk as the
database it mirrors, so it proves nothing against somebody who owns this appliance, and the
whole argument for shipping records elsewhere is that a compromised machine cannot quietly
rewrite a copy that already left it.

The cheapest real hop is syslog, which every Linux site already runs:

```toml
[audit]
sinks      = "file:/var/log/nodary/audit.jsonl,syslog:"
on_failure = "warn"
```

`syslog:` is the local daemon, which is usually what you want: point rsyslog at wherever the
site already sends logs — a collector, an MSP's agent, a NAS, a firewall — and nodary stays out
of it. `syslog:tcp://collector.internal:514` and `syslog:udp://…` talk to a remote daemon
directly. The port is required rather than assumed to be 514, because delivering nothing to a
port nobody reads is exactly the failure this is meant to prevent. Records go to the `authpriv`
facility, tagged `nodary`.

!!! warning "Syslog truncates, so it is the monitoring copy and not the evidence"
    A syslog receiver is entitled to cut a message at 1024 bytes, and implementations vary above
    that. A record with a large `detail` carries fine in the database and may arrive at the
    collector cut in half — which breaks verification *of that copy*. Treat the syslog stream as
    alerting and review; keep the `file:` sink and `nodary audit export` as the copy an assessor
    is given.

For an assessment, the artifact to hand over is not a log stream at all — it is
`nodary evidence`, which packages a period's records with the chain's own proof and a manifest.

**Rotation.** Nothing here ships a `logrotate` policy yet, and if you write one it must use
`create` and not `copytruncate`: the sink reopens the file by path for every record, so
rename-and-create is safe and truncating underneath an appender is not.

## Retention

`nodary-prune.timer` runs a retention pass daily and the windows come from the active profile —
`audit_retention_days` (1095 by default) and `usage_retention_days` (90). Nothing is configured
per host: change the profile and the next pass follows it.

```sh
sudo nodary prune --dry-run --justify "checking what would go"
sudo systemctl list-timers nodary-prune.timer
sudo nodary audit list --action data.prune
```

`--dry-run` renders the range and changes nothing. Each real pass writes one audit record naming
what it removed, including a pass that removed nothing — a retention history with gaps in it
cannot be told from one that was edited.

Raw `usage` rows are **rolled into `usage_daily` before they go**, in the same transaction, so
per-day totals per user and model survive the rows behind them. Expired join tokens are purged a
day after they expire. Revisions are kept indefinitely: they are the configuration history and
they are small.

### Why a pruned chain still verifies

`audit verify` holds a database to a chain starting at seq 1, because a database is supposed to
hold the whole chain — so a prefix missing from one means records were deleted. A prune therefore
records **where it cut**, and verification checks the survivors against that instead of against
genesis. This is the same mechanism a rotated sink file already uses: an anchored fragment proves
as much as a whole chain from the anchor onwards.

!!! warning "Pruning removes evidence, and nothing on this box can prove what it said"
    The cut is recorded in the same database, so it defends nothing about the range that is
    gone — no local record can, once the records are. Retention is exactly when the off-box
    copy stops being optional: configure the `[audit]` sink above, or ship
    `/var/log/nodary/audit.jsonl` into WORM storage yourself, *before* the window closes.
    `nodary audit verify --mirror` keeps proving what the pruned range said long after the
    database stops carrying it.

## Backups

The database is one file, and it is **useless on its own** — the TOTP seeds and the agent CA
private key inside it are sealed under `/etc/nodary/secret.key`, and the CA's own certificate
lives beside that rather than in the database at all. The LiteLLM master key is not in the
database either: it sits in the clear in `/etc/nodary/gateway.env` and `/etc/nodary/litellm.yaml`,
both 0600, because LiteLLM reads a plain YAML file and has no way to consume a sealed value.
So one command takes all of it:

```sh
sudo install -d -m 0700 /var/backups/nodary
sudo nodary backup create --out /var/backups/nodary/$(date -u +%Y-%m-%d).tar.gz
```

It refuses a world-readable destination, writes the archive 0600, and prints what it captured.
The database is snapshotted with `VACUUM INTO` rather than copied, so it is consistent as of
that instant with the control plane still serving — `cp nodary.db` on a live host silently
omits everything since the last checkpoint.

!!! warning "The archive is as sensitive as the sealing key, because it contains it"
    Anyone holding it can read every TOTP seed, the LiteLLM master key and the agent CA
    private key. Store it where you would store `/etc/nodary/secret.key` itself.

You can take one from your own machine, which is worth having at the moment you most want a
backup — just before a change you are not sure about:

```sh
nodary backup create --out /var/backups/nodary/before-OPS-4150.tar.gz \
  --server https://nodary.example.internal:8443 \
  --justify "OPS-4150: before the policy change"
```

`--out` is a path **on the control plane**, and that is where the archive stays. nodary will
not carry the sealing key to your laptop, so moving the file off that host remains whatever
already moves your backups off it. What you gain is the record: the chain says you took this
backup, where a cron on the host says `root`. Restore is the other way round — it runs on the
console, with the control plane stopped, and refuses `--server` for that reason.

!!! note "The master key is a mode, not a seal"
    Anyone who can read `/etc/nodary/gateway.env` can present that key to `127.0.0.1:4000` and
    reach LiteLLM directly — past the route allowlist, the quota and the metering. That is why
    both files are 0600 rather than 0640: the service account's *group* is not a set of people
    who should be able to bypass accounting. `server install` and `nodary upgrade` both put the
    mode back rather than assuming it, so a host installed by an older release is tightened by
    the next run of either.

To put one back:

```sh
sudo systemctl stop nodary-server
sudo nodary backup restore --from /var/backups/nodary/2026-09-13.tar.gz
sudo nodary audit verify
sudo systemctl start nodary-server
```

Restore writes files and **starts nothing**. It refuses an existing database or sealing key
unless you pass `--force`: a database from one moment beside a sealing key from another does
not announce itself, it fails weeks later at a TOTP prompt or a node's next request. It also
refuses an archive that holds a database but no sealing key, rather than restoring a control
plane that starts and cannot read its own secrets.

## Upgrading

An upgrade is two steps, and only the second one is this verb. `install.sh` fetches a release,
verifies its signature and its digest, and repoints `/opt/nodary/current`; `nodary upgrade` then
moves everything that release pins onto the host.

The second step is the one that matters for a CVE in the data plane. The LiteLLM image a
control plane runs is named in `/etc/nodary/litellm.env`, written once at install time from the
manifest embedded in the binary of the day. A release that moves that pin does not rewrite the
file, so until you run this the fixed digest sits in the new binary and the vulnerable image
keeps starting.

```sh
sudo nodary advisory check          # does a published advisory name a digest we pin?
curl -fsSL https://nodary.net/install.sh | sh
sudo nodary upgrade --check         # which pins would move, and to what
sudo nodary upgrade --justify "CVE-2026-… in the data plane"
```

`--check` reads and changes nothing: the release `current` points at, the image pinned in
`litellm.env`, and the digest of every archive and binary in `/etc/nodary/components.json` — each
against what this binary pins. A file it cannot read is a failure, not an absent pin; a report
that guessed would be answering "is this host exposed" from something nobody opened.

The upgrade itself takes a backup first, names it in the output, and then moves the binary, the
unit files, the mirror, and the image pin — restarting only the units whose inputs actually
changed. It does not touch `server.toml`, `litellm.yaml`, or anything else you configured:
re-running `server install` as an upgrade would, which is why this is a separate verb.

!!! warning "GPU nodes are upgraded by hand"
    `nodary upgrade` moves the host it runs on. Agents fetching a new binary from their control
    plane's mirror is [R5-16](https://github.com/nodarynet/nodary/blob/main/docs/tasks/R5-install.md)
    and is not built, so a node is upgraded by re-running `install.sh` on it. The two sides
    share a protocol version and skew is bounded to the upgrade window, so do the control plane
    first and the nodes shortly after.

    `--to VERSION` is refused rather than silently absent. Fetching a release means verifying a
    release signature, and until the signing key ships there is nothing to verify against — an
    upgrade that downloaded something unchecked is exactly what the install path has no override
    flag for.

## Removing nodary

```sh
sudo nodary uninstall                          # a GPU node
sudo nodary uninstall --purge                  # a control plane, or a --with-node box
sudo nodary uninstall --purge --purge-models   # and the weights
```

One verb for whichever roles the host has, so a `--with-node` box needs no special handling. It
stops and disables the units, removes them, removes `/opt/nodary`, the `nodary` link and
`/etc/nodary`, and deletes the components **nodary itself installed** — a `containerd` that was
already on the machine when nodary arrived is recorded as found and is left where it is, along
with any unit file nodary did not write.

By default `/var/lib/nodary` and the weights stay. `--purge` takes the state and the logs;
`--purge-models` takes the weights, and is separate because they are the most expensive thing on
the disk. `--purge` on its own never deletes weights, even though they live inside the data
directory.

!!! warning "A control plane needs `--purge`, and not only for tidiness"
    `/etc/nodary` is removed either way, and `secret.key` is in it. Keeping
    `/var/lib/nodary` without it would leave a database nothing can ever unseal again — every
    TOTP seed, the agent CA private key and the LiteLLM master key with it. So the uninstall
    refuses rather than letting you find out later. If you want any of it, take a backup
    first: `nodary backup create /path/to/backup.tar.gz`.

Uninstalling a node does **not** tell the control plane, for the same reason `nodary node leave`
does not: a node announcing its own departure is a claim the far end would have to trust from
the machine least able to make it. The fleet still holds its certificate until an administrator
runs `nodary node revoke <name>` on the control plane, and the uninstall prints that line.

## Checking a host

```sh
nodary status          # what this host runs, and whether it is running
sudo nodary doctor     # why it is not
```

`status` is the shallow one, and answers the question you actually asked: which roles this
machine carries, every unit they own, and whether each is up and enabled. It works on a host
that is a control plane, a node, or both, and it exits nonzero when something installed here
is not running — so it is usable from a monitoring check without parsing anything. It does no
chain verification and touches no network, so it is instant on any size of install.

`doctor` is the one that goes looking: driver, GPU enumeration, containerd, the isolated
network, certificate expiry, and a live re-run of the egress assertion — in one pass.

```sh
sudo nodary restart
```

Bounces every nodary unit this host owns, data plane before the API that proxies to it. It
does **not** restart containerd: that is a shared runtime nodary installs rather than owns, and
restarting it stops every container on the machine — every deployment with them — to fix
something that is almost never containerd.

!!! note "Certificates renew themselves"
    An agent certificate lasts 90 days and the agent replaces it two thirds of the way
    through, over the mTLS channel it already has — so there is nothing to diarize. Issuing
    supersedes the old certificate immediately, and the first attempt is thirty days before
    expiry, so a control plane that is unreachable for a week costs nothing.

    A node that is **offline past expiry** cannot renew and must re-enroll with a fresh join
    token, which takes an administrator by design. It keeps its state and its approval.
    `nodary doctor` reports the expiry on any host.

## Next

- The [CLI reference](https://github.com/nodarynet/nodary/blob/main/docs/specs/10-cli.md)
  covers every verb and every flag.
- The [specifications](https://github.com/nodarynet/nodary/tree/main/docs/specs) are what
  every component is required to do; the
  [decision records](https://github.com/nodarynet/nodary/tree/main/docs/adr) say why.
- The [implementation tracker](https://github.com/nodarynet/nodary/tree/main/docs/tasks)
  is what is done and what is next.
