# 01 — Installation

## 1. Artifacts

Three objects, named distinctly. "Bundle" refers to the third and only the third
([ADR 0004](../adr/0004-release-artifacts-and-channels.md)).

| Object | Contents | Size |
| :--- | :--- | :--- |
| **Binary** | `nodary` — server, agent and CLI in one executable | ~20–40 MB |
| **Component manifest** | Every third-party dependency: name, version, per-platform URL, SHA-256 | embedded in the binary |
| **Offline bundle** | The binary plus components resolved from the manifest | GB, site-dependent |

The binary is the only thing any channel ships. Components — containerd, `nerdctl`, runc, CNI
plugins, the NVIDIA container toolkit, LiteLLM, Prometheus, Grafana, `dcgm-exporter` — are
resolved at install time against the embedded manifest, or supplied by a bundle.

```sh
nodary components list                # what this binary pins, and where it fetches from
nodary components verify              # every URL reachable, every digest correct
```

`components verify` exists to be run in CI. A stale upstream URL is a broken install, and that
should fail in a pipeline rather than on someone's first attempt.

## 2. The `install.sh` contract

`install.sh` is deliberately tiny. It does four things and nothing else:

1. Detect OS and architecture; refuse clearly if unsupported (§8).
2. Download `nodary-<version>-<os>-<arch>`, plus `.sha256` and `.sig`.
3. **Verify the signature against a public key embedded in the script, then verify the SHA-256.** Abort on either failure. This is not optional and has no `--skip` flag.
4. Place the binary at `/opt/nodary/<version>/nodary`, flip the `current` symlink, and `exec` it.

It prints the binary's digest before proceeding, and that digest is written to the audit chain
on first contact with the control plane.

### Verifying without piping to a shell

```sh
curl -fsSLO https://nodary.net/install.sh
curl -fsSLO https://nodary.net/install.sh.minisig
minisign -Vm install.sh -P "$(cat nodary-release.pub)"
sh install.sh server
```

The release public key fingerprint is published in the repository README and in the release
notes, so it can be checked against a source other than the one serving the script.

### What performs the verification

The signature is **ECDSA P-256 over SHA-256**, verifiable with `openssl dgst -sha256 -verify`
against a PEM public key embedded in the script. OpenSSL is the only external tool `install.sh`
requires, and it is present on effectively every Linux host that can run containers.

An Ed25519 `.minisig` is published alongside for out-of-band verification with `minisign`, which
is the better tool but cannot be assumed present on a bare host.

If `openssl` is absent, `install.sh` aborts and prints the manual verification steps. It does
not proceed unverified, and it does not fetch a verifier — a verifier fetched over the channel
being verified establishes nothing.

## 3. Bootstrap order

The first control plane installs from `nodary.net`, or from a bundle on removable media. It
then resolves components once into `/var/lib/nodary/dist/` and **serves that cache to every GPU
host**.

Consequence: **only the control-plane host ever contacts an upstream source.** GPU hosts
bootstrap with no internet access and no container-registry access, exactly as before — the
property is now reached by caching rather than by shipping everything up front.

## 4. Server install

```sh
curl -fsSL https://nodary.net/install.sh | sh -s -- server \
    [--bind 0.0.0.0:8443] [--data-dir /var/lib/nodary] \
    [--tls-cert PATH --tls-key PATH]     # else self-signed, fingerprint printed
    [--components all|minimal|LIST] [--non-interactive]
```

`install.sh` places the binary and `exec`s `nodary server install`, which reopens `/dev/tty`
and prompts for the choices below. **Every prompt has a flag equivalent**; `--non-interactive`
requires that they all be supplied and never prompts.

Steps, in order, each idempotent:

1. **Preflight** (§11). Abort on any hard failure, printing every failure at once.
2. Select components. The prompt offers `minimal` (server, gateway, LiteLLM) or `all` (adds Prometheus, Grafana); an explicit list overrides both.
3. Resolve and verify each selected component into `/var/lib/nodary/dist/`, digest-checked against the embedded manifest. Skip anything already present and correct.
4. Create the `nodary` system user; create `/etc/nodary`, `/var/lib/nodary`, `/var/log/nodary` (0750, owned by `nodary`).
5. Write `/etc/nodary/server.toml`.
6. Initialise `/var/lib/nodary/nodary.db`; run migrations.
7. Generate the internal CA used to sign **agent** certificates. This is nodary's own PKI for mTLS and is unrelated to the server's public TLS certificate.
8. Install and start `nodary-server`, `nodary-gateway`, `litellm`, and the observability units if selected.
9. Create the first administrator account, printing a **one-time setup URL** valid for 15 minutes. No default password ever exists.
10. Print the node join command, including a fresh join token and the CA fingerprint.

```
nodary control plane ready.

  URL         https://nodary.example.internal:8443
  Setup       https://nodary.example.internal:8443/setup?t=<one-time>   (expires in 15m)

  Add a GPU node — install nodary there, then:
    nodary node install \
        --server https://nodary.example.internal:8443 \
        --token nodary_jt_… \
        --ca-fingerprint sha256:…
```

## 5. Node install

A GPU host runs `nodary node install`. The binary must be present first, by any channel:

```sh
# from the control plane's mirror
curl -fsSL https://<server>:8443/install.sh | sh -s -- node \
    --server URL --token TOKEN --ca-fingerprint sha256:… \
    [--models-dir /var/lib/nodary/models] [--name HOSTNAME]

# or, binary already installed by package manager
pip install nodary && nodary node install --server … --token … --ca-fingerprint …
```

1. **Preflight** (§11).
2. Fetch components from the control plane's mirror — containerd, `nerdctl`, CNI plugins, the NVIDIA container toolkit — digest-verified against the embedded manifest. Skip anything already present at an acceptable version.
3. Create the `nodary-isolated` CNI network ([03](03-agent.md#5-egress-isolation)).
4. Enroll ([02](02-enrollment.md)). Obtain a client certificate.
5. Write `/etc/nodary/agent.toml`; install and start `nodary-agent` and `dcgm-exporter`.
6. Report inventory. The machine appears in the control plane as a **pending** node.

The node receives no workload until an administrator approves it.

### Vocabulary

`server` and `node` are the two install roles, and `node` is also the fleet object: a machine
installed with `nodary node install` is administered with `nodary node list`, `node approve`,
`node drain`, `node verify-egress`. `host` is never a role — it is the ordinary English word
for a machine, used for both the control-plane host and a GPU host. `client` means one thing
only: something holding a bearer token and calling the inference API ([06](06-gateway.md)).

### Self-signed control planes

With `--tls-cert`, the `curl` above works unmodified. With the default self-signed certificate
it will not: `curl` has no way to trust that certificate yet, and this is the first command a
new operator runs.

Two supported answers, in order of preference:

1. **Install the binary from a package manager**, then run `nodary node install --ca-fingerprint …`. The binary pins the fingerprint natively and never needs a CA bundle. This is the recommended path, and it is the strongest argument for the wrapper channels being real install paths rather than conveniences.
2. **Pin in `curl`** — the server prints this form when its certificate is self-signed:

```sh
curl -fsSL --insecure --pinnedpubkey "sha256//<base64>" \
    https://<server>:8443/install.sh | sh -s -- node …
```

`--insecure` disables chain validation while `--pinnedpubkey` enforces an exact key match, so
the combination is stricter than CA validation, not weaker. It looks alarming and is not; the
printed command says so.

## 6. Offline install

An offline bundle is generated on a connected machine and carries exactly what the target site
needs:

```sh
# on a connected machine
nodary bundle create --platform linux/amd64 \
    --backends vllm,sglang --components all \
    -o nodary-2.0.0-linux-amd64.tar.zst

# on the air-gapped control plane
sh install.sh server --offline --bundle ./nodary-2.0.0-linux-amd64.tar.zst
```

`bundle create` resolves against the same embedded manifest the online path uses, so both
verify identically. Signature and digest verification still run on install; `--offline`
removes the download, not the checks.

GPU hosts still need nothing but the control plane: it serves the bundle's contents from its
mirror exactly as it serves resolved components.

## 7. Package-manager channels

Every channel ships the binary and nothing else, so all of them reach the same state
([ADR 0004](../adr/0004-release-artifacts-and-channels.md)).

| Channel | Install |
| :--- | :--- |
| PyPI | `pip install nodary` — per-platform wheels; the entry point `execv`s the binary |
| npm | `npm i -g nodary` — per-platform packages under `optionalDependencies` |
| Homebrew | `brew install nodarynet/tap/nodary` |

These are complete install paths. `pip install nodary && nodary server install` and
`curl … | sh -s -- server` differ only in how the binary arrived.

**Unsupported platforms must fail loudly.** npm resolves `optionalDependencies` silently, so a
platform with no matching package installs *nothing* and fails later at the shim with an
unrecognisable error. The wrapper packages therefore declare `os` and `cpu`, and the shim
checks for its platform package and exits with a named error if absent. Wheels carry precise
platform tags so `pip` reports "no matching distribution" rather than installing a broken
entry point.

## 8. Platform support

| Platform | Binary | `server` / `node` install | CLI |
| :--- | :--- | :--- | :--- |
| `linux/amd64`, `linux/arm64` | ✔ | ✔ | ✔ |
| Windows via WSL2 | ✔ (the Linux binary) | ✔ | ✔ |
| `darwin/amd64`, `darwin/arm64` | ✔ | ✘ | ✔ |
| Windows, natively | ✘ | ✘ | ✘ |

The server and the agent require systemd and cgroup v2, so they are Linux-only. macOS builds
exist for the operator CLI — `nodary node list --server …` from a workstation. `nodary server
install` and `nodary node install` on macOS exit with a single clear line naming the
requirement, not a systemd error.

There is no native Windows build and there will not be one: Windows containers run Windows
images, and the model servers are Linux images. Both wrapper channels are configured so a
native Windows install fails at resolution with a comprehensible message.

### Windows hosts run as WSL2 nodes

A Windows machine with an NVIDIA GPU joins the fleet by running nodary **inside WSL2**, where
it is an ordinary Linux node: same binary, same install command, same protocol. The control
plane sees `linux/amd64` and needs to know nothing else.

This is worth supporting because it is where a lot of homelab GPU capacity actually lives — a
desktop with a good card, already running Windows, not worth reinstalling.

```powershell
wsl --install -d Ubuntu          # once, on the Windows host
```

Then, inside the distribution, the normal node install. Three things differ, and preflight
checks all of them (§11):

- **The GPU driver comes from Windows.** CUDA passes through to WSL2 from the host driver, and `libcuda` is provided at `/usr/lib/wsl/lib`. **Installing an NVIDIA driver inside the distribution breaks the passthrough** — nodary skips driver installation on WSL and says so.
- **systemd is opt-in.** WSL2 runs it only when `/etc/wsl.conf` contains `[boot]` / `systemd=true`, followed by `wsl --shutdown` on the host.
- **The distribution does not start at boot.** Nothing runs until something invokes it, so a rebooted Windows host comes back with no agent unless a scheduled task starts the distribution at logon.

Two performance traps, reported as warnings rather than failures: the models directory must be
on the distribution's own filesystem and never under `/mnt/c`, where 9p makes staging
pathologically slow; and WSL2 caps VM memory at roughly half the host's RAM unless
`.wslconfig` says otherwise.

## 9. Upgrade

```sh
nodary upgrade [--to VERSION] [--check]
```

Control plane first, then agents. The control plane resolves the new binary and any changed
components into its mirror, then instructs agents to self-upgrade from it. An agent that cannot
upgrade keeps running its current version and reports `upgrade_failed` rather than falling over.

Server and agent are the same binary and share a protocol version, so skew is bounded to the
upgrade window ([03](03-agent.md#4-version-skew)). A version bump may change the component
manifest; `nodary upgrade --check` reports which components would move and to what digest.

## 10. Uninstall

```sh
nodary uninstall [--purge] [--purge-models] [--force]
```

Default behaviour is conservative:

1. Deregister from the control plane (audited). `--force` skips this if the server is unreachable.
2. Stop and remove all `nodary-*` units.
3. Remove `/opt/nodary` and `/etc/nodary`.
4. Remove components **nodary installed**, and only those.
5. **Keep** `/var/lib/nodary` and the models directory.

Step 4 is possible because installation records component ownership: anything nodary resolved
and placed is removed, anything found already present at install time is left alone. Ownership
is recorded per component at install, not inferred at uninstall.

`--purge` removes state and logs. `--purge-models` removes staged weights — kept separate
because weights cost hours to restage and are the most expensive thing on the machine.
Uninstalling the server requires `--purge` to be explicit about the audit database.

## 11. Preflight

Reported as one list, hard failures and warnings distinguished, so a misconfigured host
surfaces every problem at once rather than one per run.

| Check | Hard failure if |
| :--- | :--- |
| systemd present, cgroup v2 | absent — containerd and systemd resource control require it |
| Architecture / OS supported | unsupported (§8) |
| NVIDIA driver present | absent, or below the minimum version |
| `nvidia-smi` enumerates GPUs | none found (node role) |
| Disk space on models dir | below the configured minimum |
| Disk space for components | below what the selected set requires |
| Clock skew versus server | greater than 60s — breaks mTLS and audit ordering |
| Ports free | gateway or server ports in use (server role) |
| Component source reachable | any selected component unreachable (server role, online install) |
| Conflicting runtime | an existing nodary install at a different version |

On WSL2, additionally:

| Check | Hard failure if |
| :--- | :--- |
| systemd enabled in `/etc/wsl.conf` | absent — the message names `systemd=true` and `wsl --shutdown`, not a missing `systemctl` |
| CUDA passthrough working | `nvidia-smi` present but enumerating nothing, which is the signature of a driver installed *inside* the distribution |
| No in-distribution NVIDIA driver | a Linux NVIDIA driver package is installed, which breaks passthrough |

Warnings, not failures: no swap; SELinux or AppArmor enforcing; unusually low RAM per GPU; an
encrypted root without an automatic unlock path ([03](03-agent.md#reboot-safety)).

On WSL2, additionally as warnings: no scheduled task starting the distribution at logon, so the
node will not return after a Windows reboot; a models directory under `/mnt/c`; and a
`.wslconfig` memory cap low for the GPUs present.

## 12. Filesystem layout

```
/opt/nodary/<version>/nodary     the binary
/opt/nodary/current              symlink → active version
/etc/nodary/server.toml          bind, TLS paths, data dir           (0640 nodary:nodary)
/etc/nodary/agent.toml           server URL, node name, models dir   (0640 nodary:nodary)
/etc/nodary/components.json      what nodary installed, for uninstall
/etc/nodary/secret.key           at-rest encryption key              (0400 root:root)
/etc/nodary/pki/                 agent client cert + key, CA cert    (0400 nodary:nodary)
/etc/nodary/backends/            operator-added backend descriptors  (04-backends.md)
/etc/nodary/deployments/<id>.env per-deployment unit environment
/var/lib/nodary/nodary.db        control-plane state (server only)
/var/lib/nodary/dist/            component mirror served to nodes (server only)
/var/lib/nodary/models/          weights, HF cache layout            (configurable)
/var/log/nodary/audit.jsonl      append-only audit mirror
/var/log/nodary/agent.log        agent log (also journald)
```

Built-in backend descriptors are embedded in the binary; `/etc/nodary/backends/` holds only
operator-added ones ([04](04-backends.md#1-why-descriptors-rather-than-plugins)).
