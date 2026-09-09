# R5 — Installation

**Deliverable:** `install.sh`, component manifest, PyPI/npm/Homebrew channels,
`bundle create`, `upgrade`, `uninstall`, `doctor`.
**Proves:** one-command install — the goal is met.
· [00 §8](../specs/00-overview.md#8-milestones)

Deliverable level. Break these into tasks when R5 starts.

R5 is not greenfield. [R0](R0-release.md) built the distribution path ahead of
the milestones, so `install.sh`, the component manifest, the wheel and npm
builders, CI and the release workflow already exist. What R5 adds is everything
downstream of "the binary is on the host": preflight, the interactive installs,
the mirror, upgrade, uninstall and `doctor`. R0's own outstanding items
(R0-19 … R0-24) are tracked there, not duplicated here.

## Preflight

- [x] **R5-01** Preflight reported as one list, hard failures and warnings distinguished · [01 §11](../specs/01-install.md#11-preflight)
  - *done:* a misconfigured host surfaces every problem at once rather than one per run
  - a constraint on the **control flow**, not the output: nothing returns early, so a fresh host with no driver, no swap and a full disk learns all three in one command instead of over three installs. Asserted directly
  - failures sort first, so the thing that blocks is the thing read before scrolling
  - **a check that cannot run is not a check that passed.** Where the evidence is unreachable the result says so and never reports `ok` — most checks here establish a property by *not* finding a problem, which is exactly the shape [R4d](../plans/R4d-egress-isolation.md) found quietly stops meaning anything
- [x] **R5-02** The Linux checks: systemd and cgroup v2, architecture, NVIDIA driver and version floor, `nvidia-smi` enumeration, disk space for models and components, clock skew over 60s, ports free, component sources reachable, conflicting runtime
  - the driver is read from **nvidia-smi, not a device node**: [the spike](../spike-fips-and-manifest.md#wsl2-binds-a-gpu-through-devdxg-and-there-is-no-devnvidia) measured that a WSL2 host has no `/dev/nvidia*` and nvidia-smi still reports the card, so a filesystem test fails wrongly there and passes vacuously elsewhere
  - clock skew lives in `doctor` rather than preflight, because it needs the other end of the connection to compare against
  - *partial:* "component sources reachable" is `components verify`, which exists but is not yet folded into the preflight list; "conflicting runtime" is not implemented
- [ ] **R5-03** The WSL2 checks · [01 §8](../specs/01-install.md#windows-hosts-run-as-wsl2-nodes)
  - *done:* systemd absent from `/etc/wsl.conf` fails with a message naming `systemd=true` and `wsl --shutdown`, not a missing `systemctl`; CUDA passthrough broken by an in-distribution NVIDIA driver fails at preflight rather than letting deployments fail at start
- [x] **R5-04** Warnings that do not block: no swap, SELinux or AppArmor enforcing, low RAM per GPU, encrypted root without automatic unlock, no WSL logon task, a models directory under `/mnt/c`, a low `.wslconfig` memory cap

## Install

- [x] **R5-05** `nodary server install` — the ten ordered, idempotent steps · [01 §4](../specs/01-install.md#4-server-install)
  - *done:* every prompt has a flag equivalent and `--non-interactive` requires them all and never prompts; the binary reopens `/dev/tty`, which is why `install.sh` `exec`s rather than runs and returns
  - the install **resolves the node runtime into the mirror**, which is the half [01 §3](../specs/01-install.md#3-bootstrap-order) makes load-bearing: only the control-plane host contacts an upstream source, so an empty mirror is a fleet that cannot be built — and the symptom appears on a *different* machine, much later. Four artifacts, 108 MB, digest-verified; a re-run re-verifies in 0.08s and says so rather than reporting a change
  - **step 2's component selection is deliberately not implemented.** Every server-role component in the manifest is an `image` — LiteLLM, Prometheus and Grafana are pulled from a registry by digest, not staged into a file cache — and no unit in this slice runs one, so `--components minimal|all` would offer a choice between two sets the install cannot act on. `Manifest.Select` already implements the semantics for when there is something to select; it had **no caller at all** before this row
  - a fetch that fails is a **warning naming the consequence**, not a failure: everything else about the control plane is correct, and rolling back because a CDN was unreachable would leave nothing to retry from. `--offline` skips it outright, for an install from a bundle
  - the units are started **after** every write, not in §4's printed position: the control plane opens the same database, and there is no reason to have two writers on it while the install is still minting credentials into it
  - step 10 prints a **real** join token rather than `nodary_jt_…`. One use, one hour — long enough to walk to the GPU host, short enough that the scrollback stops being a way in
  - *deferred:* a control plane serving nodes of another architecture still needs `nodary components fetch --platform`; the install resolves for its own host only
- [x] **R5-06** Component resolution into `/var/lib/nodary/dist/`, digest-checked against the embedded manifest, skipping anything already present and correct
  - verify-**then**-rename: an artifact is hashed in a temporary file and only then moved into place, so a killed fetch leaves a temporary file rather than something that looks complete. Same rule [05 §3](../specs/05-catalog.md#3-staging) applies to weights, same reason
  - "already present and correct" is checked by **digest, not presence**, which is what makes re-running an install re-verify rather than re-download — and what catches a tampered cache instead of trusting it because the file exists. A cached artifact whose digest is wrong is **refused, not replaced**: overwriting would erase the only evidence that something put a different file where nodary keeps a pinned one
  - proved against the real pinned artifacts: 108 MB fetched, digests verified, archives extracted, and `bin/containerd`, `nerdctl`, `bridge`, `portmap` and `host-local` all present. `components verify` checks that URLs resolve; this checks what actually breaks an install
- [x] **R5-07** The control plane as a mirror: only the control-plane host contacts an upstream source; GPU hosts bootstrap with no internet and no registry access · [01 §3](../specs/01-install.md#3-bootstrap-order)
  - the mirror sits behind the **same mTLS as the rest of `/agent/`**, so it is not an open file server on the control plane's port: a host that has not enrolled has no business pulling a fleet's pinned runtime. `--mirror` therefore takes no URL — a node fetches from *its* control plane, using the certificate and pin already in `agent.toml`
  - the path is validated against a **whitelist of what `ArtifactName` produces**, not a traversal filter. This handler joins a caller-supplied string to a directory, and "reject what looks dangerous" is the design that keeps needing another exclusion
  - the node verifies the bytes against its own embedded manifest after the mirror serves them, so neither side trusts the other's word
  - this is the same property [03 §5](../specs/03-agent.md#5-egress-isolation) asserts at runtime, applied to install time: a node that curls GitHub to install containerd is a node with egress, on the day it is least supervised
- [x] **R5-08** First administrator with a one-time setup URL valid for 15 minutes · [01 §4](../specs/01-install.md#4-server-install)
  - *done:* no default password ever exists
  - the credential lives on the **installation row**, not in a table of its own. A setup link creates the *first* administrator, so the existence of any account retires it whether or not it was ever redeemed — the state already makes it single-use, and a table would let a second live credential be represented, which is a state this has no meaning for
  - the hash comparison, the expiry and the burn are **one UPDATE**, so two redemptions arriving together cannot both succeed. Same reasoning as `RedeemJoinToken`, and it matters more here because what is at stake is who administers the installation
  - `KindSetup` carries the `nodary_st_` prefix and is **deliberately absent from `Kinds`**, so `nodary token create --kind st` stays an error. The prefix is for [02 §4](../specs/02-enrollment.md#4-token-types)'s reason — greppable in a log, recognizable to a scanner — not a license to mint one
  - re-running the install **replaces** an outstanding link rather than leaving the operator holding one whose plaintext scrolled away. The old one dies at that moment, which is the safer half of the trade
  - the page is `html/template` with no stylesheet, script or external reference: it is served by a control plane on a self-signed certificate to somebody who has just installed it, and a CDN reference would be a request that fails on exactly the air-gapped host this product is for
- [x] **R5-09** `nodary node install` — preflight, fetch from the mirror, create `nodary-isolated`, enroll, write `agent.toml`, start units, report inventory · [01 §5](../specs/01-install.md#5-node-install)
  - built and **staged-verified**: preflight, enrol, layout, 108 MB fetched through the mirror over mTLS, containerd/`nerdctl`/runc placed and executing, 20 CNI plugins extracted, the unit written, and a re-run reporting **zero** changes
  - **enrollment happens before the fetch**, inverting 01 §5's printed order. That order assumes components come from upstream; [01 §3](../specs/01-install.md#3-bootstrap-order) makes the control plane the only host that does, and the mirror is behind mTLS — so a node cannot fetch until it holds a certificate. The sequence is forced · [R5c §2](../plans/R5c-the-privileged-install.md)
  - **verified as root on a real host** by [`scripts/verify-privileged.sh`](../../scripts/verify-privileged.sh): 36 checks, 0 failures. Placing outside a prefix, the units starting under systemd, `nft`, and a live container on `nodary-isolated`
- [x] **R5-10** Filesystem layout and permissions exactly as specified, including `secret.key` at 0400 root and `/etc/nodary/pki/` at 0400 · [01 §12](../specs/01-install.md#12-filesystem-layout)
  - modes are set on **every run**, not only at creation: an install that checked once would let a `chmod 777` stand forever, and `/var/lib/nodary` at 0755 is the audit chain readable by every user on the box
  - ownership is verified as root: `server.toml`, the PKI and the database belong to `nodary`, and `secret.key` stays 0400 **root**. The install runs as root and the units do not, so `install.EnsureOwnership` is its last step — without it the control plane could not open the configuration its own installer had just written
  - `secret.key` at 0400 root:root only works because `nodary-server.service` carries `LoadCredential=`. systemd reads it as root and places a copy in a per-unit ramfs at **0440**, group-readable by the service account — not the 0400 a user unit shows
- [x] **R5-11** `/etc/nodary/components.json` records component ownership **at install**, so uninstall removes what nodary placed and leaves what it found · [01 §10](../specs/01-install.md#10-uninstall)
  - *done:* ownership is recorded, never inferred at uninstall time
  - the record distinguishes **placed by nodary** from **found already present and acceptable**, and only the first is ever removable. A host may already have containerd, installed by its operator and in use by something else; removing it because the name appears in nodary's manifest would take that down — on a machine [12](../specs/12-node-guardrails.md) opens by pointing out is rarely only a nodary node
  - written as each artifact lands rather than at the end, so an install killed halfway leaves a record of exactly what it had placed
- [x] **R5-12** The `--with-node` single-box deployment · [00 §2](../specs/00-overview.md#2-topology)
  - it **composes the two installs** rather than reimplementing either, for the reason `node install` composes `components fetch` and `node enroll`: the path an operator would take by hand is the path this takes, so there is one implementation to be wrong about. It is the shape [`scripts/verify-privileged.sh`](../../scripts/verify-privileged.sh) has been running as two steps all along
  - it **waits for the port**. `systemctl enable --now` returns once the unit is active, and `Type=exec` means active as soon as the binary has been exec'd — not once it holds the port. Enrolling into that gap fails with `connection refused`, which would show up as an install that works most of the time
  - it enrolls against `127.0.0.1`, never the printed hostname: `EnsureServerCertificate` seeds `localhost` and `127.0.0.1` before any `--host`, so the single-box case never depends on the operator having named the machine correctly
  - it mints its **own** join token. Spending the printed one would hand the operator a command that fails the first time they run it on another host
  - `--with-node` with `--root` is refused by name: a staged install starts nothing, so there is nothing to enrol into
  - *unverified:* the single command has not been run as root. Every path it calls has been — this is `server install` followed by the `node install` that [`scripts/verify-privileged.sh`](../../scripts/verify-privileged.sh) proves in 36 checks

## Offline

- [ ] **R5-13** `nodary bundle create --platform --backends --components -o FILE` · [01 §6](../specs/01-install.md#6-offline-install)
  - *done:* it resolves against the same embedded manifest the online path uses, so both verify identically
- [ ] **R5-14** `install.sh server --offline --bundle …`
  - *done:* `--offline` removes the download, not the checks. An invalid bundle signature aborts the install and there is no override flag · [11 §3](../specs/11-failure-modes.md#3-security-controls)

## Lifecycle

- [ ] **R5-15** `nodary upgrade [--to VERSION] [--check]` — control plane first, then agents from its mirror · [01 §9](../specs/01-install.md#9-upgrade)
  - *done:* `--check` reports which components would move and to what digest; an agent that cannot upgrade keeps running its current version and reports `upgrade_failed` rather than falling over; a pre-upgrade backup is taken automatically and named in the output
- [ ] **R5-16** `GET /api/v1/agent/dist/{version}` serving the binary and components for agent self-upgrade · [03 §1](../specs/03-agent.md#1-transport)
- [ ] **R5-17** `nodary uninstall [--purge] [--purge-models] [--force]` · [01 §10](../specs/01-install.md#10-uninstall)
  - *done:* the default keeps `/var/lib/nodary` and the models directory; `--purge-models` is separate because weights cost hours to restage; uninstalling the server requires `--purge` to be explicit about the audit database
- [x] **R5-18** `nodary doctor` · [10 §3](../specs/10-cli.md#3-nodary-doctor)
  - *done:* it exits non-zero on any hard failure, prints a copy-pasteable summary, and runs egress verification here as well as after every deployment start — a control that is only checked at creation time is a control that drifts
  - it asserts against exactly the set the reconcile loop manages (`RunningDeployments`), because a diagnostic checking a different set would be answering a different question
  - an assertion that could not run is a **warning, never a pass**

## Channels

- [ ] **R5-19** macOS is the operator CLI only · [01 §8](../specs/01-install.md#8-platform-support)
  - *done:* `server install` and `node install` on macOS exit with a single clear line naming the requirement, not a systemd error
- [ ] **R5-20** Unsupported platforms fail loudly in every channel
  - *done:* npm resolves `optionalDependencies` silently, so the shim checks for its platform package and exits with a named error; wheels carry precise tags so `pip` reports "no matching distribution" rather than installing a broken entry point
- [ ] **R5-21** A native Windows install fails at resolution with a comprehensible message in both wrapper channels
- [ ] **R5-22** Move npm publishing to Trusted Publishing · [ADR 0004](../adr/0004-release-artifacts-and-channels.md)
  - *done:* `NPM_TOKEN` is gone and npm authenticates by OIDC, as PyPI already does. This removes the last long-lived publishing credential and the whole class of failure that `EOTP` belongs to
- [ ] **R5-23** Resolve the goreleaser `brews` deprecation before it is removed
  - *done:* the Homebrew channel survives a goreleaser major bump. The migration target, `homebrew_casks`, is macOS-only, so adopting it as-is would silently drop Linux Homebrew users — and Linux is the primary platform while macOS is CLI-only ([01 §8](../specs/01-install.md#8-platform-support)). Decide deliberately: keep a formula by another route, or accept narrowing the channel and say so in [ADR 0004](../adr/0004-release-artifacts-and-channels.md)
- [ ] **R5-24** Move npm's `latest` tag off the release candidate
  - *done:* `npm install -g nodary` resolves to a stable version. `--tag next` does not hold on a package's **first** publish — npm must give a new package a `latest` and has nowhere else to point it — so `0.0.1-rc1` currently owns it. Publishing `0.0.1` with `--tag latest` fixes it; `npm deprecate` warns installers in the meantime

## FIPS and the manifest

Both come from [pivot §9](../plans/pivot-cmmc.md#9-roadmap-deltas). They land in R5 rather
than reopening a complete [R0](R0-release.md), which is where R0's own follow-ups went.

- [x] **R5-25** A `GOFIPS140=v1.0.0` job in CI that builds the tree and runs the suite, reporting rather than gating · [pivot §3](../plans/pivot-cmmc.md#fips-is-a-build-not-a-rearchitecture)
  - *done:* it answers continuously what [the spike](../plans/mvp.md#4-the-route) answers once — whether the FIPS build compiles, whether the suite passes, and whether TOTP's HMAC-SHA-1 survives the module. Non-gating deliberately: blocking every pull request on an unmeasured dependency, for a claim the [MVP](../plans/mvp.md#6-what-an-mvp-install-cannot-claim) does not make, is the wrong trade · [MVP §5.6](../plans/mvp.md#56-fips-builds-in-ci-and-does-not-gate)
  - the `fips140=only` step records what the module still refuses rather than hiding it: that output is the list of what would have to change for [ADR 0006](../adr/0006-cui-boundary-and-fips.md)'s second gate to open
  - the static-binary step sets `CGO_ENABLED=0` **explicitly**. Measured while writing it: Go's default is `CGO_ENABLED=1`, which produces a dynamically linked binary whether `GOFIPS140` is set or not — so without it the step would have failed on every run, behind `continue-on-error`, telling nobody anything. Verified locally at 1049 `fips140` symbols, statically linked, whole suite passing under `fips140=on`
- [ ] **R5-26** The FIPS artifact ships through the four existing channels · [ADR 0004](../adr/0004-release-artifacts-and-channels.md)
  - *done:* a second artifact, not a second pipeline. This works only because the binary is static and the SQLite driver is `modernc` rather than cgo — BoringCrypto needs cgo and would break the property [R0-16](R0-release.md) asserts in CI
  - *deps:* R5-25
- [x] **R5-28** The NVIDIA Container Toolkit is the **host's** to provide, and preflight refuses a node without it · [01 §8](../specs/01-install.md#8-platform-support)
  - *done:* a node with no toolkit is refused before anything is installed, rather than after a deployment has failed for a reason naming something else
  - **it is not a component nodary fetches**, and 01 §1 and §5 are corrected to stop saying it is. Measured: upstream publishes the toolkit only as distribution packages — the release assets are a tarball *of `.deb`s and `.rpm`s*, not the flat binary archive containerd, runc and nerdctl ship — and one of them is a shared library needing a loader path. Placing it would be nodary reimplementing dpkg
  - it is also **versioned against the driver**, and [01 §8](../specs/01-install.md#8-platform-support) already establishes that nodary must not touch the driver on WSL2, where installing one breaks the passthrough
  - this is why no model had ever run. `nodary-model@.service` runs `nerdctl run --gpus …`, nerdctl 2.x resolves that through a CDI spec `nvidia-ctk cdi generate` writes, and without it a deployment starts a container with **no device** — surfacing as a model server that cannot find CUDA, naming neither the toolkit nor the flag
  - [`scripts/verify-privileged.sh`](../../scripts/verify-privileged.sh) step 13 runs `nvidia-smi` **inside a container**, which is the only assertion that covers the device, the libraries and the driver together
- [x] **R5-29** The control plane runs LiteLLM: the configuration is written, the image is pinned, and a unit starts it · [00 §7](../specs/00-overview.md#7-why-litellm-stays)
  - *done:* a completion can reach a model. Until this, `LiteLLMConfig.Render` had **no caller** — the data plane was configured in principle and absent in practice, so R3-16 was asserting the contents of a file nobody wrote
  - the runtime gains a **server role**. [00 §2](../specs/00-overview.md#2-topology) puts LiteLLM on the control-plane host and the manifest gave containerd, `nerdctl` and runc to nodes only, which left that host with no way to run the data plane its own topology diagram places on it. Placed from the artifacts just fetched, so the mirror and the host cannot hold different builds of one pinned digest
  - `--network host`, deliberately: a deployment publishes on the host's loopback ([03 §5](../specs/03-agent.md#5-egress-isolation)) and a container on a bridge cannot reach it. LiteLLM binds `127.0.0.1:4000` itself, so nothing it serves is reachable off-box
  - the master key is **read back** when it already exists. It has to appear in two files, and a re-run that regenerated it would leave them disagreeing — presenting as every request failing upstream on a control plane whose install just reported success
  - the configuration is asserted with `gateway.AssertLoggingOff` **before** it is written, not after: [pivot §3](../plans/pivot-cmmc.md#litellm-is-now-a-compliance-surface) makes this a compliance surface, and a bad configuration that reached the disk is in force the moment systemd starts the unit
  - *open:* the configuration is rendered once, at install, with an empty `model_list`. Re-rendering as routes change is R3-14's, and until it lands a new deployment does not reach the data plane on its own
- [ ] **R5-27** The component manifest becomes separately versioned and separately signed, superseding the binary's embedded copy
  - *done:* the embedded manifest remains a floor and a signed revision supersedes it, verified identically and delivered online or through `nodary bundle create`. Without this a customer's patch timeline is coupled to our release cadence while their assessor holds them to a window we do not control · [pivot §6](../plans/pivot-cmmc.md#adr-0007--the-component-manifest-becomes-an-independent-artifact)
  - *deps:* R5-13
