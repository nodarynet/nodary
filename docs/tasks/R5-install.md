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

- [ ] **R5-05** `nodary server install` — the ten ordered, idempotent steps · [01 §4](../specs/01-install.md#4-server-install)
  - *done:* every prompt has a flag equivalent and `--non-interactive` requires them all and never prompts; the binary reopens `/dev/tty`, which is why `install.sh` `exec`s rather than runs and returns
- [x] **R5-06** Component resolution into `/var/lib/nodary/dist/`, digest-checked against the embedded manifest, skipping anything already present and correct
  - verify-**then**-rename: an artifact is hashed in a temporary file and only then moved into place, so a killed fetch leaves a temporary file rather than something that looks complete. Same rule [05 §3](../specs/05-catalog.md#3-staging) applies to weights, same reason
  - "already present and correct" is checked by **digest, not presence**, which is what makes re-running an install re-verify rather than re-download — and what catches a tampered cache instead of trusting it because the file exists. A cached artifact whose digest is wrong is **refused, not replaced**: overwriting would erase the only evidence that something put a different file where nodary keeps a pinned one
  - proved against the real pinned artifacts: 108 MB fetched, digests verified, archives extracted, and `bin/containerd`, `nerdctl`, `bridge`, `portmap` and `host-local` all present. `components verify` checks that URLs resolve; this checks what actually breaks an install
- [x] **R5-07** The control plane as a mirror: only the control-plane host contacts an upstream source; GPU hosts bootstrap with no internet and no registry access · [01 §3](../specs/01-install.md#3-bootstrap-order)
  - the mirror sits behind the **same mTLS as the rest of `/agent/`**, so it is not an open file server on the control plane's port: a host that has not enrolled has no business pulling a fleet's pinned runtime. `--mirror` therefore takes no URL — a node fetches from *its* control plane, using the certificate and pin already in `agent.toml`
  - the path is validated against a **whitelist of what `ArtifactName` produces**, not a traversal filter. This handler joins a caller-supplied string to a directory, and "reject what looks dangerous" is the design that keeps needing another exclusion
  - the node verifies the bytes against its own embedded manifest after the mirror serves them, so neither side trusts the other's word
  - this is the same property [03 §5](../specs/03-agent.md#5-egress-isolation) asserts at runtime, applied to install time: a node that curls GitHub to install containerd is a node with egress, on the day it is least supervised
- [ ] **R5-08** First administrator with a one-time setup URL valid for 15 minutes · [01 §4](../specs/01-install.md#4-server-install)
  - *done:* no default password ever exists
- [ ] **R5-09** `nodary node install` — preflight, fetch from the mirror, create `nodary-isolated`, enroll, write `agent.toml`, start units, report inventory · [01 §5](../specs/01-install.md#5-node-install)
- [ ] **R5-10** Filesystem layout and permissions exactly as specified, including `secret.key` at 0400 root and `/etc/nodary/pki/` at 0400 · [01 §12](../specs/01-install.md#12-filesystem-layout)
- [x] **R5-11** `/etc/nodary/components.json` records component ownership **at install**, so uninstall removes what nodary placed and leaves what it found · [01 §10](../specs/01-install.md#10-uninstall)
  - *done:* ownership is recorded, never inferred at uninstall time
  - the record distinguishes **placed by nodary** from **found already present and acceptable**, and only the first is ever removable. A host may already have containerd, installed by its operator and in use by something else; removing it because the name appears in nodary's manifest would take that down — on a machine [12](../specs/12-node-guardrails.md) opens by pointing out is rarely only a nodary node
  - written as each artifact lands rather than at the end, so an install killed halfway leaves a record of exactly what it had placed
- [ ] **R5-12** The `--with-node` single-box deployment · [00 §2](../specs/00-overview.md#2-topology)

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
- [ ] **R5-27** The component manifest becomes separately versioned and separately signed, superseding the binary's embedded copy
  - *done:* the embedded manifest remains a floor and a signed revision supersedes it, verified identically and delivered online or through `nodary bundle create`. Without this a customer's patch timeline is coupled to our release cadence while their assessor holds them to a window we do not control · [pivot §6](../plans/pivot-cmmc.md#adr-0007--the-component-manifest-becomes-an-independent-artifact)
  - *deps:* R5-13
