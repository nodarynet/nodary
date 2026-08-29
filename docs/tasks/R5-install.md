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

- [ ] **R5-01** Preflight reported as one list, hard failures and warnings distinguished · [01 §11](../specs/01-install.md#11-preflight)
  - *done:* a misconfigured host surfaces every problem at once rather than one per run
- [ ] **R5-02** The Linux checks: systemd and cgroup v2, architecture, NVIDIA driver and version floor, `nvidia-smi` enumeration, disk space for models and components, clock skew over 60s, ports free, component sources reachable, conflicting runtime
- [ ] **R5-03** The WSL2 checks · [01 §8](../specs/01-install.md#windows-hosts-run-as-wsl2-nodes)
  - *done:* systemd absent from `/etc/wsl.conf` fails with a message naming `systemd=true` and `wsl --shutdown`, not a missing `systemctl`; CUDA passthrough broken by an in-distribution NVIDIA driver fails at preflight rather than letting deployments fail at start
- [ ] **R5-04** Warnings that do not block: no swap, SELinux or AppArmor enforcing, low RAM per GPU, encrypted root without automatic unlock, no WSL logon task, a models directory under `/mnt/c`, a low `.wslconfig` memory cap

## Install

- [ ] **R5-05** `nodary server install` — the ten ordered, idempotent steps · [01 §4](../specs/01-install.md#4-server-install)
  - *done:* every prompt has a flag equivalent and `--non-interactive` requires them all and never prompts; the binary reopens `/dev/tty`, which is why `install.sh` `exec`s rather than runs and returns
- [ ] **R5-06** Component resolution into `/var/lib/nodary/dist/`, digest-checked against the embedded manifest, skipping anything already present and correct
- [ ] **R5-07** The control plane as a mirror: only the control-plane host contacts an upstream source; GPU hosts bootstrap with no internet and no registry access · [01 §3](../specs/01-install.md#3-bootstrap-order)
- [ ] **R5-08** First administrator with a one-time setup URL valid for 15 minutes · [01 §4](../specs/01-install.md#4-server-install)
  - *done:* no default password ever exists
- [ ] **R5-09** `nodary node install` — preflight, fetch from the mirror, create `nodary-isolated`, enroll, write `agent.toml`, start units, report inventory · [01 §5](../specs/01-install.md#5-node-install)
- [ ] **R5-10** Filesystem layout and permissions exactly as specified, including `secret.key` at 0400 root and `/etc/nodary/pki/` at 0400 · [01 §12](../specs/01-install.md#12-filesystem-layout)
- [ ] **R5-11** `/etc/nodary/components.json` records component ownership **at install**, so uninstall removes what nodary placed and leaves what it found · [01 §10](../specs/01-install.md#10-uninstall)
  - *done:* ownership is recorded, never inferred at uninstall time
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
- [ ] **R5-18** `nodary doctor` · [10 §3](../specs/10-cli.md#3-nodary-doctor)
  - *done:* it exits non-zero on any hard failure, prints a copy-pasteable summary, and runs egress verification here as well as after every deployment start — a control that is only checked at creation time is a control that drifts

## Channels

- [ ] **R5-19** macOS is the operator CLI only · [01 §8](../specs/01-install.md#8-platform-support)
  - *done:* `server install` and `node install` on macOS exit with a single clear line naming the requirement, not a systemd error
- [ ] **R5-20** Unsupported platforms fail loudly in every channel
  - *done:* npm resolves `optionalDependencies` silently, so the shim checks for its platform package and exits with a named error; wheels carry precise tags so `pip` reports "no matching distribution" rather than installing a broken entry point
- [ ] **R5-21** A native Windows install fails at resolution with a comprehensible message in both wrapper channels
