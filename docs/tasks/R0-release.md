# R0 — Release pipeline

**Proves:** the distribution path works end to end — cross-compilation, signing,
verification, wheel tags and npm platform guards — while the stakes are zero.

R0 is not a milestone in [00 §8](../specs/00-overview.md#8-milestones). It is the
ground the milestones are built on, and it overlaps [R5](R5-install.md): the
artifacts, channels and manifest are R5's subject matter, brought forward so the
pipeline exists before there is anything worth shipping through it. Anything R0
leaves unfinished is listed here rather than duplicated into R5.

Scope: a real binary through every channel, implementing `nodary version` and
`nodary components list|verify`. Every other verb reports that it is not yet
implemented — recognised, not rejected.

## Delivered

Verified by reading the tree, **not** by execution: this machine has Go 1.22 and
`go.mod` requires 1.27, so `make check` could not be run here. Treat these as
"present and tested in CI" rather than "observed green locally".

- [x] **R0-01** Go module, `cmd/nodary` entry point, `internal/` layout · [ADR 0002](../adr/0002-go-with-package-manager-wrappers.md)
- [x] **R0-02** `buildinfo` carries version, commit and date, injected by `-ldflags`
- [x] **R0-03** `nodary version` in text and JSON · [10 §4](../specs/10-cli.md#4-output-discipline)
- [x] **R0-04** Component manifest: schema, `go:embed`, validation rejecting unpinned images, bad digests and duplicate names · [01 §1](../specs/01-install.md#1-artifacts)
- [x] **R0-05** `nodary components list`, per-platform, text and JSON
- [x] **R0-06** `nodary components verify` — every URL resolves, every digest matches; offline mode needs no network
- [x] **R0-07** Planned verbs are distinguishable from typos: `planned` registry returns "not implemented in this release", unknown verbs return usage error · [10 §1](../specs/10-cli.md#1-verbs)
- [x] **R0-08** Exit-code constants match the contract · [10 §5](../specs/10-cli.md#5-exit-codes)
- [x] **R0-09** `Makefile`: `build`, `check`, `dist`, `wheels`, `npm`, `packages`, `manifest`, `test-install`, `test-packages`
- [x] **R0-10** `install.sh` implements the four-step contract and has no `--skip` flag · [01 §2](../specs/01-install.md#2-the-installsh-contract)
- [x] **R0-11** `hack/test-install.sh` exercises the verification path for real, including tamper rejection
- [x] **R0-12** PyPI wheel builder with precise platform tags · [01 §7](../specs/01-install.md#7-package-manager-channels)
- [x] **R0-13** npm packages declaring `os`/`cpu`, entry package with `optionalDependencies`, shim that names the missing platform package
- [x] **R0-14** `hack/test-packages.sh` verifies built wheels and npm packages install and run
- [x] **R0-15** `.goreleaser.yaml`: `CGO_ENABLED=0`, bare-binary archives, split `.sha256`, openssl and minisign signers
- [x] **R0-16** CI workflow: `make check`, `components verify`, `test-install`, `packages` + `test-packages`
- [x] **R0-17** Release workflow with PyPI Trusted Publishing and npm provenance; platform packages published before the entry package
- [x] **R0-18** `hack/update-manifest.py` regenerates the manifest and `--check` fails a stale one in CI

## Outstanding

These block a first real release. Each is a gap between what a document promises
and what the tree does.

- [ ] **R0-19** Replace the `REPLACE_AT_RELEASE_TIME` placeholder in `install.sh` with the real ECDSA P-256 public key · [01 §2](../specs/01-install.md#2-the-installsh-contract)
  - *done:* `install.sh` verifies a genuine release artifact; `hack/test-install.sh` still passes against its throwaway key
- [ ] **R0-20** Supply `NODARY_MINISIGN_KEY` to the release workflow
  - *done:* the `minisign` signer in `.goreleaser.yaml` resolves its key; today `release.yml` stages only `NODARY_SIGNING_KEY`, so the minisign signing step has no key to read
- [ ] **R0-21** Wire the Homebrew channel · [ADR 0004](../adr/0004-release-artifacts-and-channels.md)
  - *done:* `brew install nodary/tap/nodary` places the same binary. `.goreleaser.yaml` has no `brews:` block, so the channel named in the README, [01 §7](../specs/01-install.md#7-package-manager-channels) and ADR 0004 does not exist yet
- [ ] **R0-22** Host `nodary.net/install.sh` and `nodary.net/releases/<version>/<asset>`
  - *done:* the `curl … | sh` path in the README works unmodified against a published release
- [ ] **R0-23** Publish the release key fingerprints in the README
  - *done:* the minisign and openssl fingerprints replace "to be published with the first release", so they can be checked against a source other than the one serving the download
- [ ] **R0-24** Reconcile `NODARY_VERSION` defaults across `install.sh`, `Makefile` and `components.json`
  - *done:* one version source; cutting a release does not require editing three files that can disagree
