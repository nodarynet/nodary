# Where the implementation stands

**Derived from [`dev/tasks/`](tasks/), which is derived from [`dev/specs/`](specs/).**
The specifications are authoritative; a number here that disagrees with a tracker
is a bug in this page, and two tests in [`scripts/`](../scripts/) fail when one does.

## The route that is proved

**The MVP route is complete and verified as root on real hardware**, not only in
tests: a control plane and a GPU node install end to end, a node enrolls and is
approved, weights are staged and verified, a model is deployed onto an isolated
network with no route off the box, and served through the gateway — metered, with one
usage row recording counts and no prompt text anywhere in the database. `nodary
doctor` diagnoses a host in one pass, including a live re-run of the egress
assertion. The route is [dev/plans/mvp.md](dev/plans/mvp.md).

## What is not built

Every policy setting and node guardrail this build displays is enforced. What
remains below is not built at all rather than half-built, which is the distinction
worth publishing: a half-built control is the one that gets written into a System
Security Plan by mistake.

| Not built | Lands in |
| :--- | :--- |
| OIDC. [07 §1](specs/07-identity-audit.md) makes local accounts the initial mechanism deliberately rather than by omission | — |
| A second data plane behind one contract, with Bifrost the default for a fresh install. [ADR 0009](adr/0009-bifrost-as-the-default-data-plane.md) is proposed, and is accepted only when its spike passes | [R3b](plans/R3b-a-second-data-plane.md) |

## Built, and not yet proved on hardware

Separated from the list above on purpose. These are written, tested and shipped —
and nobody has watched them work on the machine they were written for, which is a
different claim from either "done" or "not built".

| Built | Never run on |
| :--- | :--- |
| The AMD and Intel GPU path — vendor-aware preflight and enumeration, `server-vulkan` pinned beside `server-cuda`, and a `/dev/dri` render node handed to the container instead of a CDI device | a non-NVIDIA card. The development fleet is WSL2, where `/sys/class/drm` holds no cards at all. [R6a](plans/R6a-a-second-gpu-vendor.md) |
| SGLang serving. The argv nodary's own planner renders was run against the pinned digest on an RTX 5090 — ready in ~50s, both of the descriptor's probes 200, `--served-model-name` honored, a completion returned | a full install. It was a container started by hand from nodary's rendered arguments, not one started by the agent through systemd and nerdctl. **Until 2026-09-15 this backend could not start at all**, on any host: its image declares no command and nodary rendered flags with no program |
| A node upgrading itself from the control plane's mirror against a signature it verifies | a real fleet. The fetch, verify, place, flip and restart sequence is exercised by [`hack/test-selfupgrade.sh`](../hack/test-selfupgrade.sh) against a throwaway key, not by a node in the field |

## Three claims worth stating precisely

**FIPS.** Every channel ships a binary built against Go's validated FIPS 140-3
cryptographic module. **nodary itself is not a validated product and will not
become one** — the validation belongs to the module, and a page that blurs the two
is exactly the kind of statement this project exists to avoid making.
[ADR 0006](adr/0006-cui-boundary-and-fips.md)

**Remote administration.** Every administrative verb — fleet, models and staging,
routing, limits, accounts, records, configuration, policy, `backend build` and
`backup create` — acts on a control plane over the network as the person holding
the credential.
What still needs root on a host is what is *about* that host: `server install`,
`node install`, `doctor`, `gateway`, and `backup restore`. That is a boundary
rather than a gap, and a verb that has not been converted refuses `--server`
rather than quietly acting locally.

**Request content.** nodary records that a request happened and never what it said: the
metering schema has no field to write a body into, and a canary driven through the gateway
is searched for in every byte of the database, its write-ahead log and the gateway's log.
The one place a container's own bytes are kept is a failed deployment's last hundred journal
lines, which [11 §2](specs/11-failure-modes.md) asks for and an operator needs — bounded to
2048 bytes, overwritten by that deployment's next failure, and **deliberately not carried
into the audit chain**, which is append-only and leaves the boundary in the evidence bundle.
The chain records that a log was captured and how large it was, not what was in it.
What that does not claim: a deployment's `env` could still tell a backend to log prompts,
and a server that dies mid-request may print it in a traceback. Neither is closed by a flag,
and all four pinned backends print no prompt text at their defaults.
[ADR 0006](adr/0006-cui-boundary-and-fips.md)

## Milestones

| | | |
| :--- | :--- | :--- |
| **R0** Release pipeline | 26 of 26 | one signed binary through four channels, tamper rejection tested |
| **R1** Core, audit, identity | 38 of 38 | the hash chain, attestation, policy profiles, roles, TOTP |
| **R2** Control plane | 44 of 44 | schema, revisions, HTTP API, shared core, TLS/PKI, fleet reads (`node list`/`show`), `model register`, a derived image built over HTTP, and a failed deployment's captured log served by its own id |
| **R3** Gateway | 16 of 25 | the OpenAI surface, service keys, route allowlist, metering attributed to the deployment, node and GPU that served each request, throttling and quota, routes that carry only ready members and a `503` when none is, LiteLLM kept in sync automatically |
| **R4** Agent | 45 of 45 | enrollment, pinning, mTLS, desired state, heartbeat, node guardrails enforced without killing what is already serving, local and remote staging with restage/unstage, reconcile, health-gated ready, egress isolation, the GPU vendor detected into the offer, and a failed container's own output kept where an operator reads it and out of the chain that leaves the boundary |
| **R5** Install | 33 of 33 | both installs end to end, `nodary install` (the interactive route), layout and ownership, the setup link, `--with-node`, preflight, `doctor`, `upgrade` for the control-plane host, the offline bundle an air-gapped site installs from, an unsupported platform refused by name in every channel, a separately signed component manifest a site can take a fix from without waiting for a release, a shipped binary built against Go's validated FIPS 140-3 module, and nodes that upgrade themselves from the control plane's mirror against a signature they verify without trusting it |
| **R6** Backends | 25 of 25 | descriptor schema, argument translation, container environment (incl. WSL2), capability and layout validation at enable time; vLLM, SGLang and llama.cpp, an operator's own descriptor registered into the configuration snapshot and carried to the nodes that use it, the `api` dialect governing what may join a route, the stage → prepare → serve lifecycle for backends that compile an engine before they can answer, and derived images — a base image corrected for this site, built on the control plane behind an egress allowlist, recorded with the digest it produced, required to be reproducible under a regulated profile, and served to the nodes that run it; an image resolved for the platform and GPU vendor of the node it is placed on rather than of the control plane it was typed at, a device argument rendered for that vendor — CDI and `--gpus` on NVIDIA, a `/dev/dri` render node the kernel named on everything else — and the silicon a backend runs on declared by the backend, so a placement onto anything else is refused by name in the preview rather than discovered as a container that starts and exits, and `model register` defaulting to what the node's cards can actually run rather than to one backend's name |
| **R7** Read-only console | 8 of 8 | served out of the binary behind the session cookie and reaching nothing outside it — the fleet, a node's deployments and how its cards are connected, the catalog and what is staged where, usage, an audit browser that shows whether the chain still verifies rather than assuming it, and a screen for what needs attention: deployments that are not isolated, refusals, failures and nodes awaiting approval |
| **R8** Mutating console | 6 of 6 | one attestation driver every mutation goes through, driving the same `?dry_run=true` endpoints an API client drives — preview, the control plane's own rendering of the change, the profile's justification, a code re-entered for the act rather than inherited from the session, and parity across nodes, models, routes, people, credentials, limits and policy. Destructive acts name their cost first, a stale preview loops back to a fresh one, and another administrator's change is a conflict rather than a silent overwrite |
| **R9** Evidence | 21 of 21 | the signed bundle, verifiable with `sha256sum` and `minisign` alone; the advisory feed's format and `advisory check`, the offline route a site with no network receives revisions by, the decision clock that makes an undecided advisory a POA&M item, and the decision itself as an audited act; and the crosswalk — what this install produces, mapped to the NIST SP 800-171 Rev. 2 requirements it is evidence for, transcribed from NIST's own requirements list, with a System Security Plan paragraph per requirement filled with this install's values and a published list of the families it is *not* evidence for |

## Checks

```sh
make check           # gofmt, vet, tests
make packages        # cross-compile, then build wheels and npm packages
make test-install    # install.sh end to end, including tamper rejection
make test-packages   # the built wheels and npm packages install and run
```
