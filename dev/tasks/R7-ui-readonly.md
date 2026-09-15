# R7 — Read-only web UI

**Deliverable:** nodes, models, staging, usage, audit browser.
**Proves:** zero mutation, zero risk.
· [00 §8](../specs/00-overview.md#8-milestones)

R7 and R8 are polish. Stopping after [R6](R6-backends.md) is a complete outcome,
and nothing in R1–R6 depends on a frontend existing.

**The stack, decided when R7 started.** Hand-written HTML, CSS and JavaScript
embedded with `//go:embed`, served behind the session cookie, talking to
`/api/v1` with `fetch`. No build step, no npm, no framework — so the release
pipeline is unchanged, there is no dependency tree to answer for in a product
that ships a signed offline bundle and an advisory feed, and it works
air-gapped by construction. [`setup.go`](../../internal/api/setup.go) had
already fixed the rule it follows: no stylesheet, no script, no external
anything, because a reference to a CDN is a request that fails on exactly the
host this product is for. It also satisfies [R8-01](R8-ui-mutating.md)
literally — the browser drives the same `?dry_run=true` endpoints an API client
does, so the console is a third caller of the seam rather than a second
implementation of it.

Values are rendered into DOM nodes and never by assembling HTML strings: the
things on these screens are node names, model ids, justifications and refusal
reasons that people typed, and `textContent` cannot be talked into being
markup. It is the decision `setup.go` made by choosing `html/template` over
`text/template`.

- [x] **R7-01** Static asset serving from the binary, behind session authentication · [07 §1](../specs/07-identity-audit.md#1-users-and-roles)
  - *done:* embedded with `//go:embed`, served at `/ui/` with the root an exact-match redirect — a catch-all would also swallow a mistyped `/api/v1` path and answer a program with a page
  - **the assets are behind the session too, not just the data.** They carry no fleet state, so gating them buys exactly one thing: an unauthenticated scanner reaching a control plane inside a CUI boundary learns nothing, not even that this is nodary or which version. Cheap now and awkward later
  - the login page is the one thing a request with no session may have, and it posts to `/api/v1/auth/login` like any other client, so there is no second way to start a session. It carries **no TOTP box**: that endpoint takes a username and a password and nothing else, and [07 §2](../specs/07-identity-audit.md#2-attestation) makes a code a property of an *act* rather than of a session. A field there would have been a control that does nothing, which is the kind that gets written into an SSP by mistake
  - `Content-Security-Policy: default-src 'none'` and the rest, absolute rather than an allowlist somebody widens, because the console loads nothing remote. A test greps every asset for `http://`, `https://` and a CDN host — the rule is enforced rather than remembered
- [x] **R7-02** Fleet view: nodes with state, offer, constraints, `reboot_policy`, last seen, and refusals surfaced against the node · [12 §1](../specs/12-node-guardrails.md#1-where-they-apply)
  - *done:* `manual-console` and `host-managed` reboot policies are displayed prominently, and a WSL2 node shows whether a logon task exists to bring it back · [03 §7](../specs/03-agent.md#reboot-safety)
  - *done:* the listing carries state, GPUs offered against GPUs present, ready-against-placed, reboot policy, agent version and last seen. A node whose cards are present and whose offer is empty **refused** them, which reads nothing like a node that has none, so the listing shows both numbers
  - *done:* the logon task, which needed building first — see [R5-04](R5-install.md). `host-managed` now reads `starts at logon`, `no logon task` or `logon task unknown`, and the node's own page says what an absent one costs: a Windows reboot leaves the node stale until somebody opens a shell, which looks identical to any other unreachable node and is fixed in thirty seconds by whoever knows that is what happened
- [x] **R7-03** Deployments and their health, with GPU topology from `nvidia-smi topo -m` shown so an operator can see which index sets are sensible · [03 §7](../specs/03-agent.md#7-gpu-assignment-health-restart-reboot)
  - *done:* deployments with state, health, GPUs, egress verdict and routes; a failed one links to its captured log ([R2-29](R2-control-plane.md))
  - **the topology was collected as `{}` and never filled in.** `Topology` was a field on the enrollment payload and a column on `node` since R2, and [`agent.go`](../../internal/agent/agent.go) set it to an empty object — so the screen 03 §7 asks for had nothing to draw. `nvidia-smi topo -m` is now parsed into a matrix and served through `fleet.Node`
  - *found by its own test:* the parser counted any column whose heading began `GPU`, and the header row ends **`GPU NUMA ID`** — so a three-card host read as four cards, every row then failed its length check, and the whole matrix was silently discarded. A parser reading a human-facing table has to be told what a column *is*, not what it starts with
- [x] **R7-04** Catalog and staging progress — bytes completed against total, resumable state, `corrupt` visible and terminal · [05 §3](../specs/05-catalog.md#3-staging)
  - *done:* the catalog with each model's backend, source and size, and where it is staged — bytes done against total while staging, and `corrupt` shown as the terminal fault it is rather than as another kind of progress
- [x] **R7-05** Usage views over `usage` and `usage_daily`, by user, model and node · [06 §3](../specs/06-gateway.md#3-metering)
  - *done:* over `GET /usage`, grouped by model, user, node or route. The screen says on its face that these are counts and that there is nowhere for content to be: [ADR 0006](../adr/0006-cui-boundary-and-fips.md)'s claim is easiest to believe where the requests are being reported
- [x] **R7-06** Audit browser with filters matching `audit list`, and the chain's verification status shown rather than assumed · [07 §3](../specs/07-identity-audit.md#3-the-audit-chain)
  - *done:* the same `actor` and `action` filters `audit list` takes, and the chain's verification status **shown rather than assumed** — a browser that displayed records without saying whether they still hash together would be presenting an audit trail as trustworthy on no evidence, which is the one thing this screen must not do
- [x] **R7-07** The active policy profile displayed on every relevant screen · [07 §4](../specs/07-identity-audit.md#4-policy-profiles)
  - *done:* in the shell's header, so it is on every screen rather than on a settings page somebody visits once. 07 §4 makes the profile what decides what an act costs, and an operator who has to go and look is one who assumed
- [x] **R7-08** Non-compliant deployments and `out_of_policy` states shown as first-class status, not buried · [03 §5](../specs/03-agent.md#5-egress-isolation)
  - *done:* its own screen rather than a column somebody scrolls to — deployments that are not isolated, refusals, failed deployments and nodes awaiting approval. `inconclusive` is rendered as what it is and not as "fine": a deployment that could not be shown to be isolated is not one that was
  - `refused` and `out_of_policy` are shown apart with a line saying why they differ. They read alike and mean opposite things about whether anything is still serving, so a reader who ignores the distinction gets the alarming answer for the calm case and the calm one for the alarm
