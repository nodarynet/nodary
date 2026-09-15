# R8 — Mutating web UI

**Deliverable:** mutating UI with attestation.
**Proves:** parity with the CLI.
· [00 §8](../specs/00-overview.md#8-milestones)

R8 adds no new capability. Every mutation it offers already exists as a core
function with an audit record, a preview and an `intent_hash`; R8 is a third
caller of the same seam ([R2-34](R2-control-plane.md)). If a task here needs a
new core function, that is a signal the seam was drawn wrong, not that the UI
needs an exception.

- [x] **R8-01** The preview → `intent_hash` → apply flow in the browser, using the same `?dry_run=true` endpoints an API client uses · [09 §2](../specs/09-api.md#2-conventions)
  - *done:* a stale preview is refused with `412` and the operator re-reads the current diff and re-attests, exactly as on the CLI · [11 §3](../specs/11-failure-modes.md#3-security-controls)
  - *done:* one driver in [`app.js`](../../internal/api/ui/app.js) that every mutation goes through, driving the same `?dry_run=true` endpoints an API client drives. A screen says *what* it wants done; none of them decides what ceremony costs
  - what is shown for approval is **the control plane's own rendering** of the change, never this page's reading of the request. What an operator approves has to be what the machine about to act described
  - *found while testing it:* **the gates are on the apply and not on the preview**, which is right — a dry run changes nothing, so demanding a reason to look would be ceremony for its own sake. It does mean an operator can write a justification the profile will refuse, preview happily, and be refused at the end, so the driver loops back to the same dialog carrying the refusal rather than reporting a failure
- [x] **R8-02** Justification capture, with `min_justification_length` enforced by the active profile · [07 §2](../specs/07-identity-audit.md#2-attestation)
  - *done:* and **the console carries no minimum of its own.** `min_justification_length` lives in the profile, the control plane refuses, and this renders the refusal — a copy of the number here would be a second place that can disagree with the profile in force
- [x] **R8-03** TOTP re-entry when `require_totp` is set
  - *done:* a live session does not satisfy it. A cookie proves someone logged in at some point; a re-entered code proves a person was present for this specific act
  - *done:* `reauthentication_required` prompts for a code and re-sends the act with it, on the intent hash that was already approved
  - **it did not work, and finding out is most of what this row was worth.** `identity.Principal.Local()` was `p.Token.ID == ""`, and a session cookie carries no token — so every act a browser made read as *local root*, `require_totp` was silently not enforced in the console, and [`internal/core`](../../internal/core/core.go) wrote `totp_exempt: "local"` into the chain about a request that arrived over the network. A false statement in the record an assessor reads is worse than the missing prompt
  - the expression was answering two questions at once, and until the console existed no principal had one answer and not the other: `Local()` is now the actor method, and `HasToken()` is "is there a credential whose use should be recorded". Both directions are injected — restoring the old expression fails a unit test in `internal/identity` and the ceremony test in `internal/api` together
- [x] **R8-04** Verb parity with the CLI across nodes, models, deployments, routes, users, tokens, limits and policy · [10 §1](../specs/10-cli.md#1-verbs)
  - *done:* nodes (approve, drain, revoke), models (enable, disable, restart, restage, unstage), routes (membership, replace-written), users (add, suspend, delete), tokens (revoke), limits (set) and policy (move profile, roll a revision back)
  - deployments have no verb of their own and that is not an omission: they are created and removed through the configuration, which is one applier rather than a second set of writers — the same answer [R2-28](R2-control-plane.md) gave
- [x] **R8-05** Destructive operations name their cost before asking · [05 §4](../specs/05-catalog.md#4-enable-and-disable)
  - *done:* `unstage` states the restaging cost; a rolling restart with fewer than two ready replicas requires the same explicit `--allow-downtime` decision the CLI requires · [03 §7](../specs/03-agent.md#7-gpu-assignment-health-restart-reboot)
  - *done:* every destructive act names its cost in the dialog before the preview. `unstage` says how many bytes come back down; revoking a node says what keeps running with nobody watching; removing a route's last member says the route then answers 503; suspending a person says their unattended tokens stop; loosening the profile says what stops being required
  - deleting a person says what it does **not** do: the chain keeps every act they took, because 07 §3 makes the record append-only and an operator deleting an account to erase a mistake should know that before they try
  - **the `--allow-downtime` half did not work over HTTP at all, and this row is how it was found.** `fleet.ErrWouldDropTheModel` was in neither front end's error table, so the one refusal that names the flag resolving it reached a caller as a **500 with the message withheld** — an operator over `--server`, and the console, had no way to learn there was a way out. The third unrecognized error to do that here; the first two are recorded against [R2-28](R2-control-plane.md)
  - it is a `409 would_drop_the_model` and exit 4 now, and the console offers the gap rather than hiding it: the refusal is shown, the cost is stated in an operator's terms — the only replica serving stops, and for a large model that is minutes — and accepting it is a second, different request rather than a flag this page could set on its own
- [x] **R8-06** `If-Match` surfaced as a real conflict, not a silent overwrite, when two administrators act at once · [09 §2](../specs/09-api.md#2-conventions)
  - *done:* the screens that read an object and write it whole — routes and limits — send the revision they read at, and a `revision_changed` is shown as what it is: another administrator acted, nothing was applied, reload and look at what they did. Distinct from the `412`, which loops back to a fresh preview, because a client acts on them differently
