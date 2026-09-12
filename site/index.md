---
title: nodary
---

# nodary

**Run LLMs on your own GPUs, and be able to show how.**

A *notary* verifies identity, attests to acts, and keeps an official register of what was
done. nodary does that for a small fleet of GPU hosts: nothing joins without approval,
nothing changes without an attributable, justified, hash-chained record, and a deployment
reaches the network only where somebody said it could.

It is built for **a small site that handles CUI and has to answer for it** — a supplier
with a handful of GPU boxes, subject to CMMC Level 2 and NIST SP 800-171, whose obligation
is to write a System Security Plan and keep it true.

That obligation is yours and cannot be bought from a vendor. nodary does not assess, does
not certify, does not make anyone compliant, and makes no zero-trust claim. What it does is
narrower: it enforces particular mechanisms, and it records what happened, so the person
writing your SSP is describing something they can **show** rather than something they
believe.

Running a homelab instead? Same binary, same install, nothing gated — you're the community
edition rather than the target audience.

[Get started :material-arrow-right:](getting-started.md){ .md-button .md-button--primary }
[Administering a fleet](administering.md){ .md-button }
[View on GitHub](https://github.com/nodarynet/nodary){ .md-button }

## What it does

- **Enrolls nodes** with short-lived join tokens, issues mTLS certificates, and holds them
  in `pending` until an administrator approves. A leaked token alone cannot place a machine
  into the serving fleet.
- **Runs model servers** as systemd units against containerd, through declarative backend
  descriptors — vLLM and SGLang today; adding another is a TOML file, not a code change.
- **Stages weights** with verified transfers, including a fully offline path for air-gapped
  sites.
- **Issues and revokes tokens**, and meters every request against the person who made it.
  Per-user rate and budget limits are configured, exported and diffed today; the gateway
  does not yet read them.
- **Records every administrative action** in a hash-chained, tamper-evident audit log, with
  a required justification and a hash binding the approved preview to what was applied.
- **Carries policy as one reviewable object** — mandatory re-authentication, justification
  floors, credential lifetimes and deny-by-default egress are in force; origin allow/deny
  lists and retention windows are not, and `nodary policy show` marks every setting nothing
  acts on yet.
- **Keeps prompts and completions out of its own records.** The metering schema is closed:
  no free-text body field exists to write into, and a test fails the build if request
  content ever reaches storage.

## Editions

One binary. Everything that *runs* the fleet is Apache 2.0; the commercial edition sells
what turns records into a deliverable a human assessor reads.

| | Apache 2.0 | Commercial |
| :--- | :---: | :---: |
| Control plane, agent, gateway, backends | ✔ | |
| The hash chain, `audit verify`, `audit export` | ✔ | |
| Enrollment, staging, egress isolation | ✔ | |
| Both policy profiles | ✔ | |
| `nodary evidence export` — the signed bundle | | ✔ |
| The control index and SSP narratives | | ✔ |
| The signed advisory feed | mechanism | content |

We do not sell security — we sell the paperwork.

## Learn more

| | |
| :--- | :--- |
| [Specifications](https://github.com/nodarynet/nodary/tree/main/docs/specs) | What every component is required to do |
| [Decision records](https://github.com/nodarynet/nodary/tree/main/docs/adr) | Why it's built this way, and what was rejected |
| [Implementation tracker](https://github.com/nodarynet/nodary/tree/main/docs/tasks) | What's done, what's next |

The [README](https://github.com/nodarynet/nodary#status) carries the full list of what is
recorded but not yet enforced, and what is not built at all. It is on the front page rather
than in a roadmap on purpose: a capability described as enforced, which is really an object
the system stores and displays, hands the person writing an SSP language for a control that
is not in force.
