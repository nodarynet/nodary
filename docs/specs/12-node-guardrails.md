# 12 — Node guardrails

The control plane directs the fleet. A node still holds a small set of local limits on what may
be done to it, kept in a file on the machine itself.

These are not a consent boundary — you own both ends. They are safety rails against your own
mistakes, and against a control plane that is misconfigured, out of date, or being operated by
someone who has forgotten what else that machine does. A homelab box is rarely *only* a nodary
node: it drives a display, it hosts something else at 3pm on a Tuesday, and one of its GPUs is
not on offer.

## 1. Where they apply

The agent evaluates the desired-state document ([03](03-agent.md#2-desired-state-document))
against `/etc/nodary/node.toml` before reconciling. Anything outside the limits is refused and
reported; everything else proceeds normally.

```
control plane                          node
─────────────                          ────
desired state  ──────────────────────► check against node.toml
                                       ├─ within limits  → reconcile, report
                                       └─ outside limits → refuse, report reason
```

A refusal is surfaced against the node in the interface and written to the audit chain. The
control plane does not retry automatically, because a limit that is being hit repeatedly is
something an operator should see rather than something the system should grind against.

## 2. The file

`/etc/nodary/node.toml`, written at install and editable by root on the node. The control plane
reads its contents as reported inventory and does not write it.

```toml
[limits]
gpu_indices        = [1, 2, 3]        # of 4 present — GPU 0 drives the display
max_vram_fraction  = 0.90
max_deployments    = 2

[allow]
backends           = ["vllm", "sglang"]   # omit for any
prepare_jobs       = false                # engine compilation is long, hot and disruptive
package_install    = false                # no host package changes after enrollment
reboot             = false
agent_auto_upgrade = true

[window]
maintenance        = "sat 02:00-06:00 UTC"   # confine disruptive actions
```

| Setting | Refuses |
| :--- | :--- |
| `gpu_indices` | Any deployment binding a GPU not listed |
| `max_vram_fraction` | A `gpu_memory_fraction` above the ceiling |
| `max_deployments` | Placement beyond the stated count |
| `allow.backends` | An unlisted backend, including newly registered ones |
| `allow.prepare_jobs` | A backend `prepare` step ([04](04-backends.md#4-the-prepare-phase)) |
| `allow.package_install` | Post-enrollment host package changes |
| `allow.reboot` | Any reboot, independent of `reboot_policy` |
| `window.maintenance` | Stop, restart or restage outside the window |

Every field is optional. A file with no `[limits]` section offers the whole machine, which is
the right default for a dedicated GPU host and is what `nodary node install` writes unless
told otherwise:

```sh
nodary node install --server … --token … \
    --gpus 1,2,3 --max-deployments 2 --maintenance "sat 02:00-06:00 UTC"
```

## 3. Editing a live node

Changes take effect on the agent's next reconcile. A change that invalidates a **running**
deployment does not kill it: the agent reports `out_of_policy` and waits for the control plane
to withdraw it, or for the next maintenance window.

Silently terminating a serving model because a config file changed would make the file
dangerous to edit, and a guardrail nobody dares touch is not a guardrail.

## 4. Reported inventory

A node reports what it is offering, not everything it has. A host with four GPUs offering three
appears in the control plane as a three-GPU node, and the control plane will not place work on
the fourth.

```json
{"node": "gpu-01",
 "offer": {"gpus": [{"index": 1, "model": "RTX 4090", "vram_gb": 24}, …],
           "max_deployments": 2, "backends": ["vllm", "sglang"]},
 "constraints": {"prepare_jobs": false, "reboot": false,
                 "maintenance": "sat 02:00-06:00 UTC"}}
```

The limits are recorded in the node's approval record ([02](02-enrollment.md#1-flow)), so what
a machine was offering at the time it joined is part of its history rather than only its
current state.

## 5. Decommissioning

```sh
nodary node leave [--drain] [--purge-models]
```

Run on the node. Drains its deployments from their routes if the control plane is reachable,
stops units, removes credentials, and stops the agent. The control plane marks it `departed`,
keeps its audit history, and removes it from every route. Rejoining is a fresh enrollment.

This exists because taking a machine back should not require the control plane to be healthy —
the common case is precisely that something has gone wrong. `nodary node revoke` remains the
server-side counterpart for ejecting a node from the other direction
([02](02-enrollment.md#3-certificate-lifecycle)).
