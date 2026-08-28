# 05 — Catalog & weights

## 1. The catalog

A curated, administrator-managed set of models. Registering an entry is a privileged, audited
action; *enabling* one is then an ordinary operation.

```sh
nodary model register \
    --id google/gemma-4-31b-it \
    --backend vllm \
    --source remote|local \
    --artifact hf-cache \
    --origin-org google --origin-country US \
    --license gemma \
    --manifest ./gemma-4-31b-it.sha256
```

| Field | Purpose |
| :--- | :--- |
| `id` | Canonical model identifier |
| `artifact` | `hf-cache`, `single-file`, `engine-dir` — must match the backend's `weights_layout` |
| `source` | `remote` (agent downloads) or `local` (operator stages out of band) |
| `origin_org`, `origin_country` | Provenance, checked against policy |
| `license` | Recorded for audit; not interpreted |
| `manifest_sha256` | Per-file digests, used to verify staging |
| `hints` | Recommended tensor parallelism, minimum VRAM |

## 2. Provenance as a control

`origin_org` and `origin_country` are validated against the active policy profile's
`model_origin_allowlist` and `model_origin_denylist` ([07](07-identity-audit.md#4-policy-profiles)).

A model whose origin is denied is **rejected at registration**, and the rejection is written to
the audit chain with the actor and the attempted origin. This converts a provenance rule from
tribal knowledge into a control with evidence — which is the difference between a policy an
assessor can verify and one they must take on faith.

Deployments referencing a model whose origin later becomes denied are flagged, not silently
stopped; disabling them is an explicit, audited operator decision.

## 3. Staging

Weights live under `models_dir`, in the layout the artifact kind requires. For `hf-cache` this
is the HuggingFace layout — `hub/models--<org>--<name>/` — so an existing cache is adopted
without restaging.

- **`source: remote`** — the agent downloads into a temporary directory, verifies against the manifest, then atomically renames into place. Resumable across agent restarts; progress reported as bytes completed against total.
- **`source: local`** — an operator places the weights out of band (removable media, `rsync`); the agent verifies the manifest and marks them staged. This is the air-gapped path, and it is a first-class one, not a workaround.

```
absent → staging → verifying → staged
                            ↘ corrupt
```

`corrupt` is terminal and requires an explicit `nodary model restage`. Nothing auto-repairs a
failed verification, because a silent re-download is how a corrupt artifact becomes a
permanent mystery.

The control plane will not start a deployment whose weights are not `staged`.

Staging does not disappear as a cost — a large model is still hours and hundreds of gigabytes.
It becomes a **visible, resumable, reportable task** rather than something an operator watches
over SSH and hopes about.

## 4. Enable and disable

```sh
nodary model enable  google/gemma-4-31b-it \
    --node gpu-01 --gpus 0,1 --backend vllm --tp 2 [--replicas 2]
nodary model disable google/gemma-4-31b-it [--node gpu-01]
```

`enable` validates model × backend × GPU compatibility ([04](04-backends.md#7-validation)),
creates deployments, triggers staging if needed, runs `prepare` if the backend requires it,
starts units when ready, and adds them to their route once healthy.

`disable` drains from the route, stops units, and **leaves weights in place**. Removing weights
is `nodary model unstage`, deliberately a separate verb — the two operations have very
different costs to undo.

## 5. Routes

A route is a public model name mapping to a set of deployments.

```sh
nodary route set chat --add dep_7f3a --add dep_9c21
nodary route list
```

Deployments are added automatically when a model is enabled with a `--route`, and removed on
disable, on health failure, and during rolling restart. Manual `route set` is for asymmetric
cases: canarying a second backend, or draining one replica without disabling it.
