# R6a — A second GPU vendor: llama.cpp on Vulkan

**Slice of:** [R6](../tasks/R6-backends.md), [R4](../tasks/R4-agent.md) ·
**Tasks:** R4-41, R4-42, R6-13, R6-14 · **Status:** all four built; the pin and real AMD hardware remain

llama.cpp is embedded and serves GGUF on CUDA ([R6-02](../tasks/R6-backends.md), `61946b4`).
The project publishes the same server built against Vulkan, which is the practical route to
AMD discrete cards and APUs — and to Intel integrated graphics, which arrives free.

This slice is **not an image swap.** The image is the cheapest part of it. Every layer between
a card and a container resolves through `nvidia-smi` or `nvidia-ctk`, and a node that is not
NVIDIA cannot get past preflight, enumerates nothing, and would be handed no device.

## What was measured before designing anything

On the development host — WSL2, one RTX 5090 — and against the registry:

| | |
| :--- | :--- |
| `ghcr.io/ggml-org/llama.cpp` variants | `server`, `server-cuda`, `server-vulkan`, `server-intel`, `server-musa` |
| a published `server-rocm` | **none** |
| `server-b4738` (CPU) platforms | linux/amd64 **and** linux/arm64 |
| `server-vulkan-b4740` | single-arch, `sha256:5e23ba55…` |
| `/sys/class/drm` here | holds `version` and **no cards** |
| `/dev/dri`, `/dev/kfd` here | **absent** |
| `/dev/dxg`, `/dev/nvidiactl` here | present |
| `nvidia-smi` here | reports the card correctly |

The fourth, fifth and sixth rows are the finding, and they invert the obvious design.

## 1. Enumeration cannot be made vendor-neutral

The tempting move is to replace `nvidia-smi` with something that works everywhere. `/sys/class/drm`
is the candidate: no tools, no driver libraries, every vendor that binds a DRM driver.

**It finds nothing on WSL2.** There are no card nodes there at all — the only device is
`/dev/dxg` — and WSL2 is a platform [01 §8](../specs/01-install.md#8-platform-support) supports
and that this project develops on. A sysfs enumerator would report an empty offer on the one
machine the fleet has been proved against, which is [R4-01a](../tasks/R4-agent.md)'s bug
exactly, reintroduced by a refactor that looked like a generalisation.

So enumeration stays **per vendor, selected by what answers**:

| Vendor | Asks | Because |
| :--- | :--- | :--- |
| NVIDIA | `nvidia-smi --query-gpu=…` | the driver knows, and it is the only thing that knows on WSL2 |
| AMD | `/sys/class/drm/card*/device/` — `vendor` `0x1002`, plus `mem_info_vram_total` | `rocm-smi` ships with ROCm, and a Vulkan node need not have ROCm installed at all |
| Intel | the same sysfs walk, `vendor` `0x8086` | arrives free with the AMD path; nothing extra is written for it |

A host where more than one answers is a host with more than one vendor's cards. That is a real
machine and not a hypothetical, and §4 is what it forces.

## 2. Device passthrough follows the image, not the backend

`[backend.gpu] mechanism` is already in the descriptor schema with two values, `device-flag`
and `cuda-visible-devices` — **and nothing reads it.** It is a dead field, like `image_default`
beside it.

Giving it a job would be wrong. The mechanism is not a property of llama.cpp:

| | Reaches the card by |
| :--- | :--- |
| `server-cuda` on NVIDIA | `--gpus device=0`, resolved through the CDI spec `nvidia-ctk` writes |
| `server-vulkan` on AMD | `--device /dev/dri/renderD128`, plus the container being in the `render` group |

Same backend, same descriptor, different flag — decided by which image was pinned, which
follows the vendor of the card. So the mechanism belongs beside the **vendor**, not beside the
backend, and `gpu.mechanism` should be *removed* from the descriptor rather than wired up. A
field that has never been read is the cheapest possible thing to delete, and leaving it while
adding the real one would leave two places to look.

## 3. The manifest needs a vendor axis, and a platform key is not one

`components.json` keys artifacts by platform — `linux/amd64`, `linux/arm64`. A Vulkan build and
a CUDA build are both `linux/amd64`; they differ by what silicon they drive, which the platform
key cannot express.

**Rejected — a compound platform key, `linux/amd64+vulkan`.** It needs no schema change, which
is its whole appeal. It also smuggles a second dimension into a string that `resolvePlatform`,
`ForPlatform` and `ArtifactName` all split on `/`, and the first of those to be read by
somebody who has forgotten is the bug.

**Chosen — a `vendors` map on the artifact**, absent everywhere today:

```json
"platforms": {
  "linux/amd64": {
    "image": "ghcr.io/ggml-org/llama.cpp@sha256:634aca75…",
    "vendors": { "amd": { "image": "ghcr.io/ggml-org/llama.cpp@sha256:5e23ba55…" } }
  }
}
```
A component with no `vendors` map is NVIDIA-or-nothing, which is every component today and
stays true without editing one of them. `imageFor` gains a vendor argument; `pinnedImage` in
`model register` passes the node's.

**That last clause is the cost.** `model register` currently resolves the image from the
*control plane's* platform (`buildinfo.Platform()`), because until now every node's was the
same. With two vendors it has to resolve against the **node it is placing on**, whose vendor is
in the offer — so this is not a manifest change alone, it reaches into the register path.

## 4. Vendor belongs in the offer, which is what approval agreed to

`agent.GPU` is `{index, name, memory_mib, uuid}`. Nothing says which silicon.

It has to, and the place is the offer rather than a probe at deployment time.
[02 §1](../specs/02-enrollment.md) makes the offer *what the node put on the table*, written
once at enrollment, and [`nodeapprove.go`](../../internal/cli/nodeapprove.go) renders it into
the preview an administrator approves and the chain records. A fleet where a deployment is
placed on a card whose vendor nobody agreed to is one where the approval described something
else.

Two consequences worth stating rather than discovering:

- **`offer_json` is not in a revision's hash preimage.** `config.Snapshot`'s `readNodes` selects
  `name, state, constraints_json, reboot_policy` and not the offer, so adding a field does not
  invalidate a chain ([mvp §2](mvp.md#2-the-rule-that-decides-what-gets-built) does not apply).
  It *does* change the shape of future approval records, which is ordinary.
- **A node cannot restate its offer.** [02 §3](../specs/02-enrollment.md#3-certificate-lifecycle)
  gates that behind certificate expiry on purpose, and [R4-01a](../tasks/R4-agent.md) already
  records the consequence: a node that enrolled blind stays blind in `offer_json` until it
  re-enrolls. So every node enrolled before this slice reports no vendor, and the absent value
  has to mean `nvidia` — not "unknown", which would strand the existing fleet.

## 5. Preflight is five checks, not one

| Check | Today | Needs |
| :--- | :--- | :--- |
| `checkDriver` | `nvidia-smi`, **LevelFail** for a node | per-vendor, and a host with no NVIDIA is not a failed check |
| `checkGPUs` | `nvidia-smi --query-gpu=index,name` | the same enumerator §1 chooses |
| `checkRAMPerGPU` | `nvidia-smi` | VRAM per card from the vendor's own source |
| `checkFreeVRAM` | `nvidia-smi` | the same |
| `checkContainerToolkit` | `nvidia-ctk` or `nvidia-container-cli`, **LevelFail** | not required at all for `--device` passthrough; AMD needs device nodes and a group |

The last row is the one that changes the shape of the install rather than the wording of a
check. The toolkit exists because CDI is how a GPU reaches a container *on NVIDIA*. Vulkan on
AMD needs no toolkit and no CDI — it needs `/dev/dri/renderD*` to exist and the container to be
allowed to open it. **That is less machinery, not more**, and it is worth noticing that the
harder vendor is the one already built.

`GroupGPU` is declared in `internal/components` and **no component is in it**: nodary does not
ship the toolkit, and 01 §8 explains why (upstream publishes `.deb`s and `.rpm`s, not a flat
archive, and it is coupled to a driver WSL2 forbids touching). The AMD path adds nothing there
either, which keeps that decision intact.

## 6. The shape

```
enrollment          vendor detected once, written into the offer, shown at approval
       │
       ├── nvidia → nvidia-smi        → --gpus device=N       (CDI, toolkit required)
       └── amd    → /sys/class/drm    → --device /dev/dri/…   (no toolkit)
                                         │
model register ──── resolves the image for *that node's* vendor from components.json
                                         │
Build ───────────── renders the flag the vendor names, not the one the backend does
```

Four seams, in dependency order: **detect → offer → image → flag.** Each is useless without the
one before it, which is why this is one slice and not four.

## 7. Steps

- [x] **R4-41** `agent.GPU` carries a vendor; `LocalInventory` detects it, `nvidia-smi` first and
      sysfs second, and an absent value reads as `nvidia` so an enrolled fleet keeps working
- [x] **R4-42** Preflight's five GPU checks ask the vendor that answered, and a host with no
      NVIDIA toolkit is a failure only where CDI is the mechanism
- [x] **R6-13** `components.json` artifacts carry an optional `vendors` map; `imageFor` takes a
      vendor; `model register` resolves against the node's rather than the control plane's
- [x] **R6-14** `gpuFlag` renders per vendor; `[backend.gpu] mechanism` is **deleted** from the
      descriptor schema, being a field nothing has ever read
- [ ] Pin `server-vulkan` beside `server-cuda` for `llama-cpp`, and only then
- [ ] Verify on real AMD hardware: enroll, approve, register a GGUF, serve a token, and run
      `nodary node verify-egress` — the isolation assertion has never run on a non-NVIDIA node

## 8. What this slice deliberately does not do

**ROCm.** `ggml-org` publishes no `server-rocm`, and building one is a different project's
release engineering. Vulkan covers AMD discrete *and* APUs, which is the hardware this was
asked for; ROCm's advantage is throughput on datacentre parts, which is not this product's
first customer.

**vLLM or SGLang on AMD.** Both have ROCm builds and neither has a Vulkan one. They stay
NVIDIA-only, and the README should say which backends run on which silicon rather than leaving
a reader to assume the matrix is full.

**CPU-only nodes.** `server` with no device at all is the simplest node imaginable and is
*almost* free once §5 lands — but "a node offering zero GPUs" runs through placement, the
`max_deployments` default (`len(offered)`) and the guardrail evaluation, and none of that has
been traced. It is a slice of its own, not a corollary.

## 9. Open questions

- **Mixed-vendor hosts.** §1's enumerators can both answer. Indices then collide — NVIDIA's `0`
  and AMD's `0` are different cards — and `deployment_gpu`'s primary key is
  `(deployment_id, gpu_index)`. Either the index namespaces by vendor, or a mixed host is
  refused at enrollment and says so. The second is smaller and probably right for a first
  version; it needs deciding before R4-41 rather than after.
- **`render` group membership.** `--device /dev/dri/renderD128` passes the node in; whether the
  container's user can *open* it depends on group ownership, which varies by distribution. This
  is the AMD equivalent of the CDI trap [R4-23a](../tasks/R4-agent.md) found, and it will not
  show up until it is run on real hardware.
- **What `gpu_layers` should default to.** On CUDA the operator sets it. On an APU sharing
  system memory the safe default is different, and a wrong one is an out-of-memory at first
  token rather than at start.
