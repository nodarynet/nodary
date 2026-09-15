# R6b — Which backend runs on which silicon, and who gets offered what

**Slice of:** [R6](../tasks/R6-backends.md), [R4](../tasks/R4-agent.md) ·
**Follows:** [R6a](R6a-a-second-gpu-vendor.md) · **Status:** scoped — NVIDIA is served
natively, everything else is llama.cpp on Vulkan

[R6a §8](R6a-a-second-gpu-vendor.md#8-what-this-slice-deliberately-does-not-do) ends by saying
"the README should say which backends run on which silicon rather than leaving a reader to
assume the matrix is full." This slice is that sentence, built: a node's silicon is detected,
the backends that can run on it are what the operator is offered, and one of them is
recommended.

## What was measured before designing anything

Against the registries on 2026-09-15, because the last slice's most useful finding was also a
registry fact (`ggml-org` publishes no `server-rocm`, and that inverted the design).

| | |
| :--- | :--- |
| `vllm/vllm-openai` tags containing `rocm` | **none.** The upstream image is CUDA-only — `cu129`, `cu13.0.1` |
| `vllm/vllm-openai` tags containing `xpu` or `intel` | **none**, for the same reason |
| vLLM on ROCm is published by | **`rocm/vllm`** — AMD's namespace, not the vLLM project's |
| vLLM on Intel is published by | **`intel/vllm`** — a third namespace again |
| `rocm/vllm` variants | `..._rdna_...` **and** `..._cdna_...`, plus `gfx120X-all`, `gfx1152` |
| `lmsysorg/sglang` ROCm tags | `v0.5.19-rocm{10,700,720,724}-mi{30,35}x` — **Instinct only**, no RDNA build |
| `rocm/sgl-dev` | same shape: `mi35x`, `mi45x` |
| ROCm image sizes | **10–33 GB**, against roughly 5–9 GB for the CUDA images |
| `ggml-org/llama.cpp` variants | `server`, `server-cuda`, `server-vulkan`, `server-intel`, `server-musa`; still no `server-rocm` |

## 1. Decided: no ROCm, no XPU. AMD and Intel are Vulkan

**Decided.** Native vendor backends are offered on NVIDIA only. AMD and Intel are served by
llama.cpp on Vulkan, which [R6a](R6a-a-second-gpu-vendor.md) already built.

**Why.** The measurements above describe a support burden out of proportion to the hardware it
reaches:

- **Fragmentation.** There is no "sglang on AMD" image — there is `mi30x`, `mi35x`, `mi45x`,
  each against four ROCm versions. There is no "vLLM on AMD" image either — there is `rdna`,
  `cdna`, `gfx120X-all`, `gfx1152`. Every one of those is a pin to choose, verify and move.
- **Size.** 10–33 GB against 5–9 GB, on a product whose offline bundle does not carry images at
  all ([R5-05](../tasks/R5-install.md)).
- **A third and fourth publisher.** The CUDA images come from the projects that write the
  software. The ROCm and XPU images come from `rocm/*` and `intel/*`. For a product sold on
  provenance, each additional organization in the supply chain is a claim to stand behind.
- **It does not reach the buyer anyway.** SGLang publishes no RDNA build at all, so on the
  Radeon workstation a small site is likeliest to own, the "recommended" backend has no image.
  ROCm's advantage is throughput on datacentre Instinct parts — which is
  [R6a §8](R6a-a-second-gpu-vendor.md#8-what-this-slice-deliberately-does-not-do)'s sentence
  exactly: "not this product's first customer."

**This re-converges on R6a.** That slice chose Vulkan over ROCm for the same reasons and said
so; the measurements here are what a second look at the question cost, and they came back with
the same answer and more evidence for it.

**Rejected — ROCm behind a flag, or as an operator-registered descriptor.** The second is
already possible and costs this plan nothing: [04 §9](../specs/04-backends.md#9-registering-a-backend)
lets a site register its own descriptor, so an Instinct owner can run SGLang on ROCm without
nodary pinning a single one of those images. That is the right home for it — the site that has
the hardware carries the pin.

## 2. What that removes

The previous draft of this plan argued that `amd` was not enough to choose an artifact, and
that [`manifest.go`](../../internal/components/manifest.go)'s vendor vocabulary had to widen.
**That gap closes with §1.** It existed for two reasons and both were ROCm's:

- *ROCm or not* — a question only worth asking if a ROCm image could be chosen. It cannot.
- *RDNA or CDNA* — a split that exists only inside `rocm/vllm`.

So `nvidia`, `amd`, `intel` — what `internal/preflight` already detects and what
`Artifact.ForVendor` already keys on — is sufficient. No new probe, no wider vocabulary, no
change to the manifest schema, and `ForVendor`'s "a missing override is a refusal rather than a
fall back" keeps doing the job it was written for.

## 3. The matrix

| Silicon | Offer | Recommend |
| :--- | :--- | :--- |
| NVIDIA | sglang, vllm, llama-cpp | **sglang** |
| AMD — discrete, APU | llama-cpp (Vulkan) | llama-cpp |
| Intel — integrated, Arc | llama-cpp (Vulkan) | llama-cpp |
| anything else with a DRM render node | llama-cpp (Vulkan) | llama-cpp |

`server-intel` is measured as existing and is **not** adopted here: Vulkan already reaches that
silicon, and a second Intel-specific pin is the fragmentation this plan just declined.

## 4. What is left to build

R6a built the hard half — vendor-aware preflight and enumeration, `server-vulkan` pinned beside
`server-cuda`, a `/dev/dri` render node handed to the container instead of a CDI device. What
remains is the offer:

- **A descriptor declares its own silicon.**
  [04 §1](../specs/04-backends.md#1-why-descriptors-rather-than-plugins) chose descriptors over
  plugins so that what varies between backends is data a backend declares. Which silicon a
  backend runs on is exactly that — and putting it in a table in the CLI instead would mean an
  operator's own descriptor could not participate in the matrix, which is the case §1's
  "rejected" paragraph depends on.
- **`model register` offers what the node can run**, refuses what it cannot with the vendor
  named, and recommends one. Today `--backend` defaults to `vllm` for every node including a
  Radeon one, where it cannot work.
- **The install wizard's model step** offers the same set for the node being installed.
- **The matrix is published** — `README.md` and `docs/administering.md`. This is
  [R6a §8](R6a-a-second-gpu-vendor.md#8-what-this-slice-deliberately-does-not-do)'s actual
  request, and it is the part a buyer reads before they buy the wrong card.

## 5. Open questions

- ~~**TensorRT-LLM.** In or out?~~ **Decided: out.** Lowest priority against the matrix, and
  revisitable on customer demand. The descriptor, the pin and the manifest entry are gone; the
  three that ship are vLLM, SGLang and llama.cpp.
  - **It was not "the only user of `prepare`" — it was not a user at all.** Its descriptor
    declared no `[backend.prepare]` and said so as a deliberate correction: the phase was
    written for 0.x, which served an engine directory, and 1.x compiles in-process through
    `trtllm-serve`. So nothing was orphaned. `prepare` stays, is still exercised by
    `internal/agent/prepare_test.go`'s own synthetic descriptor, and
    [04 §4](../specs/04-backends.md#4-the-prepare-phase) now describes it generically instead
    of naming a backend the tree no longer carries.
  - No Go code named it outside comments, which is what made the removal a deletion rather
    than a refactor.
- **Nothing here has run on an AMD or Intel card.** As with R6a, the design is measured against
  registries and sysfs documentation, and the development fleet is a single NVIDIA host under
  WSL2 where `/sys/class/drm` holds no cards at all.
