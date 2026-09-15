# R6b — Which backend runs on which silicon, and who gets offered what

**Slice of:** [R6](../tasks/R6-backends.md), [R4](../tasks/R4-agent.md) ·
**Follows:** [R6a](R6a-a-second-gpu-vendor.md) · **Status:** measured, not yet designed

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
| vLLM on ROCm is published by | **`rocm/vllm`** — AMD's namespace, not the vLLM project's |
| `rocm/vllm` variants | `..._rdna_...` **and** `..._cdna_...`, plus `gfx120X-all`, `gfx1152` |
| `lmsysorg/sglang` ROCm tags | `v0.5.19-rocm{10,700,720,724}-mi{30,35}x` — **Instinct only** |
| `rocm/sgl-dev` | same shape: `mi35x`, `mi45x` |
| ROCm image sizes | **10–33 GB**, against roughly 5–9 GB for the CUDA images |
| `ggml-org/llama.cpp` variants | `server`, `server-cuda`, `server-vulkan`, `server-intel`, `server-musa`; still no `server-rocm` |

Three of those rows change the matrix that was asked for.

## 1. The matrix, corrected by what is published

Asked for, and why each row moved:

| Silicon | Offer | Recommend | |
| :--- | :--- | :--- | :--- |
| NVIDIA / CUDA | sglang, vllm, llama-cpp | **sglang** | as asked |
| AMD with ROCm, **CDNA** (Instinct) | vllm, sglang, llama-cpp | **sglang** | as asked |
| AMD with ROCm, **RDNA** (Radeon) | vllm, llama-cpp | **vllm** | **corrected.** SGLang publishes no RDNA build — `mi30x`/`mi35x`/`mi45x` are Instinct parts. On the Radeon workstation an SMB is likelier to own, "sglang recommended" names an image that does not exist |
| AMD, Vulkan only | llama-cpp | llama-cpp | as asked. This is also every AMD host where ROCm is not installed |
| Intel integrated | llama-cpp | llama-cpp | **arrives at pri 1 already** — R6a's argument for Vulkan was that Intel iGPU comes with it |
| Intel Arc / Max discrete | vllm | vllm | pri 2, and narrower than written: pri 1 already covers Intel iGPU. `server-intel` is a shorter path to the same silicon than vLLM's XPU build |
| TensorRT-LLM | — | — | **absent from the matrix as asked for.** It is pinned, has a descriptor, and is the only backend exercising `prepare`. Dropping it is a decision this plan does not take; see §5 |

## 2. `amd` is not enough to choose an artifact

[`manifest.go`](../../internal/components/manifest.go)'s vendor axis assumes the string
`internal/preflight` detects is the string that selects an image, and today that vocabulary is
`nvidia`, `amd`, `intel`. The measurements say it is not sufficient on two counts:

- **ROCm or not.** The same AMD card runs sglang (ROCm image) or llama-cpp (Vulkan image)
  depending on whether ROCm is installed on the host. `gpuvendor.go` declines to ask on
  purpose — "rocm-smi is not asked either: it ships with ROCm, and a node serving Vulkan need
  not have ROCm installed at all" — and this slice is the reason that has to change.
- **RDNA or CDNA.** `rocm/vllm` ships them as different images. One `amd` key cannot name both.

There is an existing ruling to respect: an `Artifact`'s own `Vendors` map "is refused by
Validate: nothing reads one", so the answer is not nesting. The vocabulary itself is the thing
to widen, and it lives in `internal/preflight` where the machine is detected — which keeps
`ForVendor`'s "a missing override is a refusal rather than a fall back" exactly as it is, and
that refusal is what stops a CUDA image being pinned onto a Radeon.

## 3. A descriptor should declare its own silicon

[04 §1](../specs/04-backends.md#1-why-descriptors-rather-than-plugins) chose descriptors over
plugins so that what varies between backends is data a backend declares. Which silicon a
backend runs on is exactly that, and putting it anywhere else — a table in the CLI, a map in
the manifest — means an operator's own registered descriptor cannot participate in the matrix.

## 4. A new publisher enters the trust surface

The ROCm artifacts come from `rocm/*`, which is AMD, not from the projects that publish the
CUDA ones. [ADR 0004](../adr/0004-release-artifacts-and-channels.md) pins by digest and
[ADR 0007](../adr/0007-independent-component-manifest.md) makes the manifest independently
verifiable, so the mechanism copes — but "who publishes what nodary runs" grew by one
organization, and for a product sold on provenance that is a decision to write down rather
than a manifest entry to add quietly.

The sizes matter too: 10–33 GB against 5–9 GB. [R5-05](../tasks/R5-install.md) leaves images
out of the offline bundle, and a 33 GB pull is a different install experience from a 6 GB one.

## 5. Open questions

- **TensorRT-LLM.** In or out? It is built, pinned, the only user of `prepare`, and carries a
  live hardware claim in [status.md](../status.md). If the matrix is the supported set, an
  absent backend is a deprecation, and `prepare` loses its only exercise.
- **How fine does the silicon key go?** `amd-rocm-rdna` and `amd-rocm-cdna` cover `rocm/vllm`;
  `mi30x`/`mi35x`/`mi45x` is finer still, and `gfx1152` finer again. The key has to be as
  specific as the *worst* backend needs, or the vocabulary is per backend rather than per host —
  which would be a different design.
- **Detecting RDNA from CDNA.** Vendor comes from a PCI id; the architecture does not.
  `/sys/class/drm/card*/device/device` gives a device id, and mapping those to families is a
  table that ages.
- **Nothing here has run on an AMD or Intel card.** As with R6a, the design is measured against
  registries and sysfs documentation, and the development fleet is a single NVIDIA host under
  WSL2 where `/sys/class/drm` holds no cards at all.
