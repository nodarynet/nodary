# 04 — Backends

A **backend** is a model server: vLLM, SGLang, llama.cpp, TensorRT-LLM. nodary treats them as
data, not code. Each is described by a TOML descriptor; adding one is a file, not a patch.

## 1. Why descriptors rather than plugins

An obvious design is a Python `Backend` base class that each server subclasses. It is rejected
for two reasons.

**Supply chain.** The install path is a signed binary, and offline and regulated sites depend
on that holding. Permitting arbitrary Python to be dropped into a plugin directory reopens the
hole the signature was closing. A descriptor is inert data validated against a schema.

**It isn't needed.** Model servers differ in their argument vocabulary, their weight layout,
and whether they need a build step. All three are expressible declaratively. The small number
that need real logic are served by the `prepare` phase (§4) rather than by arbitrary code.

Built-in descriptors are embedded in the binary. Operator-added
descriptors live in `/etc/nodary/backends/`, are audited on registration, and are gated by the
policy flag `allow_custom_backends` — default **false** under a regulated profile.

## 2. What varies between backends

| Dimension | Example of divergence |
| :--- | :--- |
| Image | Every backend ships its own |
| Argument vocabulary | `--tensor-parallel-size` (vLLM) vs `--tp-size` (SGLang) vs `--tensor-split` (llama.cpp) |
| Weight layout | HF cache dir, single GGUF file, or a compiled engine directory |
| Preparation | TensorRT-LLM must compile an engine before it can serve |
| Health endpoint | Path and readiness semantics differ |
| API dialect | OpenAI-native, Triton, or something else |
| Metrics | Endpoint path and metric names |
| Capabilities | Tensor parallelism, expert parallelism, quantization formats, LoRA |

## 3. Normalize the few, pass through the rest

Fully normalizing every backend flag means chasing upstream releases forever. Passing
everything through means no validation, no interface, and no cross-backend model definition.

nodary normalizes the parameters that are genuinely universal and passes the rest verbatim:

| Canonical parameter | Meaning |
| :--- | :--- |
| `tensor_parallel` | Number of GPUs to shard one model instance across |
| `max_context` | Maximum sequence length |
| `gpu_memory_fraction` | Share of VRAM the server may reserve |
| `dtype` | Weight precision or quantization scheme |
| `served_name` | Name the model answers to on the API |
| `port` | Listen port |

Anything else goes in `extra_args`, appended verbatim after the translated canonical set. The
control plane does not interpret `extra_args`, and says so.

## 4. The `prepare` phase

The naive lifecycle is *stage weights → serve*. That is true for vLLM and SGLang and false for
TensorRT-LLM, which must compile a per-GPU-architecture engine before it can serve — hours of
work producing a new artifact that itself has to be cached and verified.

The lifecycle is therefore **stage → prepare → serve**. `prepare` is absent for most backends;
where present it declares its own image, command, output artifact, and whether that artifact is
portable across GPU models.

Omitting this phase is the standard mistake in "just swap the image" plugin designs: the
interface looks sufficient until the first backend that needs a build step, and then it has to
be reworked.

## 5. Derived images

Sometimes the base image itself is wrong for the site. vLLM bundles an OpenCV build that is not
FIPS-validated; on a FIPS host it aborts at import, and no argument fixes it — the correction is
`opencv-python-headless==4.12.0.88` installed *over* the image, before anything starts.

This is not `prepare`. The two are siblings and confusing them bends the model out of shape:

| | `prepare` (§4) | Derived image |
| :--- | :--- | :--- |
| Input | Staged weights | A base image |
| Output | An engine directory | A new image |
| Runs on | The node — it needs that GPU | The control plane |
| How often | Once per deployment | Once per site, per version |
| Why | The backend cannot serve without it | The image is wrong for this host |

FIPS is the example, not the case. The same shape covers a CVE backport ahead of upstream, an
internal CA bundle, a pinned transitive dependency, and a driver shim.

### Builds run on the control plane

Never on a node. Three reasons, in order of weight:

1. **A node has no egress by design** ([03](03-agent.md#5-egress-isolation)). `pip install` needs an index, and opening a path to PyPI from every GPU host to install one package would undo the isolation the rest of the system spends its effort asserting.
2. **One build serves the fleet.** A derived image is not GPU-architecture-specific — that is what `prepare` is for — so building it once and pinning the result is both cheaper and more consistent than building it *n* times and hoping the results match.
3. **A node's contract is to run pinned digests.** Keeping it that way is what makes a node's state auditable from the control plane.

The result is stored in the control plane's mirror and served to nodes like any other image
([ADR 0004](../adr/0004-release-artifacts-and-channels.md)).

### The descriptor

A derive **inherits** a built-in backend and changes only its image. It cannot introduce a new
argument vocabulary, weight layout or probe — those come from the parent, so the blast radius
is an image and nothing else.

```toml
[backend]
name     = "vllm-fips"
inherits = "vllm"          # args, layout, probe and capabilities come from the parent

[backend.derive]
from      = "vllm/vllm-openai@sha256:61fc8a89…"   # digest-pinned, never a tag
steps     = [
  "pip install --no-cache-dir opencv-python-headless==4.12.0.88",
]
index_url = "https://pypi.internal/simple"        # required under a regulated profile
timeout_s = 1800
```

| Field | Meaning |
| :--- | :--- |
| `inherits` | Required. The built-in backend this varies |
| `from` | Base image, digest-pinned. A tag is rejected for the same reason it is in the component manifest |
| `steps` | Commands run in order, each a layer. Not a shell — no pipes, no redirection |
| `index_url` | Package index. Under `require_pinned_derives` it must be set, and every install step must name an exact version |
| `timeout_s` | Build ceiling |

### Building

```sh
nodary backend register --file ./vllm-fips.toml --justify "FIPS: stock opencv aborts at import"
nodary backend build vllm-fips --justify "…"
nodary backend rebuild vllm-fips --justify "…"   # after a base-image bump
```

`build` writes one audit record carrying the recipe's SHA-256, the base digest, **the digest of
the image it produced**, the builder and their justification. That record is what turns "someone
ran pip install on a GPU box" into an artifact with provenance: the inputs are pinned, the
output is pinned, and the person who asked for it is named.

A derived image is built once. **Rebuilding is explicit** — a bump to the base image does not
trigger one, because silently changing what is serving is precisely the thing the audit chain
exists to prevent. `nodary backend list` shows a derive whose base has moved as `stale`.

### The build's own egress

The build container gets a narrow allowlist — the package index and nothing else — on the same
principle as the staging unit ([03](03-agent.md#staging-is-separate)), and the control plane is
the only host that needs it. A build that tries to reach anything else fails rather than
silently succeeding with an unexpected dependency.

### Policy

| Flag | `default` | `regulated` |
| :--- | :--- | :--- |
| `allow_derived_images` | `true` | `true` |
| `require_pinned_derives` | `false` | `true` |

Derives stay available under a regulated profile because the regulated site is the one that
needs them — a FIPS override is the motivating case, not the thing being guarded against. What
`regulated` adds is that sources must be pinned and come from a named index, so the build is
reproducible rather than merely recorded.

This is also why `allow_custom_backends = false` and `allow_derived_images = true` are
consistent: registering an arbitrary backend introduces unreviewed argument handling and a new
weight layout, while a derive changes an image and inherits everything else.

## 6. Descriptor schema

```toml
[backend]
name            = "vllm"
api             = "openai"        # openai | triton | custom
weights_layout  = "hf-cache"      # hf-cache | single-file | engine-dir
mount_path      = "/root/.cache/huggingface"
container_port  = 8000
image_default   = "vllm/vllm-openai:v0.23.0"

[backend.capabilities]
tensor_parallel = true
expert_parallel = true
quantization    = ["awq", "gptq", "fp8"]
lora            = true
cpu_offload     = false

[backend.args]                    # canonical → argv template
model_path          = "--model={v}"
served_name         = "--served-model-name={v}"
tensor_parallel     = "--tensor-parallel-size={v}"
max_context         = "--max-model-len={v}"
gpu_memory_fraction = "--gpu-memory-utilization={v}"
dtype               = "--dtype={v}"
port                = "--port={v}"

[backend.gpu]
mechanism = "device-flag"         # device-flag | cuda-visible-devices

[backend.probe]
health          = "/health"
ready           = "/health"
ready_timeout_s = 1800

[backend.metrics]
path = "/metrics"
```

### Reference descriptors

**SGLang** — same shape, different vocabulary:

```toml
[backend]
name = "sglang"
api  = "openai"
weights_layout = "hf-cache"
mount_path = "/root/.cache/huggingface"
container_port = 30000

[backend.args]
model_path      = "--model-path={v}"
tensor_parallel = "--tp-size={v}"
max_context     = "--context-length={v}"
port            = "--port={v}"

[backend.probe]
health = "/health"
ready  = "/health_generate"
```

**llama.cpp** — different weight layout, no tensor parallelism, CPU offload:

```toml
[backend]
name = "llama-cpp"
api  = "openai"
weights_layout = "single-file"     # GGUF
mount_path = "/models"
container_port = 8080

[backend.capabilities]
tensor_parallel = false            # has --tensor-split, different semantics
cpu_offload     = true             # can serve where VRAM is short or absent
quantization    = ["gguf"]

[backend.args]
model_path  = "-m {v}"
max_context = "-c {v}"
port        = "--port {v}"

[backend.extra]
gpu_layers = "-ngl {v}"            # backend-specific, surfaced as a named option
```

**TensorRT-LLM** — needs `prepare`:

```toml
[backend]
name = "tensorrt-llm"
api  = "openai"                    # via trtllm-serve; "triton" if fronted by Triton
weights_layout = "engine-dir"

[backend.prepare]
required          = true
image             = "nvcr.io/nvidia/tensorrt-llm:<pinned>"
command           = "trtllm-build --checkpoint_dir {src} --output_dir {out} --tp_size {tp}"
artifact          = "engine-dir"
gpu_arch_specific = true           # engine is not portable across GPU models
timeout_s         = 21600
```

## 7. Validation

Capabilities are enforced at enable time, not discovered at crash time.

| Requested | Backend says | Result |
| :--- | :--- | :--- |
| `tensor_parallel: 4` | `tensor_parallel = false` | Rejected: *"llama-cpp does not support tensor parallelism; use `--tensor-split` via extra_args"* |
| `dtype: awq` | not in `quantization` | Rejected with the supported list |
| GGUF model | `weights_layout = "hf-cache"` | Rejected: model artifact and backend layout disagree |
| 2 GPUs, `tensor_parallel: 4` | — | Rejected: parallelism exceeds assigned GPUs |

The model catalog records each entry's artifact kind ([05](05-catalog.md)), so
model × backend compatibility is checked before anything is staged or started.

## 8. Routing implications

`api` tells the control plane whether it can route to the deployment directly.

- `openai` — vLLM, SGLang, llama.cpp. LiteLLM proxies unchanged.
- `triton` — requires an OpenAI-compatible frontend, or a LiteLLM adapter configured for it. The control plane refuses to add such a deployment to an OpenAI route without one.
- `custom` — reachable only through an explicitly configured adapter.

Mixing backends behind one route is permitted and is a supported pattern: a route may hold a
vLLM deployment and an SGLang deployment of the same model, and the gateway will round-robin
across both. It is the operator's responsibility to ensure they are configured to produce
comparable output.

## 9. Registering a backend

```sh
nodary backend list
nodary backend show vllm
nodary backend register --file ./my-backend.toml   # requires allow_custom_backends
nodary backend remove my-backend
```

Registration validates the descriptor against the schema, rejects unknown keys, and writes an
audit record containing the descriptor's SHA-256. Removal is refused while any deployment
references it.

A descriptor carrying `[backend.derive]` (§5) is registered the same way, then built with
`nodary backend build`. Registration records the recipe; the build records what the recipe
produced. Removing a derive also removes its built image from the mirror.
