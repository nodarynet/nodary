# R6 — Backends

**Deliverable:** backend descriptors beyond vLLM — SGLang, llama.cpp, TensorRT-LLM.
**Proves:** pluggability is real, not theoretical.
· [00 §8](../specs/00-overview.md#8-milestones)

Deliverable level. Break these into tasks when R6 starts.

Stopping after R6 is a complete outcome. R1–R5 deliver the whole stated goal with
no frontend; R6 is what makes "adding a backend is a TOML file, not a code change"
true rather than claimed.

Backends are data, not code: a descriptor is inert and schema-validated, where a
plugin directory of arbitrary Python would reopen the hole the release signature
closes. · [04 §1](../specs/04-backends.md#1-why-descriptors-rather-than-plugins)

- [x] **R6-01** Descriptor schema: parse, validate, reject unknown keys · [04 §6](../specs/04-backends.md#6-descriptor-schema)
  - `[backend.prepare]` and `[backend.derive]` are **refused**, not ignored: an operator who writes one and sees it accepted believes a build step will run. They become features in R6-06 and R6-08 without an intervening lie
  - taken early because the agent cannot render an argv without it · [R4b §1](../plans/R4b-backends-and-the-plan.md)
- [ ] **R6-02** Embed the built-in descriptors — vLLM, SGLang, llama.cpp, TensorRT-LLM; `/etc/nodary/backends/` holds only operator-added ones · [01 §12](../specs/01-install.md#12-filesystem-layout)
  - *partial:* **vLLM, SGLang and llama.cpp** are embedded. TensorRT-LLM needs `[backend.prepare]` (R6-06), and a descriptor embedded whose features are unimplemented would be a backend the binary claims to support and cannot run
  - two and not one, deliberately: a single descriptor cannot demonstrate the translation is data-driven, because one vocabulary is indistinguishable from a hard-coded one
  - **llama.cpp is the third, and the one that shows the format carries more than a vocabulary.** vLLM and SGLang differ only in spelling; this one differs in shape — a single GGUF rather than a HuggingFace cache, an option with no canonical equivalent, and `cpu_offload = true`, a server that runs where there is no VRAM
  - **`[backend.extra]` is a second table, not more rows in `args`.** A name in `args` is one nodary *translates* — `max_context` reaches vLLM as `--max-model-len` and SGLang as `--context-length`, and a document means the same thing against either. A name in `extra` is one it merely *passes*, so moving a deployment to another backend is expected to refuse rather than quietly mean something else. It is still named, unlike `extra_args`: `gpu_layers: 33` is spelled by the descriptor, so a typo is refused instead of reaching the container. A name in both tables is refused — whichever lookup ran first would otherwise become the answer
  - **the `single-file` layout produced no usable model path, and nothing would have found it but running the layout through.** `unitFor` special-cased `hf-cache` and otherwise used `mount_path` bare, so llama.cpp would have been told `-m /models` — a directory — and failed at start with a message about the file format, a long way from the cause. Only the manifest knows the weights' name, so `SingleFileName` reads it: exactly one entry, or an error saying what it found
  - it runs **even under `--no-verify`**, because that flag exists to skip re-reading hundreds of gigabytes of weights and the manifest is a few lines of text. Otherwise `agent plan` could never render a llama.cpp argv at all
  - a **sharded GGUF is refused, not guessed at**. llama.cpp takes the first shard, and inventing that convention here would serve the wrong weights in silence on the day the naming differs. The refusal names the manifest
  - a weights file whose name holds whitespace is refused for the reason `extra_args` already is: the name lands in `NODARY_ARGS`, which the unit expands unquoted so systemd splits it
  - **`model register` hardcoded `hf-cache` in two places** — the directory it digests and the artifact kind it stamps — so `--backend llama-cpp` looked for a HuggingFace cache a GGUF is not in, and then wrote a kind `config.Apply` refuses. Both now come from the descriptor, which [`internal/config/apply.go`](../../internal/config/apply.go) already called the authority: *"each descriptor declares one `weights_layout`"*. The "no weights at" message names what to place for the layout, because telling somebody with a GGUF to place `config.json and the tensor files` sends them looking for files their model does not have
  - *unverified on hardware:* nothing here has served a token. The argv, the layout, the manifest resolution and the registration path are covered by tests; a real GGUF on a real GPU is not
- [x] **R6-04b** A descriptor declares environment, including **host-conditional** environment
  - `[backend.env]` applies everywhere, `[backend.env_wsl2]` only on a WSL2 node. "vLLM will not start on WSL2 without `VLLM_WSL2_ENABLE_PIN_MEMORY`" is a fact about **vLLM**, not about nodary or about one operator's deployment, so it belongs in the descriptor — which is [04 §1](../specs/04-backends.md#1-why-descriptors-rather-than-plugins)'s argument for descriptors rather than plugins
  - detection, not a toggle: a fleet with both WSL2 and native nodes works without anybody remembering which is which, and a native host is never handed a variable that means nothing there
  - **the deployment wins** over both. Without that, the fallback for a host the descriptor's default does not fix would be unreachable — and that is exactly when an operator is setting one
  - one condition, not a condition engine. A second condition can generalise it; inventing the general form for a single case would be a mechanism nobody has exercised
- [x] **R6-04a** A deployment carries container **environment**, not only arguments
  - a backend is configured by both and only the first was expressible. The case that proved it: on WSL2 — a platform [01 §8](../specs/01-install.md#8-platform-support) supports — vLLM refuses to start with `RuntimeError: UVA is not available`, and both published fixes (`VLLM_WSL2_ENABLE_PIN_MEMORY=1`, `VLLM_USE_V2_MODEL_RUNNER=0`) are environment variables with no command-line form. **No deployment could be made to run at all**
  - it lands **now** rather than later because `config.Deployment` is a revision's hash preimage, and [mvp §2](../plans/mvp.md#2-the-rule-that-decides-what-gets-built) makes adding a field to that preimage the one change that invalidates every chain a customer already holds
  - rendered sorted, and whitespace is **refused rather than escaped** — the unit expands it unquoted so systemd splits it, exactly as `extra_args` does and for the same reason
- [x] **R6-03** Canonical parameter translation through `[backend.args]`, with `extra_args` appended verbatim and explicitly uninterpreted · [04 §3](../specs/04-backends.md#3-normalize-the-few-pass-through-the-rest)
  - a parameter the descriptor does not name is **dropped and the deployment refused**, never guessed. Inventing `--max-context=` for a backend that spells it differently produces a container that fails at start for a reason nobody can trace back to the translation
  - the argv order is fixed. It goes into a unit's environment file, and a set that reordered between reconciles would rewrite the file and restart a serving model for no reason
  - JSON numbers render as integers where they are integers: `--tensor-parallel-size=2.000000` is a container that will not start
- [ ] **R6-04** Capability validation at enable time, not crash time · [04 §7](../specs/04-backends.md#7-validation)
  - *done:* every row of the validation table is rejected with its named message — including `tensor_parallel` on llama.cpp pointing at `--tensor-split`, an unsupported `dtype` listing what is supported, and parallelism exceeding assigned GPUs
- [ ] **R6-05** `weights_layout` checked against the model's artifact kind before anything is staged or started · [04 §7](../specs/04-backends.md#7-validation)
- [ ] **R6-06** The `prepare` phase: stage → prepare → serve · [04 §4](../specs/04-backends.md#4-the-prepare-phase)
  - *done:* TensorRT-LLM compiles its engine before serving; `gpu_arch_specific` artifacts are not treated as portable; a failed or timed-out prepare marks the deployment `failed` with the build log tail, leaves weights staged, and does not cache the artifact
- [ ] **R6-07** `nodary backend list|show|register|remove`, gated by `allow_custom_backends`, registration recording the descriptor's SHA-256, removal refused while a deployment references it · [04 §9](../specs/04-backends.md#9-registering-a-backend)
- [ ] **R6-08** Derived images: `inherits`, a digest-pinned `from`, ordered `steps` that are not a shell, `index_url`, `timeout_s` · [04 §5](../specs/04-backends.md#5-derived-images)
  - *done:* a derive changes an image and inherits argument vocabulary, weight layout and probe from its parent, so the blast radius is an image and nothing else
- [ ] **R6-09** Builds run on the control plane, never on a node, with a narrow egress allowlist reaching the package index and nothing else · [04 §5](../specs/04-backends.md#builds-run-on-the-control-plane)
  - *done:* a build that reaches outside its index fails rather than silently succeeding with an unexpected dependency
- [ ] **R6-10** `nodary backend build|rebuild` writing one audit record with the recipe SHA-256, base digest, **resulting image digest**, builder and justification · [04 §5](../specs/04-backends.md#building)
  - *done:* rebuilding is explicit; a base-image bump marks the derive `stale` and changes nothing that is serving. A failed build produces no image and replaces none, and deployments on the previous digest keep serving
- [ ] **R6-11** `require_pinned_derives` under a regulated profile: `index_url` set and every install step naming an exact version · [04 §5](../specs/04-backends.md#policy)
- [ ] **R6-12** `api` dialect governs routing: `openai` proxies unchanged, `triton` is refused on an OpenAI route without an adapter, `custom` is reachable only through a configured one · [04 §8](../specs/04-backends.md#8-routing-implications)
  - *done:* mixing backends behind one route is supported — a vLLM and an SGLang deployment of the same model round-robin together
- [ ] **R6-13** `components.json` artifacts carry an optional `vendors` map, and `model register` resolves an image against the **node's** vendor · [R6a §3](../plans/R6a-a-second-gpu-vendor.md)
  - *rejected:* a compound platform key, `linux/amd64+vulkan`. It needs no schema change, and it smuggles a second dimension into a string `resolvePlatform`, `ForPlatform` and `ArtifactName` all split on `/`
  - a component with no `vendors` map is NVIDIA-or-nothing, which is every component today and stays true without editing one of them
  - the cost is in `model register`, which resolves against `buildinfo.Platform()` — the *control plane's* — because until now every node's was the same
- [ ] **R6-14** `gpuFlag` renders the flag the node's vendor names, and `[backend.gpu] mechanism` is deleted · [R6a §2](../plans/R6a-a-second-gpu-vendor.md)
  - the mechanism is not a property of the backend. `server-cuda` reaches a card by `--gpus device=0` through CDI and `server-vulkan` by `--device /dev/dri/renderD128`: same descriptor, different flag, decided by the vendor
  - `mechanism` has **never been read** by anything, like `image_default` beside it. A field with no readers is the cheapest thing in the tree to delete, and wiring it up would put the answer in the wrong place permanently
