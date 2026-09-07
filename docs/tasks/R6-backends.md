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
  - *partial:* **vLLM and SGLang** are embedded. llama.cpp needs `[backend.extra]` and TensorRT-LLM needs `[backend.prepare]`, and a descriptor embedded whose features are unimplemented would be a backend the binary claims to support and cannot run
  - two and not one, deliberately: a single descriptor cannot demonstrate the translation is data-driven, because one vocabulary is indistinguishable from a hard-coded one
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
