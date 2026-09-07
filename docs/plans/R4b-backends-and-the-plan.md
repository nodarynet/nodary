# R4b — Descriptors, guardrails, staging, and the plan

**Slice of:** [R4](../tasks/R4-agent.md) ·
**Tasks:** R4-13, R4-34, R6-01 – R6-03 · **Status:** in progress

Everything the agent needs to decide *what it would do*, and nothing that does it.
[R4a](R4a-agent-protocol.md) got a desired-state document onto a node. This slice turns that
document into a concrete plan — an argv, an env file's contents, a staging verdict — and
stops there. Starting units, polling health and reconciling are R4c; egress isolation is R4d.

## Why the cut is here and not at "the agent works"

The obvious slice is the whole agent, and it is the wrong one. Every part of it that is
*decidable* — which arguments a backend takes, whether a GPU is on offer, whether weights
verify — is a pure function of inputs this machine already has. Every part that *acts* needs
containerd, systemd units and a GPU bound into a container.

Splitting there means the decisions are tested exhaustively and cheaply, in CI, on a laptop,
with table tests; and R4c is left holding only the part that genuinely needs a machine. It
also produces something usable on its own: `nodary agent plan` renders what the agent would
do, against a real desired document, without touching the host.

The [R4a](R4a-agent-protocol.md) slice boundary said the opposite — that none of its pieces
was provable alone. Both are the same rule applied honestly: cut where the proof is, and here
the proof does not need the machine.

## 1. R6 is not in the MVP route, and three of its tasks are prerequisites here

**Decided.** R6-01, R6-02 and R6-03 land now, restricted to what the agent needs.

**Why.** [mvp §4](mvp.md#4-the-route) routes through R1–R5 and R9 and never reaches R6. But a
deployment cannot start without translating `{"tensor_parallel": 2}` into
`--tensor-parallel-size=2`, and [04 §3](../specs/04-backends.md#3-normalize-the-few-pass-through-the-rest)
puts that mapping in the descriptor rather than in code. The choice is not "descriptors or
not" — it is "descriptors, or the same table hard-coded in the agent and moved into a
descriptor later", and the second is the same work twice with a migration between.

[04 §1](../specs/04-backends.md#1-why-descriptors-rather-than-plugins) already says built-in
descriptors are embedded in the binary. Embedding them is not the R6 milestone; R6 is
*registration* of operator descriptors, capability validation, `prepare`, and derived images.

**What is taken, and what is not:**

| | In this slice | Left to R6 |
| :--- | :--- | :--- |
| R6-01 schema | `[backend]`, `[backend.args]`, `[backend.probe]`, `[backend.gpu]`, `[backend.capabilities]` | `[backend.prepare]`, `[backend.derive]` |
| R6-02 built-ins | vLLM and SGLang | llama.cpp (needs `[backend.extra]`), TensorRT-LLM (needs `prepare`) |
| R6-03 translation | canonical → argv, `extra_args` verbatim | — |
| R6-04 – R6-12 | none | all |

**Two descriptors and not one.** vLLM alone is the MVP path and would do. SGLang costs a TOML
file that [04 §6](../specs/04-backends.md#6-descriptor-schema) already writes out in full, and
it is the only thing that can demonstrate the translation is data-driven rather than a
vocabulary that happens to match one backend. A single descriptor proves nothing about the
mechanism.

**Rejected — hard-code vLLM's arguments in the agent and defer descriptors entirely.** The
smallest diff today by some margin. It makes [04 §1](../specs/04-backends.md#1-why-descriptors-rather-than-plugins)'s
central claim false in the shipped binary while the specification asserts it, and the
replacement lands as a rewrite of the one function every deployment depends on.

## 2. The weights manifest travels with the weights

**Decided.** For `source: local`, the per-file digest list lives beside the weights as
`nodary-manifest.sha256`. The control plane sends only `manifest_sha256` — the digest *of that
file* — and the agent refuses to stage unless the file it found hashes to it.

**Why.** [05 §1](../specs/05-catalog.md#1-the-catalog) makes `manifest_sha256` "per-file
digests, used to verify staging", and `nodary model register --manifest ./gemma.sha256` gives
the control plane a file. It does not say how the agent gets the list, and the agent needs the
list, not its hash.

Sending it beside the weights is right for the case this path exists for.
[05 §3](../specs/05-catalog.md#3-staging) calls `local` the air-gapped path: an operator
carries hundreds of gigabytes on removable media, and the manifest is a few kilobytes that
belongs in the same act of carrying. It also means the verification needs no endpoint, no
control-plane round trip, and no reachability — which is the property an air-gapped path is
for.

And the pinning still holds end to end. A manifest swapped in transit fails against
`manifest_sha256`, which came over mTLS from the control plane and was written by an audited
`model register`. The operator carries bulk; the control plane carries the one digest that
makes the bulk checkable.

**Rejected — serve the manifest from the control plane over the agent protocol.** One less
file to carry, and it works for `source: remote` too. It adds an endpoint whose only caller is
staging, and it makes the air-gapped path depend on the network at exactly the moment the
network is the thing that is absent.

**Rejected — put the digest list inline in the desired-state document.** No new endpoint and
no extra file. A document that is a few hundred bytes today becomes megabytes for a
sharded model, on an endpoint that long-polls every sixty seconds per node.

## 3. Verification reads every byte, and says so

**Decided.** `local` staging hashes every file the manifest names. There is no size-and-mtime
fast path.

**Why.** [11 §2](../specs/11-failure-modes.md#2-models-and-deployments) makes "weights corrupt"
a state with a terminal outcome and an explicit `restage`, and the whole value of that is that
`staged` means verified. Media that has been carried physically is exactly the media that
develops quiet bit errors, and size-and-mtime is blind to all of them.

The cost is real and is named rather than hidden: this is minutes of disk read for a large
model. It runs when a model is first staged and on an explicit `restage`, not on every
reconcile — a `staged` verdict is recorded and trusted until something asks again.

**Rejected — verify on first stage, then trust size and mtime.** Much faster on a reconcile.
It makes `staged` mean "was verified once, and nothing has obviously changed", which is a
weaker claim than the one an assessor is being shown.

## 4. `node.toml` is parsed and reported, and enforces nothing yet

**Decided.** R4-13 only: the file is read, refused if malformed, and its contents become the
node's advertised offer and constraints at enrolment.
[R4-14 – R4-17](../tasks/R4-agent.md) — evaluate-before-side-effect, refusals, `out_of_policy`,
inventory narrowing — stay open.

**Why.** [mvp §6](mvp.md#6-what-an-mvp-install-cannot-claim) already lists "no node guardrail
enforcement" as a gap with those four task numbers, and
[mvp §5.3](mvp.md#53-egress-isolation-is-built-node-guardrails-are-not) gives the reasoning:
guardrails protect an operator from themselves on a machine they own, and their absence is
visible rather than silent.

What is not deferrable is the *reporting* half.
[12 §4](../specs/12-node-guardrails.md#4-reported-inventory) has a four-GPU host offering three
appear as a three-GPU node, and [02 §1](../specs/02-enrollment.md#1-flow) records the offer in
the approval — which [R4a](R4a-agent-protocol.md#4-what-a-human-decided-is-audited-what-a-machine-observed-is-not)
already put inside `intent_hash`. An operator who wrote `gpu_indices = [1, 2, 3]` and was
approved for four GPUs was shown terms they did not set.

**Rejected — enforce now, since the file is already parsed.** The evaluator is not the hard
part; the hard part is R4-16, where a guardrail narrowing under a running deployment must
report `out_of_policy` and not kill it. That needs the reconcile loop to exist to *not* act,
and writing it against a loop that does not exist is writing it twice.

## 5. The shape

| | |
| :--- | :--- |
| `internal/backend` | The descriptor: schema, the embedded built-ins, argv translation |
| `internal/agent/node.go` | `node.toml`, and the offer it produces |
| `internal/agent/staging.go` | Manifest verification and the staging verdict |
| `internal/agent/plan.go` | One desired document → concrete actions |
| `internal/cli/agent.go` | `nodary agent plan` |

## 6. Steps

- [ ] `internal/backend`: parse, validate, reject unknown keys
- [ ] Embed the vLLM and SGLang descriptors
- [ ] Canonical translation, `extra_args` appended verbatim
- [ ] `node.toml` parsed, and the offer it produces at enrolment
- [ ] Local staging verified against its manifest
- [ ] `Plan` — the desired document rendered as actions, side-effect free
- [ ] `nodary agent plan`, so the plan is inspectable without running it

## 7. Open items

- R4c takes the reconcile loop, the unit template, health polling and the daemon.
- R4d takes egress isolation, which [mvp §5.3](mvp.md#53-egress-isolation-is-built-node-guardrails-are-not)
  makes non-optional.
- [mvp §4](mvp.md#4-the-route)'s route does not mention R6 at all. §1 above takes three of its
  tasks; the route should say so.
