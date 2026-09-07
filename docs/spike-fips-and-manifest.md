# Spike — FIPS and the manifest

**Answers:** all four [pivot §10](plans/pivot-cmmc.md#10-the-spike) questions ·
**Measured on:** go1.27.0, linux/amd64, commit `906ee5a`; question 1 on an RTX 5090 /
driver 610.88 / WSL2 / systemd 255 host

Throwaway work, kept as a memo. Everything below was run, not reasoned about; the
commands are given so each result can be reproduced or contradicted.

## What was measured with what

Questions 2–4 ran on a CPU-only container. Question 1 ran later on a GPU host, and **that
host had no containerd**: Docker Desktop's WSL2 integration keeps containerd inside its own
distro, so there is no socket or binary on the node, and `nvidia-ctk` is not on `PATH`
either. What follows therefore measures **docker with the `nvidia` runtime**, not
containerd. Every finding in §5 is about namespaces, cgroups and systemd, which both
runtimes share — but the substitution is real and §6 says where it still bites.

## 1. The FIPS build works, and that was the easy half

```sh
GOFIPS140=v1.0.0 CGO_ENABLED=0 go build ./cmd/nodary
```

Compiles. The binary is `statically linked` with 850 `crypto/internal/fips140` symbols
linked in, and `nodary version` runs. [ADR 0002](adr/0002-go-with-package-manager-wrappers.md)'s
static property survives, as [pivot §3](plans/pivot-cmmc.md#fips-is-a-build-not-a-rearchitecture)
predicted it would.

The full suite passes under `GODEBUG=fips140=on`. **Every package.** If the claim being
sold is "nodary runs the FIPS-validated module", it is already true and costs one CI job.

## 2. `on` and `only` are different products, and the difference is the finding

`GODEBUG=fips140=on` puts the validated module in service. `fips140=only` additionally
refuses every algorithm outside the approved set. Under `only`, three of eight packages
fail:

| | `off` | `on` | `only` |
| :--- | :--- | :--- | :--- |
| HMAC-SHA-1 — TOTP, [`totp.go:128`](../internal/identity/totp.go) | ok | ok | **panic** |
| AES-GCM with a caller-supplied IV — [`secret.go:374`](../internal/secret/secret.go) | ok | ok | **error** |
| SHA-256, HKDF-SHA256, HMAC-SHA-256, Ed25519, ECDSA P-256, PBKDF2-SHA256 | ok | ok | ok |

```sh
GOFIPS140=v1.0.0 GODEBUG=fips140=only go test ./...   # identity, secret, cli fail
```

### HMAC-SHA-1 does not survive, and it fails by panic

> `panic: crypto/hmac: use of hash functions other than SHA-2 or SHA-3 is not allowed in FIPS 140-only mode`

[Pivot §3](plans/pivot-cmmc.md#fips-is-a-build-not-a-rearchitecture) left this "unknown and
[to] be measured, not assumed". Measured: it is refused, and the refusal is a **panic
inside `hmac.New`, not an error return**. It surfaces at `identity.Enroll`, which is
called inside `audit.Act` inside `store.WriteTx` — a crash in the middle of an audited
mutation, in the process that owns the chain. Whether SP 800-131A permits HMAC-SHA-1 in
this construction is now beside the point: Go's module decides, and Go's module says no.

Bare SHA-1 panics too, so there is no variant of the RFC 6238 construction that passes.

**Only one call site exists.** `sha1` appears exactly once in non-test code. The cost of
moving TOTP to HMAC-SHA-256 is small in code and non-trivial in product: it is an
interoperability decision about which authenticator apps still work, not a refactor.

### AES-GCM's arbitrary IV is refused, which was not on anyone's list

> `crypto/cipher: use of GCM with arbitrary IVs is not allowed in FIPS 140-only mode, use NewGCMWithRandomNonce`

[`secret`](../internal/secret/secret.go) derives a per-message AES-256 subkey with
HKDF-SHA256 over a 192-bit random salt and seals under an **all-zero nonce** — a design
that is *stricter* than random-nonce GCM, chosen deliberately to escape SP 800-38D's 2^32
call budget, with the reasoning written into the package comment. `fips140=only` refuses
it anyway, because the API cannot see the uniqueness argument, only the arbitrary IV.

`cipher.NewGCMWithRandomNonce` passes. It costs 12 bytes per ciphertext (Go prepends the
nonce) and **changes the wire format**, so this is a migration, not a swap.

**This is the one finding with a deadline.** Today the only sealed values are TOTP seeds.
[R2-40](tasks/R2-control-plane.md)'s CA private key and the LiteLLM master key are sealed
under the same helper, and after R2 a format change means re-sealing live secrets on
customer installs. **Decide before R2-40, not before the FIPS artifact ships.**

### PBKDF2's constraints, since R2-42 is not built yet

Measured under `only`: PBKDF2-SHA256 requires a **salt of at least 128 bits**, and Go
enforces no iteration floor. Free to satisfy in code that does not exist — which is the
argument [pivot §3](plans/pivot-cmmc.md#fips-is-a-build-not-a-rearchitecture) already made
for switching R2-42 off argon2id before it is written, now with a number attached.

### Follow-up (R5b): `CGO_ENABLED=0` is what makes it static, and FIPS has nothing to do with it

The "static" above holds, and it is worth being precise about *why*, because building the
[R5-25](tasks/R5-install.md) job on the loose version of the claim broke it immediately.

Measured on the same host: `GOFIPS140=v1.0.0 go build` produces a **dynamically linked**
binary, and so does a plain `go build`. Go's default is `CGO_ENABLED=1`. `make dist` sets it
to `0`, which is what the existing `static-binary` job checks and what the release path uses.

So the property [ADR 0002](adr/0002-go-with-package-manager-wrappers.md) and
[R0-16](tasks/R0-release.md) depend on belongs to the cgo-free build, not to FIPS — and FIPS
does not take it away, which is the actual finding. With `CGO_ENABLED=0 GOFIPS140=v1.0.0`:
statically linked, **1049** `fips140` symbols, and the whole suite passing under
`GODEBUG=fips140=on`.

## 3. The manifest can be verified independently — the reuse claim cannot

**Question 4: yes, and it is small.** A throwaway verifier over minisign's legacy `Ed`
format — Ed25519 over the raw message — resolves a signed manifest revision against the
embedded floor and degrades correctly in every failure:

| Case | Outcome |
| :--- | :--- |
| Valid revision 7 over floor 4 | supersedes — revision 7 |
| Body tampered after signing | refused, falls back to the floor |
| Signed by an untrusted key | refused, falls back to the floor |
| Valid but older than the floor | ignored, floor holds |
| Trusted comment rewritten | refused — the global signature covers it |

Stdlib only, and it passes under `fips140=only`: **Ed25519 and ECDSA P-256 are both
approved.** ADR 0007 is no longer load-bearing and unproven.

### But `verify.go` cannot be reused, and the ADR that says so needs correcting

[Pivot §2.3](plans/pivot-cmmc.md#23-one-binary-an-ee-directory-a-signed-licence-key) says
the licence key is verified "reusing
[`internal/components/verify.go`](../internal/components/verify.go) — no new crypto and no
new trust root." **`verify.go` verifies SHA-256 digests over HTTP. It contains no
signature verification of any kind.** `grep -rn ed25519 --include=*.go` returns nothing;
every signature check in the project is shell — `install.sh` shelling out to `openssl`,
and minisign offered only for manual out-of-band checking.

This does not break the decision, and it does move a premise. ADR 0004's property is that
components are *digest*-checked in Go rather than in shell; the manifest's integrity comes
from **being embedded in a signed binary**. Remove the embedding, as ADR 0007 requires,
and the manifest loses its integrity source — so ADR 0007 and ADR 0005 both need the same
thing: a signature verifier in Go, which is new crypto, however small. The prototype says
it is roughly eighty lines and no new dependency, provided the legacy format is used.

Two consequences for [ADR 0005 and ADR 0007](plans/pivot-cmmc.md#8-new-documents), which
[MVP S1](plans/mvp.md#4-the-route) writes:

1. **Say "a verifier we write, using the stdlib" rather than "no new crypto."** The
   conclusion survives; the sentence does not.
2. **Pin the signature format to non-prehashed.** Minisign's prehashed `ED` variant signs
   a BLAKE2b-512 digest. BLAKE2b is not in the standard library and is **not FIPS-approved**,
   so a prehashed signature would put a non-approved hash on the path that verifies a
   licence and a manifest — inside the boundary ADR 0006 is being written to defend.

The current [`Manifest`](../internal/components/manifest.go) carries `schema`,
`nodary_version` and `components` and has **no revision, no signature and no key id**, and
`Load()` reads only the embedded copy. ADR 0007 adds all four.

## 4. Open

- ~~**Which minisign variant the release actually produces was not measured.**~~ **Settled,
  and it was the worse answer.** Measured against minisign 0.11: `-S` alone writes a
  **prehashed `ED`** signature, and `-l` is the flag that asks for the legacy `Ed` one. So
  §3's recommendation is a change to the release pipeline, not a note in an ADR — anything
  nodary verifies in Go must be signed `minisign -S -l`. [ADR 0007](adr/0007-independent-component-manifest.md)
  carries it, and `internal/minisign` tests both directions against the real binary.
- **Question 1 needs a GPU host.**
- **`on` or `only` is a product decision, not an implementation one.** `only` costs the TOTP
  algorithm and a sealing-format migration. `on` costs nothing today and claims less. The
  ADR that picks one is ADR 0006, and it should pick explicitly rather than inherit a default.

## 5. Question 1 — the unit is trivial; the network is where it goes wrong

A `nodary-model@.service` template, an `%i.env` file and one GPU container, started and
stopped through `systemctl`. What it needed was unremarkable: `Type=exec`,
`EnvironmentFile=%h/…/%i.env`, an `ExecStartPre=-docker rm -f`, `docker run --rm --name`
in the foreground, `ExecStop=docker stop -t 10`, `Restart=on-failure`. `Restart` was
exercised by killing the container out from under it — `NRestarts` went 0 → 1 and the unit
returned to `active`. [R4-19](tasks/R4-agent.md) is the size it looks.

Three things were not what the specifications assume.

### WSL2 binds a GPU through `/dev/dxg`, and there is no `/dev/nvidia*`

`nvidia-smi -L` inside the container reports the 5090 correctly, and `ls /dev/nvidia*`
fails: the only device node is `/dev/dxg`. WSL2's paravirtualised GPU has no per-device
char nodes, so **anything that identifies a GPU by `/dev/nvidia<index>` is wrong on a WSL2
node** — which matters for [R4-23](tasks/R4-agent.md), the pre-start check that a
deployment's assigned GPU is the one it gets.

The index itself is still enforced by the runtime, and loudly: `--gpus device=1` on a
one-GPU host fails the container at creation with `error: 1: unknown device`. R4-23 has a
real signal to check; it just cannot be a device-node test. (The hook also logs
`Auto-detected mode as 'legacy'` on WSL2, which is worth not being surprised by.)

### The cgroup warning in 03 §5 is correct, and truer than written

[03 §5](specs/03-agent.md#5-egress-isolation) warns that `IPAddressDeny=` filters the
launcher rather than the workload because containerd parents the container elsewhere.
Confirmed, for docker too: the unit's cgroup held one process — the `docker run` client —
while the container was parented outside it entirely.

A second reason was found on top of that one. This ran as a **user** unit, and a user
manager is delegated `cpu memory pids` and no network controller at all, so
`IPAddressDeny=` in a user unit is not merely aimed at the wrong process — it has nothing
to attach to. [R4-28](tasks/R4-agent.md) keeps it as documented defence in depth, which
remains the right call, and the documentation should say both reasons.

### `--internal` silently breaks ingress — this is the finding

[03 §5](specs/03-agent.md#5-egress-isolation) requires two properties of the same network:
no default route off-box, **and** the port published on `127.0.0.1` so the gateway can
reach it. Docker's `--internal` network is the obvious way to get the first, and it
destroys the second **without a warning**:

```
docker run --network nodary-isolated -p 127.0.0.1:18080:8000 …
  NetworkSettings.Ports → {"8000/tcp":[]}      # no binding
  ss -ltn | grep 18080  → nothing               # no listener
```

The identical publish on a normal bridge binds correctly, so the failure is entirely the
network mode, and nothing on the success path tells you. A deployment would come up
`active`, hold its GPU, pass a `docker exec` health probe, and be unreachable by the
gateway — with `verify-egress` **passing**, because egress really is blocked.

The specification's own mechanism, tested as written, does the right thing. A normal
bridge with the default route deleted inside the namespace gives all four:

| | |
| :--- | :--- |
| default route inside | none |
| DNS lookup | fails |
| TCP to `1.1.1.1:443` | fails |
| TCP to the bridge gateway | fails |
| `curl 127.0.0.1:18082` | **succeeds**, and `ss` shows the listener bound to `127.0.0.1` only |

All three [R4-29](tasks/R4-agent.md) assertions pass while the port still serves. **The
mechanism is right and the shortcut is wrong**, which is the same shape as the
`IPAddressDeny` trap 03 §5 already documents — a thing that looks correct, reviews clean,
and is silently not what was asked for.

[R4-26](tasks/R4-agent.md) should therefore say bridge-plus-route-removal explicitly, and
**its `done:` must include that a published port is listening after the network exists.**
An isolation test alone passes in the broken configuration.

### Follow-up (R4d): the DNS row above is true of the default bridge and not of the network nodary ships

The table above records `DNS lookup | fails`. That was measured on docker's **default**
bridge, and it does not transfer to a user-defined network — which is what `nodary-isolated`
is. Measured again while building [R4-29](tasks/R4-agent.md), same host, same route removal:

| Network | `/etc/resolv.conf` | Lookup with no default route |
| :--- | :--- | :--- |
| default bridge `docker0` | `nameserver 192.168.65.7` (the host's) | **fails** — the resolver is off-box and unreachable |
| user-defined network | `nameserver 127.0.0.11` | **resolves, with live answers** |

Docker injects an embedded resolver at `127.0.0.11` for user-defined networks only. It sits on
the container's *own loopback*, so no route is needed to reach it, and it proxies queries out
through the daemon. The container still could not connect to what it resolved — and a
compromised model server does not need to: `<exfiltrated-data>.attacker.example` is a channel
out of a container that a route check calls isolated.

Two consequences, both now built:

1. **`nodary-isolated`'s CNI configuration carries an empty `dns` block**, so the absence of a
   resolver is configured rather than inferred from the absence of a route.
2. **03 §5's three assertions are not redundant**, and the DNS one is not belt and braces. It
   is the only one of the three that catches this.

This is the same shape as the `--internal` finding immediately above: a configuration that
looks correct, reviews clean, and is silently not what was asked for. It is also the second
time the spike's own conclusion held only for the exact thing it tested, which is the argument
for [R4-29](tasks/R4-agent.md) running continuously rather than once.

## 6. Open, after question 1

- **containerd was never exercised.** Cgroup parenting, namespaces and systemd behave the
  same, but `nerdctl`'s CNI plumbing is where `nodary-isolated` actually gets built, and
  03 §5 specifies a CNI bridge rather than a docker network. The `--internal` trap above is
  docker's; CNI will have its own, and the test that catches both is the same one.
- **Multi-GPU assignment is untested.** One card, so nothing here says whether two
  deployments can be held to separate indices on a host with no `/dev/nvidia*` nodes.
- **No model was served.** The image on the host wanted an artifact format the spike had no
  weights for, so the container held the GPU and answered a probe rather than doing work.
  Throughput, `ready_timeout_s` and crash-loop behaviour under real load are unmeasured.
