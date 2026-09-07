# Spike — FIPS and the manifest

**Answers:** [pivot §10](plans/pivot-cmmc.md#10-the-spike) questions 2, 3 and 4 ·
**Question 1 is unanswered** · **Measured on:** go1.27.0, linux/amd64, commit `906ee5a`

Throwaway work, kept as a memo. Everything below was run, not reasoned about; the
commands are given so each result can be reproduced or contradicted.

## What was not measured

**Question 1 — unit rendering and containerd GPU binding — was not attempted.** The
machine had containerd and systemd 255 and **no GPU and no NVIDIA driver**. Binding a GPU
into a container is the entire question, so a CPU-only rehearsal would have answered a
question nobody asked. It needs one real GPU host and remains
[the MVP's stated risk](plans/mvp.md#7-the-risk).

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

- **Which minisign variant the release actually produces was not measured.** `.goreleaser.yaml`
  passes no `-H`, and both GitHub releases for `v0.0.1-rc1` are still **drafts**, so no asset
  was fetchable from this container to read. One command settles it against a real artifact:
  `head -2 nodary_linux_amd64.minisig | tail -1 | base64 -d | head -c2` — `Ed` is legacy,
  `ED` is prehashed. If it is `ED`, §3's recommendation becomes a change to the release
  pipeline rather than a note in an ADR.
- **Question 1 needs a GPU host.**
- **`on` or `only` is a product decision, not an implementation one.** `only` costs the TOTP
  algorithm and a sealing-format migration. `on` costs nothing today and claims less. The
  ADR that picks one is ADR 0006, and it should pick explicitly rather than inherit a default.
