# R4d — Egress isolation and its assertion

**Slice of:** [R4](../tasks/R4-agent.md) ·
**Tasks:** R4-26, R4-27, R4-29 · **Status:** complete

The control the product's strongest claim rests on.
[mvp §5.3](mvp.md#53-egress-isolation-is-built-node-guardrails-are-not) makes it non-optional
for exactly one reason: the flaw-remediation narrative is *a finding that needs network
reachability, in a container with no route*, and nobody can write that narrative without the
assertion behind it.

## The finding this slice was written around

Before designing anything, the mechanism was measured on this machine — a bridge network, a
container on it, the default route removed:

| | |
| :--- | :--- |
| default route | absent |
| TCP to an external address | refused |
| ingress on `127.0.0.1` | **works** — the half `--internal` silently breaks |
| reachable off-box | no |
| **DNS lookup** | **resolved, with live answers** |

The last row is the finding. Docker injects an embedded resolver at `127.0.0.11`, on the
container's *own loopback*, which needs no default route to reach; it proxies queries out
through the daemon. The container could not connect to what it resolved — and a compromised
model server does not need to. `<exfiltrated-data>.attacker.example` is a working channel out
of a container that passes a route check.

Two things follow, and they shape everything below.

**[03 §5](../specs/03-agent.md#5-egress-isolation)'s three-part assertion is not redundant.**
"No route off-box" does not imply "DNS fails". It reads like belt and braces and it is not;
one runtime's convenience feature defeats the route check entirely.

**The spike measured this row as passing, and it was not wrong.** Its table says
`DNS lookup | fails`, and that is true — of docker's *default* bridge, where `resolv.conf`
names the host's off-box resolver, unreachable without a route. `nodary-isolated` is a
user-defined network, and docker injects its embedded resolver only there. Measured both ways
on the same host:

| Network | `resolv.conf` | Lookup, no default route |
| :--- | :--- | :--- |
| default bridge | the host's resolver | fails |
| user-defined | `127.0.0.11` | **resolves** |

So the finding is not that the spike was wrong. It is that a result held for the exact
configuration tested and not for the one being shipped — a more uncomfortable failure mode
than being wrong, and the second time an egress conclusion here has turned on a detail nobody
thought was load-bearing. The first was `--internal` silently discarding `-p 127.0.0.1:…`.

That is the whole argument for [03 §5](../specs/03-agent.md#5-egress-isolation)'s "an
assertion that runs continuously is worth more than any amount of configuration review", and
it is now evidence rather than a prediction.

## 1. The isolated network denies DNS explicitly, rather than relying on the missing route

**Decided.** `nodary-isolated`'s CNI configuration carries no gateway, no default route, and an
**empty `dns` section**, so the container's `/etc/resolv.conf` names no resolver at all.

**Why.** The measurement above. Under CNI the bridge plugin populates `resolv.conf` from the
network's `dns` block rather than injecting an in-namespace resolver, so leaving it empty is
sufficient *and* is the state the assertion then confirms. Relying on "there is no route, so
DNS cannot work" is relying on a property that one mainstream runtime already breaks.

**Rejected — point `dns` at an unroutable address.** Also works, and it produces a clearer
error inside the container than "no nameserver". It is a configuration that *looks* like it is
trying to resolve something, and the next person to read it may helpfully make it reachable.

## 2. The probe is the nodary binary, run inside the deployment's namespace

**Decided.** `nodary agent egress-probe` runs the three checks in whatever network namespace it
finds itself in and prints JSON. `nodary node verify-egress` enters the deployment's namespace
with `nsenter` and runs it there.

**Why.** The agent is already root on the node — it drives `systemctl` — so `nsenter` costs
nothing and needs no image. The alternatives all drag in a dependency the isolated network is
specifically supposed not to have: `nerdctl exec` needs the *model's* image to contain `ip`,
`nc` and a resolver tool, which no vLLM image promises; a probe container needs an image
pinned, distributed and staged onto an air-gapped node.

A static binary that is already on the host, run in the namespace, needs none of that. It also
means the probe and the thing being asserted are versioned together.

**Rejected — assert from the host by inspecting the namespace's routes and rules.** No process
entry at all, and it reads the same information. It asserts what the *configuration* says
rather than what the container can *do*, which is the distinction this whole control exists on:
the DNS finding above is invisible to a route-table inspection.

## 3. A control run makes a vacuous pass detectable

**Decided.** `verify-egress` runs the same probe twice — once inside the namespace, once on the
host — and reports `inconclusive` rather than `compliant` when the host also cannot reach out.

**Why.** Every check here passes by *failing*, which is the shape of assertion that quietly
stops meaning anything. On a host with no internet — a genuinely air-gapped site, which is a
customer this product is aimed at — the in-namespace probe fails for reasons that have nothing
to do with the isolation, and reports compliant. The isolation may still be perfectly correct;
the point is that the check did not establish it.

Measured on this machine as the control that makes the distinction real: the host has egress
and DNS, so a passing in-namespace probe here means something.

**Rejected — assume the host has egress and report compliant regardless.** Simpler, and true
on most hosts. It makes the one deployment scenario where isolation matters most — the
air-gapped site — the one where the assertion silently degrades to a no-op.

## 4. What this slice can prove here, and what it cannot

Stated up front rather than discovered in review. This machine has **no passwordless root**,
and containerd and `nerdctl` are not installed (R5-04 fetches them).

| | |
| :--- | :--- |
| The probe's three checks, in a real empty namespace | **proved** — `unshare --net` |
| The probe against a real container with no default route | **proved** — docker, which is available here |
| The DNS finding, and that the probe catches it | **proved** |
| Ingress surviving alongside isolation | **proved** |
| Rendering the CNI configuration | **proved** |
| *Creating* the network: `nft`, sysctl, `/etc/cni/net.d` | **not proved** — needs root |
| `nerdctl` attaching a container to it | **not proved** — needs R5-04 |

The two unproved rows are the plumbing, and they are the part a first install exercises
immediately. They are marked in the tracker rather than claimed.

## 5. The shape

| | |
| :--- | :--- |
| `internal/agent/network.go` | The CNI configuration and creating it |
| `internal/agent/egress.go` | The three checks, and the verdict |
| `internal/cli/agent.go` | `nodary agent egress-probe` |
| `internal/cli/node.go` | `nodary node verify-egress` |

## 6. Steps

- [x] The `nodary-isolated` CNI configuration, with no gateway, no route and no DNS
- [x] `EnsureIsolatedNetwork`: write it, disable forwarding, drop forwarded traffic
- [x] The probe: route, DNS, connect — plus the host control run
- [x] `nodary agent egress-probe` and `nodary node verify-egress`
- [x] Prove it against a real container, including the DNS channel

## 7. A bug this slice found in itself

The DNS check began as a lookup of `nodary-egress-probe.example.com` — a name chosen because
it must not resolve. Running it on this host reported **DNS isolated**, on a machine with
perfectly good DNS.

A name that does not exist returns NXDOMAIN from a working resolver exactly as readily as from
no resolver at all. The check would have passed on any host, and — the part that matters — it
would have passed inside the very container whose injected resolver it exists to catch. The
target is now `example.com`, which is IANA-reserved and resolves from anywhere DNS works.

It is worth recording because it is the same failure shape as the two findings above: a check
that passes by failing, quietly failing for the wrong reason. The control run in §3 exists for
that class, and this instance was caught by running the verb rather than by reading it.

## 8. Open items

- The probe runs on demand here. [R4-29](../tasks/R4-agent.md) also requires it after every
  deployment start; that is one call from the reconcile loop and lands with this slice.
- Marking a failing deployment non-compliant *and removing it from its route* is the control
  plane's half, like health — the route is fleet state. The agent reports; R3 acts.
