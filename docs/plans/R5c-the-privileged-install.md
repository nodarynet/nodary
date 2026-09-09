# R5c — The privileged install

**Slice of:** [R5](../tasks/R5-install.md) ·
**Tasks:** R5-09, R5-10 · **Status:** complete, unverified on a privileged host

The half that needs root. [R5a](R5a-components-and-units.md) made a host able to fetch the
runtime and [R5b](R5b-preflight-and-doctor.md) made it able to say whether it should; this
places the binaries, writes the units, creates the service account and sets the layout.

## 1. It is written and staged here, and verified elsewhere

**Decided.** Every step takes a `Root` prefix, so the whole install runs into a temporary tree
without privilege. A real install passes `""`.

**Why.** This machine has no passwordless root, and a slice that could only be exercised on
someone else's host would be a slice nobody had run. Staging into a prefix proves everything
except the three things that are genuinely privileged — writing outside the prefix, creating a
user, and touching nftables — and those are covered by
[`scripts/verify-privileged.sh`](../../scripts/verify-privileged.sh), which is checked in so it
can be read before it is run.

**What the staged run proved here:** preflight, enrollment, the layout with its exact modes,
108 MB fetched through the control plane's mirror over mTLS, containerd 2.3.4, `nerdctl` 2.3.5
and runc 1.5.1 placed and *executing*, 20 CNI plugins extracted, the unit written, and a second
run reporting **zero** changes.

## 2. Enrollment happens before the fetch, inverting the specification's order

**Decided.** `node install` enrolls first, then fetches components through the mirror.

**Why.** [01 §5](../specs/01-install.md#5-node-install) lists the fetch as step 2 and enrollment
as step 4, and that order assumes components come from upstream. They do not:
[01 §3](../specs/01-install.md#3-bootstrap-order) makes the control plane the only host that
contacts an upstream source, and [R5a](R5a-components-and-units.md) put the mirror behind the
same mTLS as the rest of the agent protocol. A node therefore cannot fetch anything until it
holds a certificate.

The specification's order is right about intent and wrong about sequence, and the sequence is
forced. Recorded here rather than silently reordered.

## 3. A binary already present is left alone, and recorded as found

**Decided.** `PlaceComponents` skips a destination that exists and records it `placed: false`.

**Why.** R5-11's rule, applied at the moment it actually matters. A host may already run
containerd for something else, and the ownership record is what stops an uninstall taking that
down. Overwriting would also silently replace a version the operator chose.

## 4. The agent unit runs as root, and says why

**Decided.** `nodary-server` and `nodary-gateway` run as the `nodary` service account with
`ProtectSystem=strict` and an explicit `ReadWritePaths`. `nodary-agent` runs as root.

**Why.** The agent drives `systemctl`, writes unit environment files under `/etc/nodary`, and
enters a deployment's network namespace with `nsenter` to assert egress. A service account with
enough privilege for all three is root with extra steps, and dressing it up would be the kind
of security theatre this codebase argues against elsewhere. The two that *can* be confined are,
and the unit says which paths they may write.

## 5. Open items

- **R5-05** (`server install`'s ten steps) is partly done: it writes the layout, the PKI, the
  database and the units, and does not yet select components interactively, create the first
  administrator, or print the setup URL. R5-08 is the setup URL.
- **R5-12** (`--with-node`) is not a flag yet. The shape works — the verification script runs
  `server install` then `node install` on one host — but the single command does not exist.
- Nothing here has run as root. That is what the script is for, and the tracker says so rather
  than claiming otherwise.
