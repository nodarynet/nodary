# R5b — Preflight, `doctor`, and the setup URL

**Slice of:** [R5](../tasks/R5-install.md) ·
**Tasks:** R5-01, R5-02, R5-04, R5-18, R5-25 · **Status:** complete

The checks. [R5a](R5a-components-and-units.md) made a host able to get the runtime; this makes
it able to say whether it should have tried, and — once it is running — whether it still
should be.

## 1. Preflight and `doctor` are one mechanism seen at two times

**Decided.** One `Report` of levelled `Check`s. Preflight runs the subset that can be answered
before anything is installed; `doctor` runs those *and* the ones that need a running system.

**Why.** [10 §3](../specs/10-cli.md#3-nodary-doctor) and
[01 §11](../specs/01-install.md#11-preflight) describe the same output in two places — a list
of named checks, each passing or failing, with warnings distinguished. Building them
separately would produce two answers to "is the driver new enough", and the one an operator
gets would depend on which verb they happened to run.

The split is not by check but by *what exists yet*: `nvidia-smi enumerates GPUs` is answerable
on a bare host, `certificate renews in 41d` is not.

## 2. Every check runs, always

**Decided.** No check aborts the run. A failure is recorded and the next one still executes.

**Why.** [01 §11](../specs/01-install.md#11-preflight) opens with it: *reported as one list…
so a misconfigured host surfaces every problem at once rather than one per run*. That is the
whole requirement, and it is a constraint on the control flow rather than on the output — an
implementation that returned early would satisfy the format and not the point.

The practical version: an operator on a fresh GPU host with no driver, no swap and a full disk
should learn all three in one command, not discover them over three installs.

## 3. A check that cannot run is not a check that passed

**Decided.** Where a check cannot reach its evidence — `nvidia-smi` absent, `/proc` unreadable,
a control plane unreachable — it reports at its own level with the reason, never `ok`.

**Why.** This is the same rule [R4d](R4d-egress-isolation.md) arrived at for egress, and it was
learned there the hard way: a DNS check that looked up a name chosen not to exist passed on
every host, including the one whose resolver it was written to catch. Every check here is
capable of the same failure, because most of them establish a property by *not* finding a
problem.

## 4. `doctor` runs egress verification, and that is the point of having it

**Decided.** `doctor` calls the same `VerifyEgress` the reconcile loop calls after every start.

**Why.** R5-18's `done:` says it plainly — *a control that is only checked at creation time is
a control that drifts*. The isolation was correct when the deployment started; `doctor` is what
answers whether it is correct now, after a kernel upgrade, an operator's `iptables` change, or
a runtime that started injecting a resolver in a point release. That last one is not
hypothetical: [R4d](R4d-egress-isolation.md) found exactly it.

## 5. The setup URL is deferred to R5c, with the rest of `server install`

**Decided.** R5-08 does not land here. It needs a `/setup` endpoint and a password-set flow,
which belong with `server install`'s remaining steps rather than with the checks.

The design stands and is recorded so it is not re-derived: a one-time URL carrying a token
valid for 15 minutes, stored hashed, single-use, burned when the first administrator sets a
password. R5-08's `done:` is one line — *no default password ever exists* — and every
alternative creates one, because a printed generated password is a default until it is
changed. Reusing the join-token machinery is rejected: a join token enrols a *machine*
([02 §4](../specs/02-enrollment.md#4-token-types)), and giving one a second, much larger
meaning defeats the point of having distinct prefixes.

## 5a. The original note, kept

The setup URL exists so that no default password ever does

**Decided.** `server install` prints a one-time URL carrying a token valid for 15 minutes. The
token is stored hashed, single-use, and burned when the first administrator sets a password.

**Why.** R5-08's `done:` is one line — *no default password ever exists* — and it is the whole
design. Every alternative worth considering creates one: a printed generated password is a
default until it is changed, and an unauthenticated `/setup` that is open until first use is a
default that lasts until somebody notices.

Fifteen minutes is short enough that a URL left in a terminal scrollback is not a credential,
and long enough for somebody to walk to another machine.

**Rejected — reuse the join-token machinery.** It is already single-use, hashed and expiring,
and would cost nothing. A join token enrolls a *machine*
([02 §4](../specs/02-enrollment.md#4-token-types)); making one also able to create the first
administrator gives every leaked join token a second, much larger meaning, and the prefixes
exist precisely so that a credential's purpose is legible.

## 6. The FIPS job reports and does not gate

**Decided.** R5-25 as [mvp §5.6](mvp.md#56-fips-builds-in-ci-and-does-not-gate) decided:
`GOFIPS140=v1.0.0`, build and run the suite, `continue-on-error`.

**Why.** [The spike](../spike-fips-and-manifest.md) answered once whether the FIPS build
compiles and whether TOTP's HMAC-SHA-1 survives the module — it does not, under `only`, and it
*panics*. A job answers that continuously and for free. Gating on it would block every pull
request on a dependency nobody has measured, in service of a claim
[the MVP explicitly does not make](mvp.md#6-what-an-mvp-install-cannot-claim).

## 7. The shape

| | |
| :--- | :--- |
| `internal/preflight` | The checks, levelled, and the report |
| `internal/cli/doctor.go` | `nodary doctor` |
| `internal/identity/setup.go` | The one-time setup token |
| `.github/workflows/` | The non-gating FIPS job |

## 8. Steps

- [x] The report: levels, and every check running
- [x] The host checks — systemd, cgroup v2, driver, GPUs, disk, ports, clock
- [x] The warnings — swap, LSM, RAM per GPU, encrypted root
- [x] `nodary doctor`, including egress verification
- [x] The FIPS job

## 9. What the FIPS job found while it was being written

The static-binary step originally ran `go build` with no `CGO_ENABLED`. It failed: the binary
came out **dynamically linked**.

That is not FIPS. A plain `go build` on the same host is dynamic too — Go's default is
`CGO_ENABLED=1`, and the release path (`make dist`) sets it to `0`, which is why the existing
`static-binary` job passes and this one did not. [The spike's](../spike-fips-and-manifest.md)
"FIPS build is static" is correct, and correct *of the build the product actually ships*.

Worth recording because of how it would have failed: behind `continue-on-error`, as a
permanent red mark nobody reads, for a reason with nothing to do with what the job is for. A
non-gating job that always fails is worse than no job — it trains people to ignore the one
signal it exists to give. The step now sets `CGO_ENABLED=0` explicitly and says why.

Verified locally after the fix: statically linked, 1049 `fips140` symbols, and the **whole
suite passing** under `GODEBUG=fips140=on`.

## 10. Open items

- The WSL2 checks are R5-03 and are deferred by [mvp §4](mvp.md#4-the-route), even though this
  machine is a WSL2 host and would exercise them. `RebootPolicy` already detects WSL2 for
  [R4b](R4b-backends-and-the-plan.md)'s purposes, so the detection exists and the checks do not.
- `server install`'s remaining steps (R5-05), `node install` (R5-09), the layout (R5-10) and
  `--with-node` (R5-12) are the rest of [S7](mvp.md#4-the-route).
