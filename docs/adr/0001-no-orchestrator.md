# ADR 0001 — No orchestrator

**Status:** Accepted · **Date:** 2026-08-28

## Context

The default way to run model servers across a set of GPU hosts is Kubernetes: k3s or similar,
the NVIDIA GPU Operator, an ingress controller, Helm charts, and a configuration-management
system to deploy them.

Examine what Kubernetes actually contributes to this workload. The GPU Operator is deployed
with `driver.enabled=false` and `toolkit.enabled=false` — a GPU host already owns both —
leaving `devicePlugin.enabled=true` as its only live function. That advertises `nvidia.com/gpu`
to a scheduler which never makes a scheduling decision, because a serving replica is pinned to
a named node with hand-assigned GPU indices chosen for NVLink and NUMA topology. The rest of
the stack is there to support a scheduler that is not scheduling.

The workload is a small number of long-lived processes on fixed hardware that never move.

## Decision

**No orchestrator.** Model servers run as systemd units against containerd. The agent renders
unit files and calls `systemctl`; systemd owns restart, backoff and process lifetime.

| Function | Replacement |
| :--- | :--- |
| Supervision, restart | systemd `Restart=always` |
| GPU assignment | Explicit indices via the container runtime |
| Egress lockdown | Isolated network namespace, no route off-box ([03](../specs/03-agent.md#5-egress-isolation)) |
| Service discovery | The control plane is the router; endpoints are static |
| Rolling restart | Control plane drains, cycles, health-checks |
| Ingress and TLS | The control plane terminates TLS |
| Persistent storage | Directories |
| Metrics discovery | The control plane generates scrape config; it knows every endpoint |

## Consequences

**Gained.** One-command install with no cluster to stand up first. No manifest renderer, no
Helm, no kubectl, no configuration-management system. A far smaller surface to secure, audit
and explain. Failure modes an operator can inspect with `systemctl` and `journalctl`.

**Lost.** No ecosystem: adding a component means writing a unit template, not installing a
chart. No scheduler, so heterogeneous or elastic workloads are out of scope by construction
([00](../specs/00-overview.md#1-scope)). Kubernetes expertise does not transfer to operating
nodary.

**Accepted risk.** nodary now owns a distributed system — enrollment, reconnection, version
skew, upgrade ordering. This is mitigated by keeping the agent deliberately boring: it renders
files and reports status, and does not schedule, bin-pack or supervise. It is not eliminated.

**Reconsider if** the workload becomes heterogeneous or elastic — many model families
appearing and disappearing, training alongside serving, or bin-packing across a large fleet.
At that point a scheduler earns its complexity, and this decision should be revisited rather
than worked around.
