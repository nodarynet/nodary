# 03 — Agent & runtime

## 1. Transport

HTTPS with mTLS, agent-initiated only, JSON. All endpoints under `/api/v1/agent/`.

| Method | Path | Purpose |
| :--- | :--- | :--- |
| `POST` | `/api/v1/enroll` | CSR + join token → client certificate. The only unauthenticated agent endpoint |
| `GET` | `/api/v1/agent/desired?rev=N` | **Long-poll.** Blocks up to 60s, returns when the desired revision exceeds `N` |
| `POST` | `/api/v1/agent/status` | Heartbeat: inventory, unit states, staging progress. Every 15s |
| `POST` | `/api/v1/agent/events` | Audit records and lifecycle events generated on the node |
| `GET` | `/api/v1/agent/dist/<version>` | Self-upgrade: binary and components from the control plane's mirror |

## 2. Desired-state document

The complete intended state of one node. **There are no imperative commands in the protocol** —
the control plane describes an end state and never tells the agent how to reach it.

The agent evaluates it against the node's local guardrails ([12](12-node-guardrails.md))
and either reconciles or refuses with a reason ([12](12-node-guardrails.md#1-where-they-apply)).
A refusal is a normal outcome; the control plane records it and does not retry.

```json
{
  "rev": 412,
  "protocol": 1,
  "node": "gpu-01",
  "deployments": [
    {
      "id": "dep_7f3a",
      "model": "google/gemma-4-31b-it",
      "backend": "vllm",
      "image": "registry.example.internal/nodary/vllm@sha256:…",
      "gpus": [0, 1],
      "params": {
        "tensor_parallel": 2,
        "max_context": 131072,
        "gpu_memory_fraction": 0.92
      },
      "extra_args": ["--enable-prefix-caching"],
      "port": 8001,
      "network": "nodary-isolated",
      "state": "ready"
    }
  ],
  "staging": [
    {"model": "google/gemma-4-31b-it", "source": "local",
     "layout": "hf-cache", "manifest_sha256": "…", "expect_bytes": 62914560000}
  ],
  "agent": {"target_version": "2.0.0"}
}
```

`params` are canonical and backend-independent; the agent translates them through the
backend descriptor ([04](04-backends.md)). `extra_args` pass through verbatim.

## 3. Reconcile loop

Every iteration is idempotent and converges. The agent never assumes it caused the current
state — it observes and corrects.

```
loop:
  desired ← long-poll(rev)
  allowed ← evaluate(desired, node.toml)       # 12-node-guardrails.md
  refused ← desired - allowed
  actual  ← observe()            # systemctl state, staged weights, GPU inventory
  for each difference in allowed:
      stage weights | prepare | write unit | start | stop | remove
  report(actual, progress, refused)
```

`evaluate` runs before any side effect. An agent never partially applies a document it is
going to refuse — a half-applied change is worse than a rejected one.

Ordering is fixed:

1. Weights are staged before a deployment is prepared.
2. A deployment is prepared before its unit starts ([04](04-backends.md#4-the-prepare-phase)).
3. A unit stops before its weights are removed.
4. A GPU set is released before it is reassigned.

## 4. Version skew

Every message carries `protocol`; the server advertises a supported range. An agent outside
that range **stops reconciling**, continues running whatever is already up, and reports
`incompatible`. It does not guess.

Server and agent are the same binary and share a protocol version, so skew occurs only
mid-upgrade and is bounded.

## 5. Egress isolation

Deny-by-default outbound for serving deployments. This is the enforcing control behind the
closed-system guarantee, so the mechanism matters more than the intent.

### The obvious approach does not work

systemd's `IPAddressAllow=` / `IPAddressDeny=` attach a BPF program to the *unit's* cgroup.
`nerdctl run` does not run the workload in that cgroup — it hands the request to containerd,
whose shim parents the container elsewhere. Putting `IPAddressDeny=any` on
`nodary-model@.service` therefore filters `nerdctl` itself and not the model.

It looks correct, reviews clean, and enforces nothing. Do not rely on it.

### The mechanism

A network namespace with no route off-box. Deployments attach to a dedicated CNI bridge
network, `nodary-isolated`, created by the agent at install:

- the container receives an address on a host-local bridge and **no default route**;
- IP forwarding is disabled for that bridge, and an nftables rule drops forwarded traffic from its subnet;
- the port is published on `127.0.0.1` only, so the container is reachable by the gateway and by nothing off-host.

This holds regardless of how containerd parents cgroups, is inspectable with `ip route` inside
the container, and needs no BPF. `IPAddressDeny=any` remains on the unit as defence in depth —
it constrains the launcher, and is honest to keep provided nobody mistakes it for the control.

A serving deployment needs nothing more: once weights are staged it makes no outbound
connections and receives only proxied inference traffic.

### Staging is separate

Weight downloads run as a transient unit **on the host** — not in the isolated namespace —
with a narrow `IPAddressAllow=` list. Here the systemd filter *does* apply, because the
download is a direct child of the unit. It exits before the model unit starts. The serving
path never holds network reach it does not need.

### Verification is mandatory

`nodary node verify-egress <name>` executes a probe inside a live deployment's namespace and
asserts that a route off-box, a DNS lookup, and a connection to a known-external address all
fail. It runs after every deployment start and on demand. A failure marks the deployment
non-compliant and raises a critical alert.

Given how easy this mechanism is to get subtly wrong, an assertion that runs continuously is
worth more than any amount of configuration review.

## 6. Unit template

One templated unit, one instance per deployment. `%i` is the deployment id.

```ini
# /etc/systemd/system/nodary-model@.service
[Unit]
Description=nodary model deployment %i
After=containerd.service
Requires=containerd.service

[Service]
Type=exec
EnvironmentFile=/etc/nodary/deployments/%i.env
ExecStartPre=-/usr/local/bin/nerdctl rm -f nodary-%i
ExecStart=/usr/local/bin/nerdctl run --rm --name nodary-%i \
    --gpus '"device=${NODARY_GPUS}"' \
    --network nodary-isolated \
    -v ${NODARY_MODELS_DIR}:${NODARY_MOUNT_PATH}:ro \
    -p 127.0.0.1:${NODARY_PORT}:${NODARY_CONTAINER_PORT} \
    ${NODARY_IMAGE} ${NODARY_ARGS}
ExecStop=/usr/local/bin/nerdctl stop --time 30 nodary-%i
Restart=always
RestartSec=10s

# Defence in depth only. NOT the egress control — see §5.
IPAddressDeny=any
IPAddressAllow=localhost

[Install]
WantedBy=multi-user.target
```

The agent writes only `/etc/nodary/deployments/<id>.env` and calls `systemctl`. It contains no
supervision logic; systemd owns restart, backoff and process lifetime.

## 7. GPU assignment, health, restart, reboot

**Assignment is explicit, always.** A deployment names its GPU indices; the control plane
guarantees no two deployments on a node claim the same index, and the agent double-checks
before starting. Topology-aware placement — NVLink pairs, same-NUMA groups — is expressed by
*choosing* indices, and the agent reports `nvidia-smi topo -m` so the interface can show which
sets are sensible.

**Health.** The agent polls each deployment's health endpoint (from the backend descriptor)
every 10s. Three consecutive failures mark it `unhealthy`, the control plane removes it from
its route, and `Restart=always` handles recovery. A deployment that fails to become ready
within the backend's timeout is marked `failed` and reported with the last 100 lines of
container log.

**Rolling restart** never drops the last ready replica:

```
for each deployment of the model:
    remove from route  →  wait for in-flight to drain (≤30s)
    stop  →  start  →  wait for ready (≤backend timeout)
    add to route
    if not ready: halt, leave remainder running, report
```

With fewer than two ready replicas the command warns and requires `--allow-downtime`.

### Reboot safety

A host whose root filesystem is encrypted without an automatic unlock path needs a human at
the physical console to come back up. The agent detects this at preflight, the control plane
stores it as `reboot_policy: manual-console`, and **the agent refuses to initiate a reboot on
such a host**. The interface displays it prominently on the node.

This is a general mechanism, not a site-specific accommodation: any encrypted-root host
without network-bound unlock is affected.

A WSL2 node is recorded as `reboot_policy: host-managed` for a different reason: `reboot`
inside the distribution does not restart the Windows host, and the host's lifecycle is not
nodary's to drive. The agent never attempts a reboot there either, and the control plane
displays whether a logon task exists to bring the node back
([01](01-install.md#windows-hosts-run-as-wsl2-nodes)).
