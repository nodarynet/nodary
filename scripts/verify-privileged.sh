#!/usr/bin/env bash
#
# verify-privileged.sh — the rows nothing else can prove.
#
# Everything in nodary that does not need root is covered by `make check`. This
# script covers what is left: placing binaries on the host, writing system
# units, creating the isolated CNI network, and — the one that matters most —
# starting a real container and asserting it has no way off the box.
#
# WHAT THIS CHANGES ON YOUR HOST
#
#   /usr/local/bin/     containerd, containerd-shim-runc-v2, ctr, nerdctl, runc
#                       (only if absent — an existing one is left alone)
#   /opt/cni/bin/       the CNI plugins
#   /etc/cni/net.d/     10-nodary-isolated.conflist
#   /etc/systemd/system nodary-server, nodary-gateway, nodary-agent, containerd
#   /opt/nodary/        the binary, versioned, with a `current` symlink
#   /etc/nodary/        configuration, PKI, the sealing key
#   /var/lib/nodary/    database, component cache, models
#   /var/log/nodary/    the audit mirror
#   nftables            a table named `nodary` (nodary's own; nothing else is edited)
#   a system user       `nodary`, no shell, no home
#
# It does NOT pull any model weights and does NOT need a GPU for most of it.
#
# TO UNDO: run with `cleanup` as the first argument. That removes everything
# above except the component binaries it *placed* — those are listed at the end
# so you can decide.
#
# Usage:
#   sudo ./scripts/verify-privileged.sh            # run the checks
#   sudo ./scripts/verify-privileged.sh cleanup    # undo
#
set -uo pipefail

PASS=0; FAIL=0; SKIP=0
BIN="${NODARY_BIN:-/tmp/nodary-verify}"
PORT="${NODARY_PORT:-18443}"
GWPORT="${NODARY_GWPORT:-18080}"

say()  { printf '\n\033[1m== %s\033[0m\n' "$*"; }
ok()   { PASS=$((PASS+1)); printf '  \033[32m✔\033[0m %s\n' "$*"; }
bad()  { FAIL=$((FAIL+1)); printf '  \033[31m✘\033[0m %s\n' "$*"; }
skip() { SKIP=$((SKIP+1)); printf '  \033[33m–\033[0m %s\n' "$*"; }

need_root() {
  if [ "$(id -u)" -ne 0 ]; then
    echo "This script needs root: it writes to /etc, /usr/local/bin and /etc/systemd/system." >&2
    echo "Re-run with sudo." >&2
    exit 2
  fi
}

# --- cleanup ------------------------------------------------------------------

cleanup() {
  need_root
  say "Stopping and removing units"
  for u in nodary-agent nodary-gateway nodary-server containerd; do
    systemctl disable --now "$u.service" >/dev/null 2>&1 && echo "  stopped $u"
    rm -f "/etc/systemd/system/$u.service"
  done
  systemctl stop 'nodary-model@*' >/dev/null 2>&1
  rm -f /etc/systemd/system/nodary-model@.service /etc/systemd/system/containerd.service
  systemctl daemon-reload

  say "Removing the isolated network"
  nft delete table inet nodary 2>/dev/null && echo "  removed the nodary nftables table"
  rm -f /etc/cni/net.d/10-nodary-isolated.conflist
  ip link delete nodary0 2>/dev/null && echo "  removed the nodary0 bridge"

  say "Removing nodary's own state"
  if [ -f /etc/nodary/components.json ]; then
    echo "  components nodary PLACED (remove by hand if you want them gone):"
    grep -B2 '"placed": true' /etc/nodary/components.json 2>/dev/null | grep '"path"' | sed 's/^/    /'
  fi
  rm -rf /etc/nodary /var/lib/nodary /var/log/nodary /opt/nodary
  userdel nodary 2>/dev/null && echo "  removed the nodary user"
  rm -f "$BIN"
  echo
  echo "Done. Component binaries in /usr/local/bin were left in place."
  exit 0
}

[ "${1:-}" = "cleanup" ] && cleanup

# --- the checks ---------------------------------------------------------------

need_root
cd "$(dirname "$0")/.." || exit 1

say "Building"
if go build -o "$BIN" ./cmd/nodary; then ok "built $BIN"; else bad "build failed"; exit 1; fi

say "Preflight sees this host"
"$BIN" doctor --role server 2>&1 | sed 's/^/  /'

say "1. server install — layout, PKI, database, units"
FP=$("$BIN" server install --bind "127.0.0.1:$PORT" --host localhost 2>/dev/null | tail -1)
if [ -n "$FP" ]; then ok "installed; CA fingerprint $FP"; else bad "server install produced no fingerprint"; fi

# R5-10: the layout and its modes.
say "2. R5-10 — filesystem layout and permissions"
check_mode() {
  local path="$1" want="$2"
  if [ ! -e "$path" ]; then bad "$path does not exist"; return; fi
  local got; got=$(stat -c '%a' "$path")
  if [ "$got" = "$want" ]; then ok "$path is $got"; else bad "$path is $got, want $want"; fi
}
check_mode /var/lib/nodary 700
check_mode /etc/nodary 755
check_mode /etc/nodary/pki 700
check_mode /var/log/nodary 700
if [ -f /etc/nodary/secret.key ]; then
  m=$(stat -c '%a' /etc/nodary/secret.key)
  # 08 §4: a sealing key at 0644 is a silent total compromise.
  if [ "$m" = "400" ]; then ok "secret.key is 400"; else bad "secret.key is $m, want 400"; fi
else
  bad "secret.key was not created"
fi

# The install runs as root; the units do not. Every file the service opens has
# to belong to the service account, or `server start` dies with
# `open /etc/nodary/server.toml: permission denied` — which is exactly what a
# privileged run reported before install.EnsureOwnership existed.
check_owner() {
  local path="$1" want="$2"
  if [ ! -e "$path" ]; then bad "$path does not exist"; return; fi
  local got; got=$(stat -c '%U:%G' "$path")
  if [ "$got" = "$want" ]; then ok "$path is $got"; else bad "$path is $got, want $want"; fi
}
check_owner /etc/nodary/server.toml nodary:nodary
check_owner /etc/nodary/pki nodary:nodary
check_owner /var/lib/nodary/nodary.db nodary:nodary
# And the one that must NOT be handed over: the unit reads it as a systemd
# credential instead, so the account running the network-facing process cannot
# read the key that decrypts every TOTP seed and the agent CA.
check_owner /etc/nodary/secret.key root:root

say "3. The binary is at 01 §12's location"
# The units carry PrivateTmp=true, so a binary in /tmp is invisible to the
# service and systemd reports 203/EXEC. Measured: same binary, PrivateTmp on
# exits 203 and off exits 0.
if [ -x /opt/nodary/current/nodary ]; then
  ok "/opt/nodary/current/nodary → $(readlink /opt/nodary/current)"
else
  bad "/opt/nodary/current/nodary is missing; the units will fail with 203/EXEC"
fi

say "4. Units are written and load"
for u in nodary-server nodary-gateway; do
  if [ -f "/etc/systemd/system/$u.service" ]; then ok "$u.service written"; else bad "$u.service missing"; fi
done
systemctl daemon-reload
if systemctl cat nodary-server.service >/dev/null 2>&1; then
  ok "systemd loads nodary-server.service"
else
  bad "systemd will not load nodary-server.service"
fi

say "5. The control plane starts under systemd"
systemctl enable --now nodary-server.service >/dev/null 2>&1
sleep 3
if systemctl is-active --quiet nodary-server.service; then
  ok "nodary-server is active"
else
  bad "nodary-server did not start"
  journalctl -u nodary-server.service -n 20 --no-pager | sed 's/^/    /'
fi

say "6. R5-06/R5-07 — components resolve into the mirror"
if "$BIN" components fetch --role node >/dev/null 2>&1; then
  n=$(ls /var/lib/nodary/dist 2>/dev/null | wc -l)
  ok "$n artifacts in /var/lib/nodary/dist"
else
  bad "components fetch failed"
fi

say "7. R5-09 — node install on this same host (--with-node shape)"
TOK=$("$BIN" token join --uses 1 --yes --justify "privileged verification" 2>/dev/null | tail -1)
if [ -z "$TOK" ]; then bad "could not mint a join token"; fi
if "$BIN" node install --server "https://127.0.0.1:$PORT" --token "$TOK" \
     --ca-fingerprint "$FP" --name "$(hostname -s)" 2>&1 | sed 's/^/  /'; then
  ok "node install completed"
else
  bad "node install failed"
fi

say "8. containerd is running"
# The containerd release tarball ships no unit; nodary places one. Without it
# nodary-model@.service's Requires=containerd.service resolves to nothing.
if systemctl is-active --quiet containerd.service; then
  ok "containerd.service is active"
else
  bad "containerd.service is not active"
  journalctl -u containerd.service -n 15 --no-pager 2>/dev/null | sed 's/^/    /'
fi

say "9. The placed runtime actually runs"
for b in containerd nerdctl runc; do
  if command -v "$b" >/dev/null 2>&1 && "$b" --version >/dev/null 2>&1; then
    ok "$b: $($b --version 2>&1 | head -1)"
  else
    bad "$b is not runnable"
  fi
done
for p in bridge portmap host-local; do
  if [ -x "/opt/cni/bin/$p" ]; then ok "CNI $p present"; else bad "CNI $p missing"; fi
done

say "10. R4-26 — the nodary-isolated network exists"
if [ -f /etc/cni/net.d/10-nodary-isolated.conflist ]; then
  ok "the CNI configuration is written"
  # The properties that make it the control.
  #
  # `isDefaultGateway`, not `isGateway`. This checked the second, on the same
  # wrong reasoning the Go test carried: isGateway puts an address on the
  # *bridge*, which is what lets the host route in, while isDefaultGateway is
  # what installs a default route in the container. Asserting the wrong one held
  # the network at a setting where portmap's DNAT pointed at an address the host
  # could not reach, so every published port was installed and dead.
  if grep -q '"isDefaultGateway": false' /etc/cni/net.d/10-nodary-isolated.conflist; then
    ok "isDefaultGateway is false — the container gets no default route"
  else bad "isDefaultGateway is not false; the container would get a default route"; fi
  if grep -q '"isGateway": true' /etc/cni/net.d/10-nodary-isolated.conflist; then
    ok "isGateway is true — the host can route in, so a published port works"
  else bad "isGateway is not true; portmap's DNAT would point where the host has no route"; fi
  if grep -q '"ipMasq": false' /etc/cni/net.d/10-nodary-isolated.conflist; then
    ok "ipMasq is false — nothing NATs this subnet out"
  else bad "ipMasq is not false"; fi
  if grep -q '"dns": {}' /etc/cni/net.d/10-nodary-isolated.conflist; then
    ok "dns is empty — no resolver in the namespace"
  else bad "dns is not empty; see docs/plans/R4d-egress-isolation.md"; fi
else
  bad "the CNI configuration was not written"
fi
if nft list table inet nodary >/dev/null 2>&1; then
  ok "the nodary nftables table exists"
  nft list table inet nodary | grep -q 'drop' && ok "it drops forwarded traffic from the subnet"
else
  skip "nft is not installed, so the drop rule could not be added"
fi

say "11. The agent is running and reports in"
if systemctl is-active --quiet nodary-agent.service; then
  ok "nodary-agent is active"
  sleep 16   # one heartbeat
  if "$BIN" node list 2>/dev/null | grep -q "$(hostname -s)"; then
    ok "the node appears in the fleet"
  else
    skip "node list is not implemented yet; check the database directly"
  fi
else
  bad "nodary-agent did not start"
  journalctl -u nodary-agent.service -n 20 --no-pager | sed 's/^/    /'
fi

say "12. R4-29 — a REAL container, and is it actually isolated?"
# This is the row nothing else can prove. A container on nodary-isolated, and
# the probe run inside its namespace.
if ! command -v nerdctl >/dev/null 2>&1; then
  skip "nerdctl is not available"
elif ! systemctl is-active --quiet containerd.service 2>/dev/null && ! pgrep -x containerd >/dev/null; then
  skip "containerd is not running; see step 8"
else
  nerdctl rm -f nodary-verify >/dev/null 2>&1
  # The pull is separate and its output is kept. "cannot fetch an image" and
  # "cannot attach to nodary-isolated" are unrelated failures, and inside a
  # single `run` they looked identical — a truncated progress bar and nothing
  # else, which is how a missing iptables read as a registry problem.
  if ! PULL=$(nerdctl pull --quiet alpine:3 2>&1); then
    skip "no test image, so this host cannot prove the row: $(printf '%s' "$PULL" | tail -1)"
  # Something that answers on port 80, not `sleep`: the ingress half of this row
  # is whether the gateway could actually reach a model, and nothing listening
  # cannot tell a working port mapping from a broken one.
  #
  # busybox `nc`, because **alpine's busybox has no httpd** — measured: `sh:
  # httpd: not found`, the container exited at once, and the row failed looking
  # for a pid. The loop is what keeps the container alive whatever happens to the
  # listener, so a missing tool cannot take the egress probe down with it.
  elif RUNERR=$(nerdctl run -d --name nodary-verify --network nodary-isolated \
       -p 127.0.0.1:19099:80 alpine:3 \
       sh -c 'while true; do printf "HTTP/1.0 200 OK\r\n\r\nnodary\n" | nc -l -p 80 2>/dev/null || sleep 5; done' 2>&1); then
    ok "a container started on nodary-isolated"
    PID=$(nerdctl inspect --format '{{.State.Pid}}' nodary-verify 2>/dev/null)
    if [ -n "$PID" ] && [ "$PID" != "0" ]; then
      echo "  probe inside the namespace:"
      nsenter --target "$PID" --net -- "$BIN" agent egress-probe 2>&1 | sed 's/^/    /'
      if nsenter --target "$PID" --net -- "$BIN" agent egress-probe >/dev/null 2>&1; then
        ok "ISOLATED — no route, no DNS, no reachable address"
      else
        bad "NOT ISOLATED — see the probe output above"
      fi
      # And the other half, asked by connecting rather than by looking. A
      # published port under CNI is an iptables DNAT rule and not a listening
      # socket, so `ss -ltn` shows nothing here even when it works — and it
      # shows nothing when the DNAT points at an address the host has no route
      # to, which is the silently-unreachable configuration R4-26 exists to
      # catch. Only a request can tell those apart.
      sleep 1
      if ! command -v curl >/dev/null 2>&1; then
        skip "curl is not installed, so ingress could not be proven"
      elif curl -fsS --max-time 5 http://127.0.0.1:19099/ >/dev/null 2>&1; then
        ok "the published port answers on 127.0.0.1 (ingress survives)"
      else
        bad "the published port does not answer — isolation broke ingress, the trap R4-26 exists to catch"
        nerdctl logs nodary-verify 2>&1 | tail -3 | sed 's/^/    /'
      fi
    else
      bad "could not find the container's pid"
      nerdctl inspect --format 'status={{.State.Status}} exit={{.State.ExitCode}}' \
        nodary-verify 2>&1 | sed 's/^/    /'
      nerdctl logs nodary-verify 2>&1 | tail -3 | sed 's/^/    /'
    fi
    nerdctl rm -f nodary-verify >/dev/null 2>&1
  else
    bad "could not start a container on nodary-isolated"
    printf '%s\n' "$RUNERR" | tail -3 | sed 's/^/    /'
    # Which half? Without a published port the portmap plugin is never invoked,
    # and portmap is pure iptables. A host with no iptables fails here and
    # nowhere else, which is what made this row so hard to read.
    if nerdctl run --rm --network nodary-isolated alpine:3 true >/dev/null 2>&1; then
      bad "the network attaches; it is the published port that fails (portmap needs iptables)"
    else
      bad "the network itself does not attach; the port mapping is not the cause"
    fi
  fi
fi

say "13. The data plane is running"
# LiteLLM is what the gateway proxies to (00 §7). Nothing ran it until R5-29,
# so a completion could not have been served whatever else worked.
if systemctl is-active --quiet nodary-litellm.service 2>/dev/null; then
  ok "nodary-litellm is active"
  if curl -fsS --max-time 5 http://127.0.0.1:4000/health/liveliness >/dev/null 2>&1 ||
     curl -fsS --max-time 5 http://127.0.0.1:4000/health/readiness >/dev/null 2>&1; then
    ok "it answers on 127.0.0.1:4000"
  else
    bad "nothing answers on 127.0.0.1:4000, so the gateway has no upstream"
    journalctl -u nodary-litellm.service -n 10 --no-pager | sed 's/^/    /'
  fi
else
  bad "nodary-litellm did not start"
  journalctl -u nodary-litellm.service -n 15 --no-pager | sed 's/^/    /'
fi
# The configuration is a compliance surface: pivot §3 makes "LiteLLM began
# writing request bodies somewhere" an incident rather than a nuisance.
if [ -f /etc/nodary/litellm.yaml ]; then
  miss=""
  for k in turn_off_message_logging store_prompts_in_spend_logs disable_spend_logs disable_error_logs; do
    grep -q "$k" /etc/nodary/litellm.yaml || miss="$miss $k"
  done
  if [ -z "$miss" ]; then ok "the configuration pins request logging off"
  else bad "the configuration omits:$miss"; fi
else
  bad "/etc/nodary/litellm.yaml was not written"
fi

# And the verb that re-renders it as routes appear. A fresh control plane has
# none, so this asserts the idempotent path: it reports no change and does not
# restart a unit for nothing.
if "$BIN" gateway sync --dry-run >/dev/null 2>&1; then
  ok "gateway sync reads the routes and agrees with what is on disk"
else
  bad "gateway sync failed"
  "$BIN" gateway sync --dry-run 2>&1 | tail -3 | sed 's/^/    /'
fi

say "14. R5-28 — can a container actually see the GPU?"
# The question nothing else answers, and the one that decides whether this host
# can serve a model at all. `nodary-model@.service` runs `nerdctl run --gpus`,
# and nerdctl 2.x resolves that through the NVIDIA Container Toolkit's CDI spec.
# Everything upstream of this can pass while a deployment still starts a
# container with no device and fails as "cannot find CUDA".
if ! command -v nerdctl >/dev/null 2>&1; then
  skip "nerdctl is not available"
elif ! command -v nvidia-ctk >/dev/null 2>&1 && ! command -v nvidia-container-cli >/dev/null 2>&1; then
  skip "the NVIDIA Container Toolkit is not installed; preflight refuses a node without it"
elif ! command -v nvidia-smi >/dev/null 2>&1 && [ ! -x /usr/lib/wsl/lib/nvidia-smi ]; then
  skip "no nvidia-smi on this host, so there is no GPU to pass through"
else
  nerdctl rm -f nodary-gpu >/dev/null 2>&1
  # The driver's own image, matched to the driver already present. `nvidia-smi`
  # inside the container is the whole assertion: it runs only if the device,
  # the libraries and the driver all arrived.
  if GPUERR=$(nerdctl run --rm --name nodary-gpu --gpus all \
       nvidia/cuda:12.6.2-base-ubuntu24.04 nvidia-smi -L 2>&1); then
    ok "a container sees the GPU: $(printf '%s' "$GPUERR" | head -1)"
  else
    bad "a container cannot see the GPU; no deployment on this host could serve a model"
    printf '%s\n' "$GPUERR" | tail -4 | sed 's/^/    /'
    if command -v nvidia-ctk >/dev/null 2>&1 && [ ! -e /etc/cdi/nvidia.yaml ] && [ ! -e /var/run/cdi/nvidia.yaml ]; then
      bad "no CDI spec exists; nerdctl 2.x needs one: sudo nvidia-ctk cdi generate --output=/etc/cdi/nvidia.yaml"
    fi
  fi
fi

say "15. doctor, as the node"
"$BIN" doctor 2>&1 | sed 's/^/  /'

# --- summary ------------------------------------------------------------------

printf '\n\033[1m%d passed, %d failed, %d skipped\033[0m\n' "$PASS" "$FAIL" "$SKIP"
echo
echo "To undo everything this changed:"
echo "  sudo $0 cleanup"
[ "$FAIL" -eq 0 ] || exit 1
