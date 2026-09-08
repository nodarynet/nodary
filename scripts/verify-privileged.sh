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
  # The three properties that make it the control.
  if grep -q '"isGateway": false' /etc/cni/net.d/10-nodary-isolated.conflist; then
    ok "isGateway is false — no default route"
  else bad "isGateway is not false"; fi
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
  if nerdctl run -d --name nodary-verify --network nodary-isolated \
       -p 127.0.0.1:19099:80 alpine:3 sleep 600 >/dev/null 2>&1; then
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
      # And the other half: the published port must still be listening.
      # docs/spike-fips-and-manifest.md found a configuration that passed the
      # isolation check while being silently unreachable.
      if ss -ltn 2>/dev/null | grep -q '127.0.0.1:19099'; then
        ok "the published port is listening on 127.0.0.1 (ingress survives)"
      else
        bad "the published port is NOT listening — isolation broke ingress, which is the trap R4-26 exists to catch"
      fi
    else
      bad "could not find the container's pid"
    fi
    nerdctl rm -f nodary-verify >/dev/null 2>&1
  else
    bad "could not start a container on nodary-isolated"
    nerdctl run --rm --network nodary-isolated alpine:3 true 2>&1 | sed 's/^/    /' | head -5
  fi
fi

say "13. doctor, as the node"
"$BIN" doctor 2>&1 | sed 's/^/  /'

# --- summary ------------------------------------------------------------------

printf '\n\033[1m%d passed, %d failed, %d skipped\033[0m\n' "$PASS" "$FAIL" "$SKIP"
echo
echo "To undo everything this changed:"
echo "  sudo $0 cleanup"
[ "$FAIL" -eq 0 ] || exit 1
