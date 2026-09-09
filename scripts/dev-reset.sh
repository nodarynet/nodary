#!/usr/bin/env bash
# dev-reset.sh — tear a nodary install off this box, back to bare metal.
#
# THIS IS NOT `nodary uninstall`. That verb is unbuilt (R2-38/R5), and when it
# lands it will be careful: prompted, `--purge`/`--purge-models` opt-in,
# recorded. This is the opposite of careful — it is for a developer who wants
# to run the install from zero again and does not care what it destroys. Never
# point it at a machine anyone depends on.
#
# What it leaves alone: containerd, runc, the CNI plugin binaries, nerdctl —
# the shared runtime `server install`/`node install` place idempotently and
# would simply find "already exists" on the next run. What it removes:
# everything nodary itself owns — the units, the database, the audit chain,
# every secret, the isolated network, the service account, the binary.
#
# Usage: sudo ./scripts/dev-reset.sh
set -eu

if [ "$(id -u)" -ne 0 ]; then
  printf 'run as root: sudo %s\n' "$0" >&2
  exit 1
fi

echo "== stopping units =="
systemctl stop nodary-agent nodary-server nodary-gateway nodary-litellm 2>/dev/null || true
# nodary-model@*.service: whatever deployments exist, by name, since a glob
# stop needs the instances listed rather than guessed.
systemctl list-units 'nodary-model@*' --all --no-legend 2>/dev/null \
  | awk '{print $1}' | xargs -r systemctl stop || true
systemctl disable nodary-agent nodary-server nodary-gateway nodary-litellm 2>/dev/null || true

echo "== removing containers =="
nerdctl rm -f nodary-litellm 2>/dev/null || true
nerdctl ps -a --format '{{.Names}}' 2>/dev/null | grep '^nodary-' | xargs -r nerdctl rm -f || true

echo "== removing the isolated network =="
nft delete table inet nodary 2>/dev/null || true
ip link delete nodary0 2>/dev/null || true
rm -f /etc/cni/net.d/10-nodary-isolated.conflist

echo "== removing unit files =="
rm -f /etc/systemd/system/nodary-*.service
systemctl daemon-reload

echo "== removing state =="
rm -rf /etc/nodary /var/lib/nodary /var/log/nodary /opt/nodary
rm -f /usr/local/bin/nodary

echo "== removing the service account =="
userdel nodary 2>/dev/null || true
groupdel nodary 2>/dev/null || true

echo "== done. containerd, runc, CNI plugins and nerdctl are untouched. =="
