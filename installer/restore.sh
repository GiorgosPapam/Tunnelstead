#!/usr/bin/env bash
# Restore an encrypted VPNix Create backup (.vbk), on this server or on a fresh install on a new server.
# Usage: sudo restore.sh FILE [--yes]
# A safety backup of the current data is made first. All VPN servers, clients and the firewall are then
# redeployed to match the backup.
set -Eeuo pipefail
[[ $EUID -eq 0 ]] || { echo "Run as root (sudo)" >&2; exit 1; }
[[ $# -ge 1 && "$1" != -h && "$1" != --help ]] || { sed -n '2,5p' "$0"; exit 0; }
FILE="$(realpath -e "$1")"; shift
ENV=/etc/vpnix-create/vpnix-create.env STATE=/var/lib/vpnix-create APP=/opt/vpnix-create

systemctl stop vpnix-create-api
trap 'chown -R vpnix-create:vpnix-create "$STATE"; chown root:vpnix-create "$ENV"; chmod 0640 "$ENV"; systemctl start vpnix-create-api' EXIT
# Runs as root: adopting the backup's secret key means rewriting the root-owned configuration.
(set -a; . "$ENV"; set +a; cd "$APP/backend" && "$APP/venv/bin/python" -m vpnix_create.cli restore "$FILE" "$@")
chown -R vpnix-create:vpnix-create "$STATE"; chown root:vpnix-create "$ENV"; chmod 0640 "$ENV"
systemctl start vpnix-create-api; trap - EXIT
for _ in $(seq 30); do curl -fsS http://127.0.0.1:8090/api/health >/dev/null 2>&1 && break; sleep 1; done
vpnix-create-cli resync
echo "Restore complete. Sign in with the accounts from the backup."
