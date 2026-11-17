#!/usr/bin/env bash
# Update VPNix Manager from the command line (the dashboard's Updates page does the same).
# Usage: sudo update.sh vpnix-manager-X.Y.Z.tar.gz   (the .sig file must be next to it)
#        sudo update.sh --rollback                 (back to the version before the last update, incl. its data)
#        sudo update.sh --status
# Only bundles signed with the VPNix Manager release key and newer than the installed version are accepted.
set -Eeuo pipefail
[[ $EUID -eq 0 ]] || { echo "Run as root (sudo)" >&2; exit 1; }
DL=/var/lib/vpnix-manager/updates
show() { python3 -c 'import json,sys; s=json.load(open(sys.argv[1])); print("\n".join(s.get("log",[]))); print("State:", s["state"], s.get("error",""))' "$DL/status.json"; }
case "${1:-}" in
  ""|-h|--help) sed -n '2,6p' "$0"; exit 0 ;;
  --status) show; exit 0 ;;
  --rollback) systemctl start vpnix-manager-updater@rollback.service || true; show; exit 0 ;;
esac
B="$(realpath -e "$1")"; N="$(basename "$B")"
[[ "$N" =~ ^vpnix-manager-([0-9]{1,4}\.[0-9]{1,4}\.[0-9]{1,4})\.tar\.gz$ ]] || { echo "Expected vpnix-manager-X.Y.Z.tar.gz" >&2; exit 2; }
V="${BASH_REMATCH[1]}"
[[ -f "$B.sig" ]] || { echo "Missing $B.sig" >&2; exit 2; }
install -d -m 0750 -o vpnix-manager -g vpnix-manager "$DL"
install -m 0640 -o vpnix-manager -g vpnix-manager "$B" "$B.sig" "$DL/"
systemctl reset-failed "vpnix-manager-updater@install-$V.service" 2>/dev/null || true
systemctl start "vpnix-manager-updater@install-$V.service" || true
show
