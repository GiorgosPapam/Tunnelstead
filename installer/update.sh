#!/usr/bin/env bash
# Update Tunnelstead from the command line (the dashboard's Updates page does the same).
# Usage: sudo update.sh tunnelstead-X.Y.Z.tar.gz   (the .sig file must be next to it)
#        sudo update.sh --rollback                 (back to the version before the last update, incl. its data)
#        sudo update.sh --status
# Only bundles signed with the Tunnelstead release key and newer than the installed version are accepted.
set -Eeuo pipefail
[[ $EUID -eq 0 ]] || { echo "Run as root (sudo)" >&2; exit 1; }
DL=/var/lib/tunnelstead/updates
show() { python3 -c 'import json,sys; s=json.load(open(sys.argv[1])); print("\n".join(s.get("log",[]))); print("State:", s["state"], s.get("error",""))' "$DL/status.json"; }
case "${1:-}" in
  ""|-h|--help) sed -n '2,6p' "$0"; exit 0 ;;
  --status) show; exit 0 ;;
  --rollback) systemctl start tunnelstead-updater@rollback.service || true; show; exit 0 ;;
esac
B="$(realpath -e "$1")"; N="$(basename "$B")"
[[ "$N" =~ ^tunnelstead-([0-9]{1,4}\.[0-9]{1,4}\.[0-9]{1,4})\.tar\.gz$ ]] || { echo "Expected tunnelstead-X.Y.Z.tar.gz" >&2; exit 2; }
V="${BASH_REMATCH[1]}"
[[ -f "$B.sig" ]] || { echo "Missing $B.sig" >&2; exit 2; }
install -d -m 0750 -o tunnelstead -g tunnelstead "$DL"
install -m 0640 -o tunnelstead -g tunnelstead "$B" "$B.sig" "$DL/"
systemctl reset-failed "tunnelstead-updater@install-$V.service" 2>/dev/null || true
systemctl start "tunnelstead-updater@install-$V.service" || true
show
