#!/usr/bin/env bash
# Remove Tunnelstead from this server.
# Usage: sudo uninstall.sh [--purge] [--yes] [--dry-run]
#   default   removes the application, its services, its VPN servers and its firewall table; KEEPS the database
#             and backups in /var/lib/tunnelstead so you can reinstall and restore later
#   --purge   also deletes the database, all backups and the configuration (cannot be undone)
#   --dry-run only lists what would be removed
# Only things Tunnelstead created are removed: WireGuard/OpenVPN configs without its marker, other nftables tables,
# your own Caddy configuration, wireguard-tools, openvpn and caddy packages are left alone.
set -Eeuo pipefail
[[ $EUID -eq 0 ]] || { echo "Run as root (sudo)" >&2; exit 1; }
PURGE=0 YES=0 DRY=0
for a in "$@"; do case "$a" in --purge) PURGE=1 ;; --yes) YES=1 ;; --dry-run) DRY=1 ;; -h|--help) sed -n '2,10p' "$0"; exit 0 ;;
  *) echo "Unknown option: $a" >&2; exit 2 ;; esac; done
MARK="# Managed by Tunnelstead"
do_() { if ((DRY)); then echo "  would run: $*"; else "$@"; fi; }

managed=()
for f in /etc/wireguard/wg*.conf /etc/openvpn/server/ovpn*.conf; do
  [[ -f "$f" ]] && head -n1 "$f" | grep -q "^$MARK" && managed+=("$f")
done
echo "Tunnelstead will be removed from this server:"
echo "  services tunnelstead-api, tunnelstead-helper, updater; /opt/tunnelstead; the 'inet tunnelstead' firewall table"
echo "  VPN servers it created: ${managed[*]:-none}"
((PURGE)) && echo "  AND all data: /var/lib/tunnelstead (database, backups), /etc/tunnelstead, /var/backups/tunnelstead" \
          || echo "  Kept: /var/lib/tunnelstead (database and backups), /etc/tunnelstead (secret key needed to read them)"
if ((!YES && !DRY)); then read -r -p "Type 'uninstall' to continue: " ans; [[ "$ans" == uninstall ]] || { echo "Cancelled."; exit 1; }; fi

for f in "${managed[@]}"; do
  n="$(basename "$f" .conf)"
  if [[ "$f" == /etc/wireguard/* ]]; then u="wg-quick@$n"; else u="openvpn-server@$n"; fi
  do_ systemctl disable --now "$u" 2>/dev/null || true
  do_ rm -f "$f"
  [[ -d "/etc/openvpn/server/$n" ]] && do_ rm -rf "/etc/openvpn/server/$n"
done
do_ systemctl disable --now tunnelstead-api tunnelstead-helper 2>/dev/null || true
do_ nft delete table inet tunnelstead 2>/dev/null || true
do_ rm -f /etc/systemd/system/tunnelstead-api.service /etc/systemd/system/tunnelstead-helper.service \
          /etc/systemd/system/tunnelstead-updater@.service /etc/sysctl.d/90-tunnelstead.conf /usr/local/sbin/tunnelstead-cli
if [[ -f /etc/caddy/Caddyfile ]] && grep -q "Managed by Tunnelstead" /etc/caddy/Caddyfile; then
  do_ rm -f /etc/caddy/Caddyfile /etc/systemd/system/caddy.service.d/tunnelstead.conf
  do_ systemctl daemon-reload; do_ systemctl stop caddy || true
fi
do_ systemctl daemon-reload
do_ rm -rf /opt/tunnelstead /opt/tunnelstead.prev
if ((PURGE)); then
  do_ rm -rf /var/lib/tunnelstead /etc/tunnelstead /var/backups/tunnelstead
  id tunnelstead >/dev/null 2>&1 && do_ userdel tunnelstead
fi
((DRY)) && echo "Dry run: nothing was changed." || echo "Tunnelstead was removed.$( ((PURGE)) || echo " Your data is kept in /var/lib/tunnelstead.")"
