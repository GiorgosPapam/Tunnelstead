#!/usr/bin/env bash
# Tunnelstead installer: Ubuntu 22.04/24.04 LTS, Debian 12/13. Idempotent: safe to re-run.
# Usage: sudo bash installer/install.sh [--domain vpn.example.org] [--admin-user admin]
set -Eeuo pipefail
umask 027

PREFIX=/opt/tunnelstead      # application code (root-owned, read-only to the service)
ETC=/etc/tunnelstead         # secrets/config (root:tunnelstead 0750)
STATE=/var/lib/tunnelstead   # database, backups (tunnelstead)
SVC_USER=tunnelstead
SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DOMAIN=""; ADMIN_USER="admin"

c_ok=$'\e[32m'; c_err=$'\e[31m'; c_dim=$'\e[2m'; c_b=$'\e[1m'; c_0=$'\e[0m'
step() { printf '%s==>%s %s\n' "$c_b" "$c_0" "$*"; }
ok()   { printf '    %s✓%s %s\n' "$c_ok" "$c_0" "$*"; }
die()  { trap - ERR; printf '%s✗ %s%s\n' "$c_err" "$*" "$c_0" >&2; exit 1; }
trap 'die "Installation failed at line $LINENO. Nothing was removed; fix the error and re-run (the installer is safe to repeat)."' ERR

while [[ $# -gt 0 ]]; do
  case "$1" in
    --domain) DOMAIN="${2:?--domain needs a value}"; shift 2 ;;
    --admin-user) ADMIN_USER="${2:?--admin-user needs a value}"; shift 2 ;;
    -h|--help) sed -n '2,3p' "$0"; exit 0 ;;
    *) die "Unknown option: $1" ;;
  esac
done
# Re-runs and updates keep the original --domain (stored by the first install).
for conf in /etc/tunnelstead/install.conf /etc/vpnix-manager/install.conf /etc/vpnix-create/install.conf; do   # old names: being migrated
  if [[ -z "$DOMAIN" && -f "$conf" ]]; then DOMAIN="$(sed -n 's/^DOMAIN=//p' "$conf")"; fi
done
[[ "$ADMIN_USER" =~ ^[a-z0-9][a-z0-9._-]{2,63}$ ]] || die "--admin-user must be 3-64 lowercase letters, digits, . _ -"
[[ -z "$DOMAIN" || "$DOMAIN" =~ ^[A-Za-z0-9.-]{1,253}$ ]] || die "Invalid --domain"

# ---------- 1-4: environment checks ----------
step "Checking the system"
[[ $EUID -eq 0 ]] || die "Run as root (sudo)."
. /etc/os-release
case "$ID:${VERSION_ID:-}" in ubuntu:22.04|ubuntu:24.04|debian:12|debian:13) ok "OS: $PRETTY_NAME" ;;
  *) die "Unsupported OS: ${PRETTY_NAME:-unknown}. Supported: Ubuntu 22.04/24.04, Debian 12/13." ;; esac
ARCH="$(uname -m)"; case "$ARCH" in x86_64|aarch64) ok "Architecture: $ARCH" ;; *) die "Unsupported architecture $ARCH" ;; esac
KMAJ="$(uname -r | cut -d. -f1)"; KMIN="$(uname -r | cut -d. -f2)"
(( KMAJ > 5 || (KMAJ == 5 && KMIN >= 6) )) && ok "Kernel $(uname -r) (WireGuard built in)" || die "Kernel 5.6+ required for in-kernel WireGuard"
MEM_MB=$(( $(awk '/MemTotal/{print $2}' /proc/meminfo) / 1024 )); (( MEM_MB >= 900 )) || die "At least 1 GB RAM required"
DISK_MB=$(df -Pm / | awk 'NR==2{print $4}'); (( DISK_MB >= 1500 )) || die "At least 1.5 GB free disk required"
ok "Resources: ${MEM_MB} MB RAM, ${DISK_MB} MB free disk"
getent hosts deb.debian.org >/dev/null || getent hosts archive.ubuntu.com >/dev/null || die "No DNS / network connectivity"
ok "Network connectivity"

# ---------- 5-6: packages ----------
step "Installing packages"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq python3 python3-venv curl ca-certificates rsync nftables wireguard-tools openvpn caddy >/dev/null
systemctl disable --now openvpn.service >/dev/null 2>&1 || true   # VPN instances are started per instance, never by default
ok "python3, nftables, wireguard-tools, openvpn, caddy"

# ---------- migration from the earlier names: VPNix Create (1.x) and VPNix Manager → Tunnelstead ----------
MIGRATED_FROM=""
for OLD in vpnix-manager vpnix-create; do
  [[ -d "/opt/$OLD" && ! -d "$PREFIX" ]] || continue
  step "Migrating $OLD to Tunnelstead"
  systemctl disable --now "$OLD-api" "$OLD-helper" >/dev/null 2>&1 || true
  # Same user and group IDs under the new name, so every file keeps its owner.
  if id "$OLD" &>/dev/null && ! id "$SVC_USER" &>/dev/null; then
    usermod -l "$SVC_USER" -d "$STATE" "$OLD"
    if getent group "$OLD" >/dev/null; then groupmod -n "$SVC_USER" "$OLD"; fi
  fi
  for move in "/etc/$OLD:$ETC" "/var/lib/$OLD:$STATE" "/var/backups/$OLD:/var/backups/tunnelstead"; do
    if [[ -e "${move%%:*}" && ! -e "${move##*:}" ]]; then mv "${move%%:*}" "${move##*:}"; fi
  done
  if [[ -f "$ETC/$OLD.env" ]]; then mv "$ETC/$OLD.env" "$ETC/tunnelstead.env"; fi
  # Settings keep their values under the new names (VPNIX_* → TUNNELSTEAD_*), and the database file is renamed.
  sed -i -e "s#/var/lib/$OLD#$STATE#g" -e "s#/run/$OLD#/run/tunnelstead#g" -e 's/^VPNIX_/TUNNELSTEAD_/' \
         -e 's#/vpnix\.db#/tunnelstead.db#' "$ETC/tunnelstead.env"
  for ext in "" -wal -shm; do
    if [[ -e "$STATE/vpnix.db$ext" && ! -e "$STATE/tunnelstead.db$ext" ]]; then mv "$STATE/vpnix.db$ext" "$STATE/tunnelstead.db$ext"; fi
  done
  # The pre-update snapshot points at the old paths and can't be rolled back to across the rename.
  rm -f /var/backups/tunnelstead/snapshot.json /var/backups/tunnelstead/pre-update.db
  # VPN configs and the Caddyfile created under the old name keep being recognised as managed.
  for f in /etc/wireguard/wg*.conf /etc/openvpn/server/ovpn*.conf /etc/caddy/Caddyfile; do
    if [[ -f "$f" ]]; then sed -i -E 's/^# Managed by VPNix (Create|Manager)/# Managed by Tunnelstead/' "$f"; fi
  done
  if [[ -f "/etc/sysctl.d/90-$OLD.conf" ]]; then mv "/etc/sysctl.d/90-$OLD.conf" /etc/sysctl.d/90-tunnelstead.conf; fi
  rm -f "/etc/systemd/system/$OLD-api.service" "/etc/systemd/system/$OLD-helper.service" \
        "/etc/systemd/system/$OLD-updater@.service" "/etc/systemd/system/caddy.service.d/$OLD.conf" "/usr/local/sbin/$OLD-cli"
  rm -rf "/run/$OLD" "/run/$OLD-update.lock"
  systemctl daemon-reload
  MIGRATED_FROM="$OLD"
  ok "Data, settings and backups moved; VPN servers keep running"
done

# ---------- 7-10: application, user, directories, permissions ----------
step "Installing Tunnelstead"
id "$SVC_USER" &>/dev/null || useradd --system --home "$STATE" --shell /usr/sbin/nologin "$SVC_USER"
install -d -m 0755 "$PREFIX"
install -d -m 0750 -o root -g "$SVC_USER" "$ETC"
printf 'DOMAIN=%s\n' "$DOMAIN" > "$ETC/install.conf"; chmod 0640 "$ETC/install.conf"
install -d -m 0750 -o "$SVC_USER" -g "$SVC_USER" "$STATE" "$STATE/backups" "$STATE/updates"
rsync -a --delete --exclude .venv --exclude __pycache__ --exclude tests "$SRC/backend/" "$PREFIX/backend/"
install -m 0644 "$SRC/VERSION" "$PREFIX/VERSION"
install -d -m 0755 "$PREFIX/helper" && install -m 0644 "$SRC"/helper/{tunnelstead_helper,ovpn_ops}.py "$PREFIX/helper/"
[[ -d "$PREFIX/venv" ]] || python3 -m venv "$PREFIX/venv"
"$PREFIX/venv/bin/pip" install -q --upgrade pip
"$PREFIX/venv/bin/pip" install -q --require-virtualenv -r "$PREFIX/backend/requirements.txt"
if [[ -d "$SRC/frontend/dist" ]]; then rsync -a --delete "$SRC/frontend/dist/" "$PREFIX/web/"; else die "frontend/dist missing (use a release bundle or run npm run build)"; fi
# Code is not secret: root-owned, world-readable, never writable by the service (secrets live in $ETC)
# The installer itself is kept in $PREFIX so an update can be rolled back to exactly this version.
rsync -a --delete "$SRC/installer/" "$PREFIX/installer/"
install -d -m 0755 "$PREFIX/updater" && install -m 0644 "$SRC/updater/updater.py" "$PREFIX/updater/"
install -m 0644 "$SRC/installer/release-key.pub" "$PREFIX/release-key.pub"
chown -R root:root "$PREFIX"; chmod -R u=rwX,go=rX "$PREFIX"
chmod 0755 "$PREFIX"/installer/*.sh
cat > /usr/local/sbin/tunnelstead-cli <<'WRAP'
#!/usr/bin/env bash
# Root-only administration CLI (runs as the service account with the service configuration).
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "Run as root" >&2; exit 1; }
set -a; . /etc/tunnelstead/tunnelstead.env; set +a
cd /opt/tunnelstead/backend && exec runuser -u tunnelstead -- /opt/tunnelstead/venv/bin/python -m tunnelstead.cli "$@"
WRAP
chmod 0750 /usr/local/sbin/tunnelstead-cli
ok "Application in $PREFIX, data in $STATE"

# ---------- 13-14: configuration, database, administrator ----------
step "Configuring"
if [[ ! -f "$ETC/tunnelstead.env" ]]; then
  KEY="$("$PREFIX/venv/bin/python" -c 'import base64,os;print(base64.urlsafe_b64encode(os.urandom(32)).decode().rstrip("="))')"
  cat > "$ETC/tunnelstead.env" <<ENV
TUNNELSTEAD_SECRET_KEY=$KEY
TUNNELSTEAD_DATABASE_URL=sqlite:///$STATE/tunnelstead.db
TUNNELSTEAD_COOKIE_SECURE=true
ENV
  chown root:"$SVC_USER" "$ETC/tunnelstead.env"; chmod 0640 "$ETC/tunnelstead.env"
  ok "Generated encryption key ($ETC/tunnelstead.env, readable only by root and the service)"
else
  ok "Existing configuration kept"
fi
cli() { (set -a; . "$ETC/tunnelstead.env"; set +a; cd "$PREFIX/backend" && runuser -u "$SVC_USER" -- "$PREFIX/venv/bin/python" -m tunnelstead.cli "$@"); }
systemctl stop tunnelstead-api 2>/dev/null || true   # migrations need exclusive access
cli migrate >/dev/null && ok "Database schema up to date"
ADMIN_OUT="$(cli init-admin --username "$ADMIN_USER")"
ADMIN_PW="$(sed -n 's/^TUNNELSTEAD_ADMIN_PASSWORD=//p' <<<"$ADMIN_OUT")"

# ---------- 11-12: services and web server ----------
step "Starting services"
install -m 0644 "$SRC"/installer/systemd/tunnelstead-{api,helper}.service "$SRC"/installer/systemd/tunnelstead-updater@.service /etc/systemd/system/
install -d -m 0700 /var/backups/tunnelstead
systemctl daemon-reload
systemctl enable tunnelstead-helper tunnelstead-api >/dev/null 2>&1
systemctl restart tunnelstead-helper tunnelstead-api   # pick up new code on re-runs
for _ in $(seq 10); do [[ -S /run/tunnelstead/helper.sock ]] && break; sleep 1; done
[[ -S /run/tunnelstead/helper.sock ]] || die "Privileged helper did not start: journalctl -u tunnelstead-helper"
ok "Privileged helper running (socket 0660 root:$SVC_USER)"
SITE="${DOMAIN:-$(ip -4 route get 1.1.1.1 | awk '{for(i=1;i<NF;i++) if($i=="src") print $(i+1)}')}"
TLS_LINE=$([[ -n "$DOMAIN" ]] && echo "" || echo "tls internal")
if [[ -f /etc/caddy/Caddyfile ]] && ! grep -q "Managed by Tunnelstead" /etc/caddy/Caddyfile && [[ -s /etc/caddy/Caddyfile ]] \
   && ! grep -q "^:80" /etc/caddy/Caddyfile; then
  die "/etc/caddy/Caddyfile has your own configuration. It was not changed; add Tunnelstead manually (see docs/INSTALL.md)."
fi
# Caddy's admin API must not be reachable by other local users (it can rewrite the web server's config):
# move it from TCP 127.0.0.1:2019 to a socket in a directory only the caddy user can enter.
install -d -m 0755 /etc/systemd/system/caddy.service.d
cat > /etc/systemd/system/caddy.service.d/tunnelstead.conf <<'DROPIN'
# Managed by Tunnelstead installer
[Service]
RuntimeDirectory=caddy
RuntimeDirectoryMode=0700
DROPIN
systemctl daemon-reload
cat > /etc/caddy/Caddyfile <<CADDY
# Managed by Tunnelstead installer. Port 80 redirects to HTTPS.
{
	admin unix//run/caddy/admin.sock
}
$SITE {
	$TLS_LINE
	encode gzip
	header {
		-Server
		Content-Security-Policy "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'; object-src 'none'"
		Strict-Transport-Security "max-age=63072000; includeSubDomains"
		X-Content-Type-Options nosniff
		X-Frame-Options DENY
		Referrer-Policy no-referrer
		Permissions-Policy "camera=(), microphone=(), geolocation=(), payment=()"
		Cross-Origin-Opener-Policy same-origin
	}
	handle /api/* {
		reverse_proxy 127.0.0.1:8090
	}
	handle {
		root * $PREFIX/web
		try_files {path} /index.html
		file_server
	}
}
CADDY
caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile >/dev/null 2>&1 || die "Generated Caddyfile is invalid"
systemctl enable caddy >/dev/null 2>&1
# Reload when the running Caddy already uses the socket; otherwise (first run, admin address change) restart.
if [[ -S /run/caddy/admin.sock ]]; then systemctl reload caddy || systemctl restart caddy; else systemctl restart caddy; fi
ok "HTTPS on $SITE ($([[ -n "$DOMAIN" ]] && echo "Let's Encrypt" || echo "local CA: browsers warn once"))"

# ---------- 15: health ----------
for _ in $(seq 30); do curl -fsS http://127.0.0.1:8090/api/health >/dev/null 2>&1 && break; sleep 1; done
curl -fsS http://127.0.0.1:8090/api/health >/dev/null || die "The API did not become healthy: journalctl -u tunnelstead-api"
ok "API healthy"
if [[ -n "$MIGRATED_FROM" ]]; then
  # Redeploy every VPN server and the firewall under the new names, then remove what the old version left behind.
  cli resync >/dev/null || die "Migrated, but redeploying the VPN servers failed: run 'sudo tunnelstead-cli resync'"
  nft delete table inet "${MIGRATED_FROM//-/_}" 2>/dev/null || true
  rm -rf "/opt/$MIGRATED_FROM" "/opt/$MIGRATED_FROM.prev"
  ok "VPN servers and firewall redeployed as Tunnelstead"
fi

# ---------- 16: results ----------
printf '\n%s Tunnelstead is installed.%s\n\n' "$c_ok$c_b" "$c_0"
printf '  Open:      https://%s/\n' "$SITE"
if [[ -n "$ADMIN_PW" ]]; then
  printf '  Username:  %s\n  Password:  %s%s%s\n\n' "$ADMIN_USER" "$c_b" "$ADMIN_PW" "$c_0"
  printf '  %sThis temporary password is shown only now and must be changed at first sign-in.%s\n' "$c_dim" "$c_0"
  printf '  %sLost it? Run: sudo tunnelstead-cli reset-admin --username %s%s\n\n' "$c_dim" "$ADMIN_USER" "$c_0"
else
  printf '  An administrator already exists; existing credentials were kept.\n\n'
fi
printf '  Allow TCP 80/443 in your provider firewall. VPN ports are opened when you create VPN instances.\n'
