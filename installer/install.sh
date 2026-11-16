#!/usr/bin/env bash
# VPNix Create installer: Ubuntu 22.04/24.04 LTS, Debian 12/13. Idempotent: safe to re-run.
# Usage: sudo bash installer/install.sh [--domain vpn.example.org] [--admin-user admin]
set -Eeuo pipefail
umask 027

PREFIX=/opt/vpnix-create      # application code (root-owned, read-only to the service)
ETC=/etc/vpnix-create         # secrets/config (root:vpnix-create 0750)
STATE=/var/lib/vpnix-create   # database, backups (vpnix-create)
SVC_USER=vpnix-create
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

# ---------- 7-10: application, user, directories, permissions ----------
step "Installing VPNix Create"
id "$SVC_USER" &>/dev/null || useradd --system --home "$STATE" --shell /usr/sbin/nologin "$SVC_USER"
install -d -m 0755 "$PREFIX"
install -d -m 0750 -o root -g "$SVC_USER" "$ETC"
install -d -m 0750 -o "$SVC_USER" -g "$SVC_USER" "$STATE" "$STATE/backups"
rsync -a --delete --exclude .venv --exclude __pycache__ --exclude tests "$SRC/backend/" "$PREFIX/backend/"
install -m 0644 "$SRC/VERSION" "$PREFIX/VERSION"
install -d -m 0755 "$PREFIX/helper" && install -m 0644 "$SRC/helper/vpnix_create_helper.py" "$PREFIX/helper/"
[[ -d "$PREFIX/venv" ]] || python3 -m venv "$PREFIX/venv"
"$PREFIX/venv/bin/pip" install -q --upgrade pip
"$PREFIX/venv/bin/pip" install -q --require-virtualenv -r "$PREFIX/backend/requirements.txt"
if [[ -d "$SRC/frontend/dist" ]]; then rsync -a --delete "$SRC/frontend/dist/" "$PREFIX/web/"; else die "frontend/dist missing (use a release bundle or run npm run build)"; fi
# Code is not secret: root-owned, world-readable, never writable by the service (secrets live in $ETC)
chown -R root:root "$PREFIX"; chmod -R u=rwX,go=rX "$PREFIX"
cat > /usr/local/sbin/vpnix-create-cli <<'WRAP'
#!/usr/bin/env bash
# Root-only administration CLI (runs as the service account with the service configuration).
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "Run as root" >&2; exit 1; }
set -a; . /etc/vpnix-create/vpnix-create.env; set +a
cd /opt/vpnix-create/backend && exec runuser -u vpnix-create -- /opt/vpnix-create/venv/bin/python -m vpnix_create.cli "$@"
WRAP
chmod 0750 /usr/local/sbin/vpnix-create-cli
ok "Application in $PREFIX, data in $STATE"

# ---------- 13-14: configuration, database, administrator ----------
step "Configuring"
if [[ ! -f "$ETC/vpnix-create.env" ]]; then
  KEY="$("$PREFIX/venv/bin/python" -c 'import base64,os;print(base64.urlsafe_b64encode(os.urandom(32)).decode().rstrip("="))')"
  cat > "$ETC/vpnix-create.env" <<ENV
VPNIX_SECRET_KEY=$KEY
VPNIX_DATABASE_URL=sqlite:///$STATE/vpnix.db
VPNIX_COOKIE_SECURE=true
ENV
  chown root:"$SVC_USER" "$ETC/vpnix-create.env"; chmod 0640 "$ETC/vpnix-create.env"
  ok "Generated encryption key ($ETC/vpnix-create.env, readable only by root and the service)"
else
  ok "Existing configuration kept"
fi
cli() { (set -a; . "$ETC/vpnix-create.env"; set +a; cd "$PREFIX/backend" && runuser -u "$SVC_USER" -- "$PREFIX/venv/bin/python" -m vpnix_create.cli "$@"); }
systemctl stop vpnix-create-api 2>/dev/null || true   # migrations need exclusive access
cli migrate >/dev/null && ok "Database schema up to date"
ADMIN_OUT="$(cli init-admin --username "$ADMIN_USER")"
ADMIN_PW="$(sed -n 's/^VPNIX_ADMIN_PASSWORD=//p' <<<"$ADMIN_OUT")"

# ---------- 11-12: services and web server ----------
step "Starting services"
install -m 0644 "$SRC"/installer/systemd/vpnix-create-{api,helper}.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable vpnix-create-helper vpnix-create-api >/dev/null 2>&1
systemctl restart vpnix-create-helper vpnix-create-api   # pick up new code on re-runs
for _ in $(seq 10); do [[ -S /run/vpnix-create/helper.sock ]] && break; sleep 1; done
[[ -S /run/vpnix-create/helper.sock ]] || die "Privileged helper did not start: journalctl -u vpnix-create-helper"
ok "Privileged helper running (socket 0660 root:$SVC_USER)"
SITE="${DOMAIN:-$(ip -4 route get 1.1.1.1 | awk '{for(i=1;i<NF;i++) if($i=="src") print $(i+1)}')}"
TLS_LINE=$([[ -n "$DOMAIN" ]] && echo "" || echo "tls internal")
if [[ -f /etc/caddy/Caddyfile ]] && ! grep -q "Managed by VPNix Create" /etc/caddy/Caddyfile && [[ -s /etc/caddy/Caddyfile ]] \
   && ! grep -q "^:80" /etc/caddy/Caddyfile; then
  die "/etc/caddy/Caddyfile has your own configuration. It was not changed; add VPNix Create manually (see docs/INSTALL.md)."
fi
cat > /etc/caddy/Caddyfile <<CADDY
# Managed by VPNix Create installer. Port 80 redirects to HTTPS.
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
systemctl enable caddy >/dev/null 2>&1; systemctl reload-or-restart caddy
ok "HTTPS on $SITE ($([[ -n "$DOMAIN" ]] && echo "Let's Encrypt" || echo "local CA: browsers warn once"))"

# ---------- 15: health ----------
for _ in $(seq 30); do curl -fsS http://127.0.0.1:8090/api/health >/dev/null 2>&1 && break; sleep 1; done
curl -fsS http://127.0.0.1:8090/api/health >/dev/null || die "The API did not become healthy: journalctl -u vpnix-create-api"
ok "API healthy"

# ---------- 16: results ----------
printf '\n%s VPNix Create is installed.%s\n\n' "$c_ok$c_b" "$c_0"
printf '  Open:      https://%s/\n' "$SITE"
if [[ -n "$ADMIN_PW" ]]; then
  printf '  Username:  %s\n  Password:  %s%s%s\n\n' "$ADMIN_USER" "$c_b" "$ADMIN_PW" "$c_0"
  printf '  %sThis temporary password is shown only now and must be changed at first sign-in.%s\n' "$c_dim" "$c_0"
  printf '  %sLost it? Run: sudo vpnix-create-cli reset-admin --username %s%s\n\n' "$c_dim" "$ADMIN_USER" "$c_0"
else
  printf '  An administrator already exists; existing credentials were kept.\n\n'
fi
printf '  Allow TCP 80/443 in your provider firewall. VPN ports are opened when you create VPN instances.\n'
