# Installing VPNix Manager

## Requirements

- Ubuntu 22.04 / 24.04 LTS or Debian 12 / 13, 64-bit (x86_64 or arm64). Fully tested on Ubuntu 24.04 x86_64; the
  other combinations are supported by the installer but not yet covered by the real-system tests
- 1 CPU, 1 GB RAM, 2 GB free disk (more for many clients and long metric history)
- root access (SSH), a public IP address, and optionally a domain name pointing to it
- a server you control. The installer does not touch your own WireGuard/OpenVPN configurations, nftables tables
  or Caddy configuration, but a fresh server is the simplest and safest start.

The installer adds these packages if missing: `python3`, `python3-venv`, `curl`, `ca-certificates`, `rsync`,
`nftables`, `wireguard-tools`, `openvpn`, `caddy`.

## 1. Download and verify the release

Download `vpnix-manager-X.Y.Z.tar.gz` and `vpnix-manager-X.Y.Z.tar.gz.sig` from the project's GitHub releases page.
Each release is signed with the project's Ed25519 key, so check the signature before you install. The public key
is the one in `installer/release-key.pub` of the official repository:

```bash
python3 - X.Y.Z <<'EOF'
import base64, hashlib, sys
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
v = sys.argv[1]; b = open(f"vpnix-manager-{v}.tar.gz", "rb").read()
key = Ed25519PublicKey.from_public_bytes(base64.b64decode("PASTE-THE-PUBLIC-KEY-HERE"))
key.verify(base64.b64decode(open(f"vpnix-manager-{v}.tar.gz.sig").read()), f"vpnix-manager-release:{v}:{hashlib.sha256(b).hexdigest()}".encode())
print("Signature OK")
EOF
```

(`python3-cryptography` is in the standard Ubuntu/Debian repositories.) If the check fails, **do not install**.

## 2. Install

```bash
tar -xzf vpnix-manager-X.Y.Z.tar.gz && cd vpnix-manager-X.Y.Z
sudo bash installer/install.sh                            # no domain: HTTPS with a local certificate
sudo bash installer/install.sh --domain vpn.example.org   # with a domain: free Let's Encrypt certificate
```

Options: `--domain NAME` (remembered for later re-runs and updates), `--admin-user NAME` (default `admin`).
The installer is idempotent: running it again repairs or updates an installation and never deletes data.

At the end it prints the dashboard address and a **one-time administrator password**. It is shown only once and
never stored. You have to change it at the first sign-in. If you lose it before signing in:
`sudo vpnix-manager-cli reset-admin --username admin`.

## 3. Open the ports

In your cloud provider's firewall (Hetzner, AWS, DigitalOcean…), allow:

| Port | For |
|---|---|
| TCP 80, TCP 443 | the dashboard (80 only redirects to HTTPS and is used for Let's Encrypt) |
| TCP 22 | SSH, as before |
| the port of each VPN server | shown in the wizard, e.g. UDP 51820 (WireGuard), UDP/TCP 1194 (OpenVPN) |

On the server itself, VPNix Manager opens its VPN ports automatically in its own nftables table.

Without a domain the browser warns once about the local certificate. That's expected: the connection is encrypted
with a certificate made on your server. With `--domain` you get a normal trusted certificate.

## 4. First steps

1. Sign in and choose your own password. Turn on two-factor authentication under **Settings → Account & security**.
2. **VPN Servers → New VPN instance**: the wizard suggests free ports, interface names and subnets.
3. Open the server and add clients. WireGuard clients can scan a QR code; OpenVPN clients download a `.ovpn` file.
4. Under **Settings → Backups**, create a backup and turn on daily backups. Keep a downloaded copy somewhere safe.

## What gets installed where

| Path | Contents | Owner |
|---|---|---|
| `/opt/vpnix-manager` | application, web UI, installer scripts, release public key | root, read-only for the service |
| `/etc/vpnix-manager` | `vpnix-manager.env` (database URL, **secret key**), `install.conf` | root:vpnix-manager 0750 |
| `/var/lib/vpnix-manager` | database, `backups/`, `updates/` | vpnix-manager 0750 |
| `/var/backups/vpnix-manager` | pre-update snapshot of the database | root 0700 |
| `/etc/wireguard/wgN.conf`, `/etc/openvpn/server/ovpnN*` | VPN servers created by VPNix Manager (marked as managed) | root |
| services | `vpnix-manager-api`, `vpnix-manager-helper`, `vpnix-manager-updater@`, plus `caddy` | |

## Upgrading from VPNix Create 1.0.0

VPNix Manager was called VPNix Create until version 1.0.0. A 1.0.0 installation doesn't see 2.x releases (the
release files were renamed), so upgrade once by hand with the 2.0.0 bundle:

```bash
tar -xzf vpnix-manager-2.0.0.tar.gz && cd vpnix-manager-2.0.0
sudo bash installer/install.sh
```

The installer finds the 1.0.0 installation and migrates it in place:
- **kept:** users, VPN servers, clients, keys, firewall rules, settings, backups and the saved domain;
- **renamed:** services, folders, the CLI and the firewall table.

Your VPN servers keep running, and clients don't need new configurations. From then on, updates work from the
dashboard again. A rollback to 1.0.0 isn't possible after migrating, so take a backup first.

## Uninstalling

```bash
sudo /opt/vpnix-manager/installer/uninstall.sh --dry-run   # list what would be removed
sudo /opt/vpnix-manager/installer/uninstall.sh             # remove; keeps the database and backups
sudo /opt/vpnix-manager/installer/uninstall.sh --purge     # remove everything, including all data
```

Uninstalling stops and deletes the VPN servers VPNix Manager created. Your own WireGuard/OpenVPN configurations,
other firewall tables and the installed packages are left alone.

## Using your own Caddy configuration

If `/etc/caddy/Caddyfile` already has your own sites, the installer stops without changing it. Add a site that
serves `/opt/vpnix-manager/web` and proxies `/api/*` to `127.0.0.1:8090`, with the security headers from
`installer/install.sh`, then re-run the installer.
