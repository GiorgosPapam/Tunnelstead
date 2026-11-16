<p align="center"><img src="branding/vpnix-create-logo.svg" alt="VPNix Create" width="360"></p>

**VPNix Create** is a self-hosted dashboard for running your own VPN servers. It sets up and manages
**WireGuard** and **OpenVPN** on a Linux server, with as many servers and clients as you need, from a modern web
interface. No cloud account and no third-party service are involved: everything runs on your server.

## Features

- **VPN servers:** any number of WireGuard and OpenVPN (UDP or TCP) servers side by side. A 10-step wizard detects
  port, interface and subnet conflicts and suggests free values. IPv4 and IPv6, full or split tunnel, NAT.
- **Clients:** QR codes and config downloads, expiry dates, data limits, enable/disable, key regeneration. You can see
  who is online, when they last connected and how much they used.
- **Firewall:** your own allow/block rules and dashboard access restriction. Every change is undone after 60 seconds
  unless you keep it, so a mistake can't lock you out. Only VPNix Create's own nftables table is ever touched.
- **Monitoring and logs:** CPU, memory, disk, traffic and clients online over 30 days; per-server throughput and
  availability; service logs; a tamper-evident audit log.
- **Alerts:** webhook (Slack, Discord, Teams, ntfy…) and e-mail when a server goes down, a certificate expires, a
  client is blocked, an account is locked, a backup fails or an update is available.
- **Backups:** encrypted (Argon2id + AES-256-GCM), manual or daily, restore with preview and a safety copy, move to
  a new server with `restore.sh`.
- **Updates:** signed releases only (Ed25519), snapshot before every update, health check, automatic rollback,
  downgrade protection, optional automatic install in a maintenance window.
- **Accounts:** administrator, operator and viewer roles; Argon2id passwords, mandatory password change on first
  sign-in, two-factor authentication (TOTP) with recovery codes, account lockout.

## Install

On a fresh **Ubuntu 22.04/24.04** or **Debian 12/13** server, as root:

```bash
tar -xzf vpnix-create-X.Y.Z.tar.gz && cd vpnix-create-X.Y.Z
sudo bash installer/install.sh                      # IP address only: HTTPS with a local certificate
sudo bash installer/install.sh --domain vpn.example.org   # with a domain: Let's Encrypt certificate
```

The installer prints the dashboard address and a one-time administrator password. You must change the password
the first time you sign in. Verify the release signature before installing; [docs/INSTALL.md](docs/INSTALL.md) shows how.

## Documentation

| | |
|---|---|
| [Installation](docs/INSTALL.md) | requirements, verifying a release, firewall/ports, first sign-in, uninstalling |
| [Operations](docs/OPERATIONS.md) | backups, restore and moving servers, updates and rollback, logs, troubleshooting |
| [Security](docs/SECURITY.md) | threat model, what runs as root and why, hardening, reporting vulnerabilities |
| [Architecture](docs/ARCHITECTURE.md) | components, privilege boundaries, data model, VPN engine interface |
| [Releasing](docs/RELEASING.md) | for maintainers: building and signing releases |
| [Changelog](CHANGELOG.md) | what changed in each version |

## Development

```bash
cd backend && python -m venv .venv && .venv/bin/pip install -r requirements.txt && .venv/bin/python -m pytest
cd frontend && npm ci && npm run build && npx playwright test
```

Real-system tests (WireGuard, OpenVPN, firewall, operations, updates) live in `tests-e2e/` and run as root on a
disposable Linux server. See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

[Apache License 2.0](LICENSE).
