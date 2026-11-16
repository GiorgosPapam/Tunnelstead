# VPNix Create: Architecture

## 1. Components and privilege boundaries

```
Browser ──HTTPS──► Caddy (TLS, static UI, security headers) ──► vpnix-create-api (FastAPI, user vpnix-create, no capabilities)
                                                                   │  SQLite via SQLAlchemy 2 + Alembic migrations
                                                                   │  JSON over Unix socket /run/vpnix-create/helper.sock (0660 root:vpnix-create)
                                                                   ▼
                                                       vpnix-create-helper (root, systemd-sandboxed, fixed allowlist)
                                                                   │  argv-only exec: wg, wg-quick, ip, ss, nft, sysctl, systemctl, openvpn, journalctl
                                                                   ▼
                                                     WireGuard · OpenVPN · nftables (own table) · sysctl · journald
vpnix-create-updater@<action> (root, oneshot): started by the helper's sys.update or by update.sh
```

| Component | Runs as | Can | Cannot |
|---|---|---|---|
| Web UI (React) | browser | call the API with the HttpOnly session cookie + in-memory CSRF token | read the session token; store secrets in localStorage |
| `vpnix-create-api` | `vpnix-create` | DB, psutil metrics, backups in its state dir, update downloads, call helper methods | run commands, write `/etc` or `/opt`, change the firewall directly |
| `vpnix-create-helper` | root | the allowlisted methods below, validating every argument first | anything else; arbitrary paths, units or tables; a shell |
| updater | root, oneshot | verify a signed bundle, snapshot, install, health-check, roll back | install unsigned, mis-versioned or older bundles |

**Helper methods:** `net.*` (interfaces, port in use), `wg.*` (sync, service, delete, dump), `ovpn.*` (apply,
service, status, delete), `fw.*` (apply/confirm/pending/show the `inet vpnix_create` table, read-only ruleset),
`sys.*` (forwarding, status, journal for allowlisted units, start the updater). Interfaces must match `wgN`/`ovpnN`
and their config files must carry the managed marker; foreign configurations are reported, never changed.

## 2. Technology

| Area | Choice |
|---|---|
| API | Python 3.12, FastAPI, Pydantic v2 |
| Data | SQLAlchemy 2, Alembic; SQLite in WAL mode |
| Crypto | argon2-cffi (passwords, backup keys), cryptography: AES-256-GCM (secrets at rest, backups), X25519 (WireGuard), ECDSA P-256 PKI (OpenVPN), Ed25519 (release signatures) |
| UI | React 18, TypeScript (strict), Vite, Tailwind CSS 4, lucide-react; dependency-free SVG charts |
| Proxy/TLS | Caddy (Let's Encrypt or local CA), admin API on a private Unix socket |
| Tests | pytest (API, RBAC, helper/updater validation, migrations), Playwright, real-host suites in `tests-e2e/` |
| License | Apache-2.0 |

## 3. Data model

`users`, `user_sessions`, `audit_log` (hash-chained), `settings` (JSON values: firewall pending state, management
access, notifications, backup schedule, update settings and cache…), `vpn_instances`, `clients`, `client_stats`,
`retired_certs` (old OpenVPN certificates kept on the CRL), `firewall_rules`, `host_metrics`, `instance_metrics`.
Secrets are AES-256-GCM encrypted with associated data naming their row.

## 4. Roles

- **admin:** everything.
- **operator:** view everything; manage clients (create, enable/disable, download configurations).
- **viewer:** read-only; never sees secrets or configurations.

Enforced server-side by a permission check on every route; tests call each protected route as each role.

## 5. VPN engine interface

`engines/base.py` defines `VpnEngine`: `check_installation`, `create_keys`, `new_client_credentials`, `apply`,
`start`, `stop`, `delete`, `status`, `collect_stats`, `render_client_config`, plus capability flags (`supports_qr`,
`supports_own_key`, `session_counters`, `file_ext`, `port_range`, `iface_prefix`). `WireGuardEngine` and
`OpenVPNEngine` are registered in `engines/registry.py`; the rest of the app is protocol-neutral.

## 6. Background work

One collector loop in the API process, every 30 s:
- client statistics, expiry and quota enforcement;
- service health with down/recovered alerts;
- host and per-server metrics;
- firewall rollback reconciliation;
- scheduled backups;
- reporting update outcomes.

Every ~10 min it also checks for updates and handles the automatic-update window. Every hour it prunes data older
than 30 days and checks certificate expiry.

## 7. Repository layout

```
backend/    FastAPI app (vpnix_create/), Alembic migrations, tests
helper/     privileged helper (stdlib only)
updater/    root updater (snapshot, install, health check, rollback)
frontend/   React UI, Playwright tests
installer/  install.sh uninstall.sh update.sh backup.sh restore.sh, systemd units, release-key.pub
tools/      release.py (build and sign releases)
tests-e2e/  real-system tests (run as root on a disposable server)
docs/       architecture, install, operations, security, releasing
```
