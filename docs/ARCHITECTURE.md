# VPNix Create: Architecture

## 1. Components and privilege boundaries

```
Browser ──HTTPS──► Caddy (TLS, static UI) ──► vpnix-api  (FastAPI, user "vpnix", no capabilities)
                                                │  SQLite (default) / PostgreSQL via SQLAlchemy + Alembic
                                                │  JSON-RPC over Unix socket /run/vpnix/helper.sock (0660 root:vpnix)
                                                ▼
                                          vpnix-helper (root, systemd-hardened, fixed operation allowlist)
                                                │  argv-only exec / netlink: wg, ip, nft, systemctl, openvpn
                                                ▼
                                   WireGuard · OpenVPN · nftables · sysctl
vpnix-updater (root, oneshot; started by a path unit when the API drops a signed-update request)
vpnix-backup  (root, oneshot; timer + on-demand request file)
```

| Component | Runs as | Can | Cannot |
|---|---|---|---|
| Web UI (React) | browser | call the API with an HttpOnly session cookie + CSRF header | hold tokens in localStorage, see private keys except on explicit download |
| `vpnix-api` | `vpnix` | DB, read-only system metrics (`/proc`), talk to the helper, write request files | run shell commands, touch `/etc/wireguard`, change the firewall directly |
| `vpnix-helper` | root | the allowlisted operations below, each re-validating every argument | anything not on the allowlist; arbitrary paths; shell |
| updater / backup | root, oneshot | verify signatures, back up, install, roll back | be triggered with arbitrary arguments (request files carry only a validated version string / nothing) |

**Helper operation allowlist (by module):** `wg.*` (interface up/down/apply, peer upsert/remove, dump),
`ovpn.*` (instance apply/start/stop, client add/remove, CRL, status), `fw.*` (apply the application-owned
nftables table only), `net.*` (list interfaces, check port in use, sysctl forwarding), `sys.*` (service
status). Each module owns a name prefix (`wg` interfaces `wg*`, OpenVPN `ovpn*`, nft table `inet vpnix_create`)
and the helper refuses operations on resources outside that module's namespace: one VPN engine cannot
touch another engine's interfaces or files.

## 2. Technology choices

| Area | Choice | Reason |
|---|---|---|
| API | Python 3.12, FastAPI, Pydantic v2 | typed validation at the boundary, OpenAPI docs for free, easy to audit |
| Data | SQLAlchemy 2 + Alembic; SQLite default, PostgreSQL supported | zero-setup single server, same models scale out; migrations from day one |
| Passwords | Argon2id (`argon2-cffi`) | OWASP-recommended memory-hard hash |
| Secrets at rest | AES-256-GCM (`cryptography`), key in a root-owned env file | private keys/PSKs/TOTP secrets encrypted, bound to their row via associated data |
| Metrics | `psutil` | real CPU/RAM/disk/network without privileges |
| UI | React 18 + TypeScript + Vite + Tailwind CSS 4 + Lucide icons | spec stack; Tailwind gives a consistent design system without a heavy component kit |
| Charts | Recharts | maintained, accessible SVG output |
| Firewall | nftables (own table only) | modern, atomic rule replacement; never edits unrelated rules |
| TLS/proxy | Caddy | automatic HTTPS, simple config |
| Releases | Ed25519-signed `SHA256SUMS`, pinned public key | tamper and downgrade protection without third-party services |
| License | Apache-2.0 | permissive with an explicit patent grant (see LICENSE section in README) |

The UI uses hand-built accessible components on Tailwind instead of a large component library: fewer
dependencies, full control over the Liquid Glass look, and no unused code.

## 3. Data model (Phase 1–2)
`users` (role: admin | operator | viewer), `user_sessions`, `audit_log` (hash-chained), `settings`,
`vpn_instances` (protocol, name, interface, port, transport, subnets, DNS, MTU, routing mode, state),
`clients` (instance, name, description, tags, addresses, keys encrypted, status, expiry, quota),
`client_stats` (time series), later: `certificates`, `firewall_rules`, `backups`, `update_jobs`.

## 4. Roles (RBAC)
- **admin**: everything.
- **operator**: manage clients and view instances; cannot change instances, firewall, users, updates.
- **viewer** (read-only administrator): view everything except secrets; no mutations, no config downloads.
Authorization is enforced server-side on every route by permission checks, never only in the UI.

## 5. VPN engine interface
Each engine implements: `check_installation`, `create_instance`, `delete_instance`, `start`, `stop`,
`restart`, `status`, `add_client`, `remove_client`, `render_client_config`, `collect_stats`. Engines are
registered in a registry; a protocol is exposed in the UI only after its engine passes its lifecycle tests.

## 6. Security risks and mitigations
| Risk | Mitigation |
|---|---|
| Web app compromise → root | API unprivileged; helper allowlist with argument validation; systemd sandboxing |
| Command/config injection (interface names, keys, CIDRs, OpenVPN directives) | strict regex/ipaddress validation in API **and** helper; argv-only exec; no newline-bearing values in configs |
| Credential stuffing / brute force | Argon2id, per-IP limiter, per-account lockout incl. MFA, uniform error messages |
| Session theft / CSRF | HttpOnly SameSite=Strict cookies, double-submit CSRF header, rotation, revocation |
| IDOR / privilege escalation | per-route permission checks, role tests that try every admin route as lower roles |
| Firewall lock-out | app-owned table only; management port always allowed from admin networks; apply with timed auto-rollback |
| Malicious update | signature + checksum + version monotonicity (no downgrades) before anything runs; backup + rollback |
| Secret leakage | encrypted at rest; never logged; never returned except explicit config download (audited) |
| Initial credential exposure | generated randomly by the installer, printed once in the terminal, forced change at first login, no web endpoint reveals it |

## 7. Repository layout
```
backend/   FastAPI app (vpnix_create/), Alembic migrations, tests
helper/    privileged helper (stdlib only)
frontend/  React UI, Playwright tests
installer/ install.sh uninstall.sh update.sh backup.sh restore.sh + systemd units
docs/      architecture, install, upgrade, backup, API, troubleshooting
```
