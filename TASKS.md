# VPNix Create: Task Checklist

Legend: [x] done and tested · [ ] pending · [~] in progress · [!] blocked (reason given)

## Phase 1: Foundation ✅
- [x] Repository structure, architecture and security-risk analysis (docs/ARCHITECTURE.md)
- [x] Branding: main logo, icon, light and dark versions, SVG favicon (branding/)
- [x] Authentication: Argon2id, opaque sessions (HttpOnly, SameSite=Strict, Secure on HTTPS), CSRF header,
      per-IP rate limit, per-account lockout shared by password/2FA/password-change, uniform error messages
- [x] Session expiry (absolute 12 h + idle 60 min), session list and revocation, sign-out everywhere on password change
- [x] Forced password change on first sign-in; password policy (length, no username, not repetitive)
- [x] Optional TOTP 2FA with 10 single-use recovery codes (hashed), regenerate, disable (password required)
- [x] RBAC: admin / operator / viewer, enforced per route; last active admin protected
- [x] Hash-chained audit log with integrity check, filtering, search and CSV export
- [x] First install: random admin password from the installer CLI, printed once in the terminal, never via HTTP;
      `vpnix-create-cli reset-admin` for recovery
- [x] Installer (Phase 1 scope): OS/arch/kernel/resource checks, packages, service user, directories and permissions,
      secrets, migrations, hardened systemd unit (exposure 1.4), Caddy HTTPS with security headers, health check; idempotent
- [x] Glass top navigation (desktop + mobile), dark/light themes, keyboard and screen-reader support
- [x] Overview with real CPU, memory, disk, network, uptime, failed sign-ins, audit integrity, recent events
- [x] Tests: 16 backend (auth, RBAC on every route, CLI, migrations), 7 browser (Playwright)
- [x] Verified on Ubuntu 24.04 VPS: install, idempotent re-run, HTTPS, headers, anonymous access refused

## Phase 2: WireGuard ✅
- [x] Privileged helper (root, Unix socket 0660, hardened systemd unit): fixed allowlist, every argument validated
      before any process runs or file changes, argv-only execution, refuses WireGuard interfaces it did not create
- [x] Live-safe apply: full desired state per instance, applied with `wg syncconf` (other clients keep their sessions)
- [x] Multiple WireGuard instances, independent start/stop/restart/delete (delete requires typing the name)
- [x] Conflict detection against the DB and the live host: ports (real socket check), interface names (incl. foreign
      WireGuard configs), subnet overlaps (other instances and host interfaces), names
- [x] Recommendations for port, interface and subnet that skip anything in use on the server
- [x] 10-step deployment wizard with live port check, DNS presets, full/split routing, NAT/isolation,
      validation against the live server, configuration preview and leak warnings, advanced settings
- [x] Clients: create/edit/enable/disable/revoke/regenerate/delete, description, tags, expiry, data quota,
      per-client routes and DNS, bring-your-own public key, IPv4+IPv6 addresses
- [x] Config download + QR code (secrets only for operator/admin, every download audited)
- [x] Live statistics every 30 s (handshake, endpoint, traffic, history); expiry and quota enforced on the server
- [x] Firewall: application-owned nftables table (dry-run checked first), forwarding, NAT, client isolation
- [x] Onboarding checklist after first sign-in, based on live server state
- [x] Tests: 41 backend (helper hostile input, conflicts, lifecycle, roles, rollback, enforcement), 10 browser,
      27/27 real-host checks on Ubuntu 24.04 (tests-e2e/wireguard_e2e.py)

## Phase 3: OpenVPN ✅
- [x] OpenVPN engine on the shared engine interface (openvpn-server@ovpnN), multiple instances, UDP and TCP
- [x] Per-instance PKI: ECDSA P-256 CA, server and client certificates (random CNs), tls-crypt, TLS 1.2+,
      AES-256-GCM / ChaCha20-Poly1305; only the CA fingerprint is ever shown
- [x] Revocation enforced twice: ccd-exclusive (+ live session killed) and CRL; regenerated certificates stay on the CRL
- [x] Certificate expiry monitoring (CA, server, every client) on the server page and /api/certificates
- [x] .ovpn downloads (full/split tunnel, IPv6 leak protection, DNS); no QR or bring-your-own key for OpenVPN (explained)
- [x] Live sessions and lifetime traffic from per-session counters
- [x] Helper: OpenVPN operations validate every value against strict patterns before writing (directive injection,
      path traversal, foreign instances all refused)
- [x] UI: Clients removed from the navigation; each VPN server opens a detail page with all its settings,
      certificates, traffic and its clients (online now, last connected, from where, usage, quota, expiry, actions)
- [x] Tests: 58 backend, 11 browser, 25/25 real OpenVPN checks (UDP+TCP, incl. old profile rejected after regeneration),
      WireGuard regression 27/27

## Phase 4: Routing & Firewall ✅
- [x] Networks page: per-server health/leak checks (forwarding, NAT, IPv6, DNS, port open, route conflicts)
- [x] Routing presets (full, VPN-only, LAN, custom) with before/after preview and affected-client list
- [x] Firewall page: custom allow/block rules in the app-owned `inet vpnix_create` table only
- [x] Strict validation in API and helper (rejects injection), `nft -c` dry run before apply
- [x] Every change auto-rolls back after 60 s unless "Keep changes" is pressed; dashboard reconciles
- [x] Management-access restriction with lock-out detection and explicit risk acknowledgement
- [x] Read-only view of the full host ruleset; other tables are never modified
- [x] Tests: 72 backend, 14 browser, real host: firewall 12/12, WireGuard 27/27, OpenVPN 25/25

## Phase 5: Operations ✅
- [x] Metrics history every 30 s (CPU, memory, disk, network, clients online; per-server throughput and availability), 30-day retention
- [x] Monitoring page: 1h / 24h / 7d / 30d charts, outage banner, per-server availability
- [x] Outage detection: a server that should run but does not is alerted once and audited; recovery too
- [x] Service logs (journald via helper, allowlisted units only): filter by service, level, period, text; rotation by journald
- [x] Notifications: https webhook (Slack/Discord/Teams/ntfy) and SMTP e-mail, per-event choice, 6 h repeat suppression, test button
- [x] Alerts: server down/recovered, client blocked, certificate expiring, disk > 90 %, account locked, firewall rollback, backup ok/failed
- [x] Encrypted backups (Argon2id + AES-256-GCM, SHA-256 integrity), manual + daily schedule with retention, upload/download
- [x] Restore with decrypt-and-verify preview, typed confirmation, safety copy, version check, redeploy of servers + firewall, sessions cleared
- [x] installer/backup.sh and installer/restore.sh (restore onto a new server adopts the backup's secret key)
- [x] Fix: CSRF token is re-fetched after a page reload (GET /api/auth/csrf)
- [x] Tests: 91 backend, 18 browser; real host: ops 23/23, firewall 12/12, WireGuard 27/27, OpenVPN 25/25

## Phase 6: Updates ✅
- [x] Ed25519 release signing (tools/release.py); signature binds version + SHA-256 (no relabelled old bundles)
- [x] Public key shipped in installer/release-key.pub; private key kept outside the repo by the maintainer
- [x] GitHub releases check (stable only, needs bundle + .sig assets), release notes, 6 h cache, "update available" alert
- [x] Download + verify (API), then root updater re-verifies its own private copy, safe extraction (no links/paths outside)
- [x] Snapshot (/opt + database) before install, health check of the new version, automatic rollback on failure
- [x] Manual rollback to the snapshot; downgrades refused; one update at a time (lock)
- [x] Settings: off / notify / auto install in a day + hour window (each version tried once)
- [x] Updates page with live progress; installer/update.sh for the command line; --domain kept across re-runs/updates
- [x] Fixes found on the VPS: scripts lost their exec bit; a refused attempt hid the rollback
- [x] Tests: 106 backend, 20 browser; real host: update 22/22, ops 23/23, firewall 12/12, WireGuard 27/27, OpenVPN 25/25

## Phase 7: Release
- [ ] Security hardening pass, CI/CD (tests, lint, types, audit, secrets, SAST), docs, release

## Blocked
- (none)
