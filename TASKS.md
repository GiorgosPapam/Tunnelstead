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

## Phase 3: OpenVPN
- [ ] Engine, UDP/TCP, multiple instances, PKI, CRL revocation, cert expiry monitoring, .ovpn download

## Phase 4: Routing
- [ ] Full/split tunnel, presets, IPv4/IPv6, NAT/forwarding, DNS leak guidance, config previews
- [ ] Firewall UI (app-owned nftables table), validation, timed rollback, lock-out protection

## Phase 5: Operations
- [ ] Monitoring charts, logs (structured, filter/search, rotation), notifications
- [ ] Backup/restore (encrypted, scheduled, retention, preview, integrity)

## Phase 6: Updates
- [ ] Signed GitHub releases, checks, notify, install now / schedule, rollback, downgrade protection

## Phase 7: Release
- [ ] Security hardening pass, CI/CD (tests, lint, types, audit, secrets, SAST), docs, release

## Blocked
- (none)
