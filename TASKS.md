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

## Phase 2: WireGuard
- [ ] Privileged helper with allowlist; WireGuard engine
- [ ] Multiple instances; port/interface/subnet conflict detection; port recommendations (real availability)
- [ ] Clients: create/edit/enable/disable/revoke/regenerate, tags, expiry, quotas
- [ ] Config download + QR; handshake and transfer stats
- [ ] Instance deployment wizard (10 steps) with review

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
