# VPNix Create: Task Checklist

Legend: [x] done and tested · [ ] pending · [~] in progress · [!] blocked (reason given)

## Phase 1: Foundation
- [x] Repository structure, architecture document (docs/ARCHITECTURE.md)
- [~] Branding: logo (main, icon, light, dark), favicon
- [~] Authentication: Argon2id, sessions (HttpOnly/SameSite/Secure), CSRF, rate limiting, lockout
- [~] Forced password change on first login; TOTP 2FA + recovery codes; session revocation
- [~] RBAC roles: admin, operator, viewer (read-only)
- [~] Hash-chained audit log
- [~] First-install credentials: random admin password printed once by installer (CLI only)
- [~] Glass top navigation UI shell, dark/light theme
- [~] Overview with real system metrics
- [ ] Phase 1 tests (backend + browser)

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
- [!] Real VPN testing on the VPS: waiting for the SSH key to be added (needed from Phase 2)
