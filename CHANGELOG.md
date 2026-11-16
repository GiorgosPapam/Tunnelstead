# Changelog

All notable changes. Versions follow [semantic versioning](https://semver.org/).

## 1.0.0

First public release.

- **VPN servers:** WireGuard and OpenVPN (UDP/TCP), any number side by side.
  - 10-step wizard with port, interface and subnet conflict detection and suggestions.
  - IPv4/IPv6, full/split tunnel, NAT.
  - Per-instance OpenVPN CA with tls-crypt and CRL.
- **Clients:** QR codes, config downloads, expiry, data limits, enable/disable, key regeneration, online status,
  last connection, usage.
- **Networks:** health and leak checks per server; routing presets with before/after preview.
- **Firewall:** custom rules and management-access restriction in an app-owned nftables table, with a 60-second
  automatic rollback unless kept.
- **Monitoring:** 30 days of host and per-server metrics, availability, outage detection.
- **Logs:** tamper-evident audit log, and service logs from journald.
- **Notifications:** webhook and e-mail alerts.
- **Backups:** encrypted backups (manual and scheduled), restore with preview and safety copy, `backup.sh`/`restore.sh`.
- **Updates:** signed updates with snapshot, health check, automatic rollback and downgrade protection; scheduled
  automatic updates; `update.sh`.
- **Accounts:** Argon2id, forced first password change, TOTP 2FA with recovery codes, lockout, roles
  (admin/operator/viewer).
- **Installation:** hardened installation (unprivileged API, sandboxed root helper, Caddy with security headers and a
  private admin socket), `install.sh` and `uninstall.sh`.
