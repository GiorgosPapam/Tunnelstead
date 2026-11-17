# Security

## Reporting a vulnerability

Please report security problems privately through GitHub's **Report a vulnerability** (Security tab → Advisories),
not in a public issue. Include the version, what you found and how to reproduce it. You'll get an answer within
7 days. Fixes are released as signed updates and credited in the changelog unless you prefer otherwise.

## Threat model

VPNix Manager runs on a server that holds VPN keys for all your clients. The main threats are:
- someone on the internet taking over the dashboard;
- a bug in the web application being used to get root;
- a malicious or tampered update;
- secrets leaking through backups, logs or the browser;
- an administrator locking themselves out.

## Privilege separation

| Part | Runs as | Can |
|---|---|---|
| Caddy | `caddy` | TLS, static files, proxy to the API on 127.0.0.1:8090. Its admin API is a socket in a 0700 directory (not TCP), so no other local user can reconfigure it |
| API (`vpnix-manager-api`) | `vpnix-manager`, no capabilities, `ProtectSystem=strict`, systemd exposure 1.4 | database, read-only metrics, talk to the helper |
| Helper (`vpnix-manager-helper`) | root, sandboxed (exposure 5.7: it needs `CAP_NET_ADMIN` etc. for WireGuard, nftables, sysctl) | a fixed list of operations. Every argument is validated **before** anything runs; programs are called with argument lists, never a shell. It only touches `wgN`/`ovpnN` interfaces, configs that carry its marker, and the nftables table `inet vpnix_manager` |
| Updater (`vpnix-manager-updater@`) | root, oneshot | install a bundle whose Ed25519 signature matches the release key; snapshot and roll back |

A full compromise of the API therefore does **not** give root: the attacker could only call the helper's
validated operations (which can still change VPN servers and the firewall table, so the dashboard must be protected).

## Authentication and sessions

- Passwords: Argon2id. Policy: at least 12 characters, not containing the username, not too repetitive. The one-time
  installer password must be changed at first sign-in.
- Two-factor authentication: TOTP with single-use recovery codes.
- Brute force: per-IP rate limit, plus per-account lockout shared across password, 2FA and password-change failures.
  Error messages are identical for unknown users, wrong passwords and locked accounts.
- Sessions: random tokens in an `HttpOnly; Secure; SameSite=Strict` cookie, stored hashed. Idle and absolute
  timeouts. Sessions are revoked on password change and listed (and revocable) under Settings.
- CSRF: every change needs an `X-CSRF-Token` header (an HMAC of the session) that the page keeps in memory only.
  No CORS, so other sites can't read it.
- Roles: administrator, operator (clients only), viewer (read-only, never sees secrets). Checked on every API route.

## Data protection

- VPN private keys, pre-shared keys, CA keys, TOTP secrets and SMTP/backup passphrases are encrypted in the database
  with AES-256-GCM. The key is in `/etc/vpnix-manager/vpnix-manager.env` (root:vpnix-manager 0640). Each value is bound
  to its row, so encrypted values can't be swapped between rows.
- Backups: Argon2id-derived key, AES-256-GCM, SHA-256 integrity, mode 0600. Sign-in sessions are never restored.
- Logs never contain keys or passwords. The audit log is hash-chained to detect tampering.
- HTTP security headers: HSTS, strict Content-Security-Policy (no inline scripts), `X-Frame-Options: DENY`,
  `nosniff`, no referrer, `Cache-Control: no-store` on the API. The OpenAPI description is not served in production.

## Network safety

- Firewall changes apply atomically (`nft -c` dry run first) and are undone after 60 s unless confirmed. Dashboard
  access restrictions warn if your own address would be locked out.
- Webhooks: https only, no redirects, no targets on the server itself or in link-local space (cloud metadata).

## Updates

Releases are signed on the maintainer's machine; the private key never reaches GitHub or CI. The signature covers
`version + SHA-256`, so old releases can't be relabelled. Downgrades are refused. The bundle is verified again
by the root updater on a private copy, extracted without links or paths outside its folder, and installed only
after a snapshot. If its health check fails, it is rolled back automatically.

## Recommendations for operators

1. Use a domain (`--domain`) for a trusted certificate, and turn on 2FA for every administrator.
2. Restrict dashboard access to your own networks (Firewall → Management access).
3. Keep daily backups and download copies to a different place. Store the backup passphrase in a password manager.
4. Keep "notify" or "auto" updates on. Use SSH keys (not passwords) for the server.

## Verified

Automated checks on every change (see `.github/workflows`):
- ruff, including bandit security rules;
- mypy;
- 100+ API tests, including RBAC on every route and hostile-input tests for the helper and updater;
- browser tests;
- shellcheck;
- pip-audit and npm audit;
- gitleaks over the full history;
- CodeQL.

Real-system tests in `tests-e2e/` exercise WireGuard, OpenVPN, the firewall, operations and updates as root on a
disposable server.
