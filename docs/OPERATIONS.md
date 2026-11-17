# Operating Tunnelstead

## Backups

A backup holds **everything**: VPN servers with their keys and certificates, clients, users, firewall rules and
settings. Backups are encrypted with your passphrase (Argon2id + AES-256-GCM) and carry a SHA-256 integrity check.
**Without the passphrase a backup cannot be restored, and nobody can recover it for you.**

- **Dashboard:** Settings → Backups → *Back up now*, or turn on daily backups (time in UTC, keep the last N).
  Scheduled backups store their passphrase encrypted on the server so they can run unattended.
- **Command line:** `sudo /opt/tunnelstead/installer/backup.sh [--copy-to DIR]`
- Files are in `/var/lib/tunnelstead/backups/` (`*.tsbk`, mode 0600). **Download copies regularly and keep them off
  the server.** A backup stored only on the same server does not protect against losing that server.

## Restoring

**On the same server:** Settings → Backups → *Restore*.
1. Enter the passphrase. The backup is decrypted and checked, and you see what it contains.
2. Type the backup's name to confirm.
3. A safety copy of the current data is saved first (`…-pre-restore.tsbk`).
4. All VPN servers and the firewall are redeployed to match the backup. Everyone signs in again.

**On a new server** (moving, or after losing the old one):
```bash
sudo bash installer/install.sh                                  # fresh install of the same or a newer version
sudo /opt/tunnelstead/installer/restore.sh tunnelstead-backup-….tsbk  # asks for the passphrase
```
`restore.sh` also adopts the backup's secret key, so all encrypted keys and certificates keep working. Clients
connect to the address in their configuration: if the new server has a different IP or domain, update DNS or give
clients new configurations.

A backup made by a newer version can't be restored onto an older one; update first.

## Updates

**Updates** page:
1. Set the GitHub repository.
2. Choose *Do nothing*, *Tell me*, or *Install automatically* on a day and hour.
3. *Check now* shows new versions and their release notes.
4. *Download* fetches the release and checks its signature. *Install* runs the update.

What an update does (the root updater, `tunnelstead-updater@`):
1. Copies the bundle to a root-only directory and checks the Ed25519 signature against
   `/opt/tunnelstead/release-key.pub`. The signature covers the version, so an old release can't pose as a new one.
2. Refuses anything that is not newer than the installed version.
3. Takes a snapshot of `/opt/tunnelstead` and of the database.
4. Runs the new version's installer, then waits for the new version to answer its health check.
5. If anything fails, it restores the snapshot automatically and the previous version keeps running.

VPN connections are not interrupted by an update; the dashboard restarts and reconnects by itself.

**Rollback:** after an update, *Roll back* (or `sudo /opt/tunnelstead/installer/update.sh --rollback`) restores
the version and the database from just before the update. **Changes made after the update are lost.**

**Command line:**
```bash
sudo /opt/tunnelstead/installer/update.sh tunnelstead-X.Y.Z.tar.gz   # .sig must be next to it
sudo /opt/tunnelstead/installer/update.sh --status
```

## Monitoring and alerts

- **Monitoring** shows samples taken every 30 seconds and kept for 30 days. A server that should run but doesn't is
  shown in red and raises a *server down* alert once (and again when it recovers).
- **Settings → Notifications:** webhook (https only; targets on the server itself or link-local addresses are
  refused, redirects are not followed) and/or SMTP e-mail. Pick which events alert. The same alert repeats at
  most every 6 hours. *Save and send test* checks the setup.

## Logs

- **Logs → Audit log:** every sign-in and change, hash-chained. The page tells you if any entry was altered or removed.
- **Logs → Service logs:** journald output of the API, helper, Caddy and every VPN server. Rotation and size are
  handled by journald (`/etc/systemd/journald.conf`).
- On the server: `journalctl -u tunnelstead-api -u tunnelstead-helper -f`

## Troubleshooting

| Problem | What to check |
|---|---|
| Dashboard unreachable | `systemctl status caddy tunnelstead-api`; provider firewall allows TCP 443; Firewall page → management access includes your address (an unconfirmed change undoes itself after 60 s) |
| Locked out of the dashboard by a firewall rule you kept | over SSH: `sudo nft delete table inet tunnelstead`, then remove the rule in the dashboard (VPN ports reopen on the next change) |
| Forgot the admin password | `sudo tunnelstead-cli reset-admin --username admin` (prints a one-time password) |
| Clients can't connect | Monitoring/Networks pages; provider firewall allows the VPN port; `sudo wg show` or `journalctl -u openvpn-server@ovpnN` |
| Connected but no internet | Networks page checks (IP forwarding, NAT, egress interface) |
| Server config out of sync after manual edits | `sudo tunnelstead-cli resync` redeploys everything from the database |
| Update failed | Updates page → *Details of the last update*; `sudo /opt/tunnelstead/installer/update.sh --status` |
