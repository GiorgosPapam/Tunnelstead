# Releasing (maintainers)

Releases are built and **signed on the maintainer's machine**. The private signing key is never committed, never
uploaded to GitHub and never given to CI. Anyone holding it can publish updates that every installation trusts.

## One-time setup

```bash
python tools/release.py keygen --key ~/.vpnix-manager/release-signing.key
```
This writes the private key (keep it secret and back it up offline, e.g. in a password manager) and puts the public
key in `installer/release-key.pub`. Commit the public key. **Changing it later means existing installations reject
new releases** until they install a release containing the new public key, which must still be signed with the old key.

## Each release

1. All CI checks green on `main`. Run the real-system tests in `tests-e2e/` on a disposable server.
2. Set the version in `VERSION` (`X.Y.Z`, semantic versioning) and add a section to `CHANGELOG.md`. Commit.
3. Build the web UI and the signed bundle:
   ```bash
   (cd frontend && npm ci && npm run build)
   python tools/release.py build --key ~/.vpnix-manager/release-signing.key     # → dist/
   ```
4. Tag and publish:
   ```bash
   git tag -s vX.Y.Z -m "VPNix Manager X.Y.Z" && git push origin main vX.Y.Z
   gh release create vX.Y.Z dist/vpnix-manager-X.Y.Z.tar.gz dist/vpnix-manager-X.Y.Z.tar.gz.sig --notes-file NOTES.md
   ```
   The release notes are shown on every installation's Updates page.
5. The **Verify release** workflow checks the signature and version of the uploaded assets and attaches `SHA256SUMS`.
   If it fails, delete the release immediately.

Releases marked *pre-release* or *draft* are never offered to installations.

`tools/release.py build --replace PATH=FILE` swaps a file inside the bundle. It exists only for update tests (e.g.
a deliberately failing installer); never publish a bundle built with it.
