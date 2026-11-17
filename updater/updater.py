#!/usr/bin/env python3
"""Tunnelstead updater. Runs as root, only via tunnelstead-updater@<action>.service or update.sh.

    updater.py install-X.Y.Z   install the downloaded, signed bundle for version X.Y.Z
    updater.py rollback        restore the snapshot taken before the last update (code AND database)

Safety rules:
  * The bundle is copied into a root-only directory first and verified there (the unprivileged API that downloaded
    it cannot swap it afterwards). The Ed25519 signature must match /opt/tunnelstead/release-key.pub and covers the
    version and SHA-256, so an old signed bundle cannot be relabelled as new.
  * Only newer versions are installed (downgrade protection). Going back is only possible through `rollback`,
    which restores the exact snapshot (application + database) taken before the update.
  * Before installing: snapshot of /opt/tunnelstead and an online copy of the database. After installing, the new
    version must answer its health check with the expected version, otherwise everything is rolled back automatically.
"""
import base64
import hashlib
import json
import os
import re
import shutil
import sqlite3
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.request
from datetime import UTC, datetime
from pathlib import Path

APP = Path(os.environ.get("TUNNELSTEAD_APP_DIR", "/opt/tunnelstead"))
PREV = Path(str(APP) + ".prev")
STATE = Path(os.environ.get("TUNNELSTEAD_STATE_DIR", "/var/lib/tunnelstead"))
DOWNLOADS = STATE / "updates"
STATUS = DOWNLOADS / "status.json"
SAFE = Path(os.environ.get("TUNNELSTEAD_UPDATE_SAFE_DIR", "/var/backups/tunnelstead"))  # root-only (0700)
DB = STATE / "tunnelstead.db"
HEALTH = "http://127.0.0.1:8090/api/health"
VERSION_RE = re.compile(r"^\d+\.\d+\.\d+$")
SVC_USER = "tunnelstead"
_log: list[str] = []


class UpdateError(RuntimeError):
    pass


def vtuple(v: str) -> tuple[int, ...]:
    if not VERSION_RE.match(v):
        raise UpdateError(f"invalid version {v!r}")
    return tuple(int(x) for x in v.split("."))


def installed_version() -> str:
    try:
        return (APP / "VERSION").read_text().strip()
    except OSError:
        return "0.0.0"


def log(msg: str) -> None:
    line = f"{datetime.now(UTC):%H:%M:%S} {msg}"
    print(line, flush=True)
    _log.append(line)


def rollback_target() -> str | None:
    """The version a rollback would restore, if a snapshot exists (independent of the last attempt's outcome)."""
    try:
        return json.loads((SAFE / "snapshot.json").read_text())["version"] if PREV.is_dir() else None
    except (OSError, ValueError, KeyError):
        return None


def drop_snapshot() -> None:
    shutil.rmtree(PREV, ignore_errors=True)
    for f in ("snapshot.json", "pre-update.db"):
        (SAFE / f).unlink(missing_ok=True)


def status(state: str, **kw) -> None:
    DOWNLOADS.mkdir(parents=True, exist_ok=True)
    data = {"state": state, "updated_at": datetime.now(UTC).isoformat(), "log": _log[-60:],
            "rollback_to": rollback_target() if state != "running" else None, **kw}
    tmp = STATUS.with_suffix(".tmp")
    tmp.write_text(json.dumps(data))
    try:
        shutil.chown(tmp, SVC_USER, SVC_USER)
    except (LookupError, PermissionError):
        pass
    os.chmod(tmp, 0o600)  # read only by the service account (owner)
    os.replace(tmp, STATUS)


def message(version: str, sha256: str) -> bytes:
    return f"tunnelstead-release:{version}:{sha256}".encode()


def verify(bundle: Path, sig: Path, version: str, pubkey: Path | None = None) -> str:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    pub = Ed25519PublicKey.from_public_bytes(base64.b64decode((pubkey or APP / "release-key.pub").read_text().strip()))
    digest = hashlib.sha256(bundle.read_bytes()).hexdigest()
    try:
        pub.verify(base64.b64decode(sig.read_text().strip()), message(version, digest))
    except (InvalidSignature, ValueError):
        raise UpdateError("signature check failed: this bundle was not signed by the Tunnelstead release key") from None
    return digest


def safe_extract(bundle: Path, dest: Path, version: str) -> Path:
    prefix = f"tunnelstead-{version}/"
    with tarfile.open(bundle, "r:gz") as tar:
        for m in tar.getmembers():
            name = m.name
            if not (name == prefix.rstrip("/") or name.startswith(prefix)) or ".." in Path(name).parts or name.startswith("/"):
                raise UpdateError(f"unexpected path in bundle: {name}")
            if not (m.isfile() or m.isdir()):
                raise UpdateError(f"links and devices are not allowed in a bundle: {name}")
        tar.extractall(dest, filter="data")
    root = dest / prefix.rstrip("/")
    if (root / "VERSION").read_text().strip() != version:
        raise UpdateError("the bundle's VERSION file does not match its signed version")
    return root


def sh(*argv: str, timeout: int = 900) -> None:
    log("$ " + " ".join(argv))
    p = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
    for line in (p.stdout + p.stderr).strip().splitlines()[-15:]:
        if "PASSWORD" not in line.upper():  # never let a credential reach the status file
            log("  " + line)
    if p.returncode:
        raise UpdateError(f"{argv[0]} failed with exit code {p.returncode}")


def healthy(expect: str, timeout: int = 90) -> bool:
    end = time.time() + timeout
    while time.time() < end:
        try:
            with urllib.request.urlopen(HEALTH, timeout=5) as r:
                if json.load(r).get("version") == expect:
                    return True
        except OSError:
            pass
        time.sleep(2)
    return False


def snapshot(from_version: str, to_version: str) -> None:
    log(f"Snapshot of {APP} and the database before updating")
    SAFE.mkdir(mode=0o700, parents=True, exist_ok=True)
    sh("rsync", "-a", "--delete", f"{APP}/", f"{PREV}/")
    if DB.exists():
        tmp = SAFE / "pre-update.db.tmp"
        tmp.unlink(missing_ok=True)
        os.close(os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600))  # private from the first byte
        _sqlite_copy(DB, tmp)
        os.replace(tmp, SAFE / "pre-update.db")
    (SAFE / "snapshot.json").write_text(json.dumps({"version": from_version, "replaced_by": to_version,
                                                    "taken_at": datetime.now(UTC).isoformat()}))


def _sqlite_copy(src: Path, dst: Path) -> None:
    """Consistent copy of a SQLite database into another one (online backup API; safe with WAL and open readers)."""
    s, d = sqlite3.connect(src), sqlite3.connect(dst, timeout=30)
    try:
        s.backup(d)
    finally:
        s.close()
        d.close()


def restore_snapshot() -> str:
    meta = json.loads((SAFE / "snapshot.json").read_text())
    if not PREV.is_dir():
        raise UpdateError("no snapshot to roll back to")
    log(f"Rolling back to {meta['version']}")
    sh("systemctl", "stop", "tunnelstead-api")
    sh("rsync", "-a", "--delete", f"{PREV}/", f"{APP}/")
    if (SAFE / "pre-update.db").exists():
        # Through SQLite's backup API, never by deleting the -wal/-shm files and copying over the database file:
        # a process that still had the database open would keep writing into the deleted files and lose those writes.
        _sqlite_copy(SAFE / "pre-update.db", DB)
        for f in (DB, Path(str(DB) + "-wal"), Path(str(DB) + "-shm")):
            if f.exists():
                shutil.chown(f, SVC_USER, SVC_USER)
                os.chmod(f, 0o600)
    units = APP / "installer" / "systemd"
    for u in units.glob("*.service"):
        shutil.copy2(u, f"/etc/systemd/system/{u.name}")
    sh("systemctl", "daemon-reload")
    sh("systemctl", "restart", "tunnelstead-helper", "tunnelstead-api")
    if not healthy(meta["version"]):
        raise UpdateError("the restored version did not start; see journalctl -u tunnelstead-api")
    return meta["version"]


def install(version: str) -> None:
    current = installed_version()
    if vtuple(version) <= vtuple(current):
        raise UpdateError(f"{version} is not newer than the installed {current} (downgrades are refused; use rollback)")
    name = f"tunnelstead-{version}.tar.gz"
    with tempfile.TemporaryDirectory(prefix="tunnelstead-update-") as td:  # root-only (0700)
        work = Path(td)
        for f in (name, name + ".sig"):
            if not (DOWNLOADS / f).is_file():
                raise UpdateError(f"{f} has not been downloaded")
            shutil.copyfile(DOWNLOADS / f, work / f)
        digest = verify(work / name, work / (name + ".sig"), version)
        log(f"Signature valid for {version} (sha256 {digest[:16]}…)")
        src = safe_extract(work / name, work, version)
        status("running", version=version, previous=current, step="snapshot")
        snapshot(current, version)
        status("running", version=version, previous=current, step="install")
        try:
            sh("bash", str(src / "installer" / "install.sh"))
            if not healthy(version):
                raise UpdateError(f"{version} did not pass its health check")
        except Exception as e:
            log(f"Update failed: {e}. Rolling back automatically.")
            status("running", version=version, previous=current, step="rollback")
            back = restore_snapshot()
            drop_snapshot()  # the snapshot is what runs now; the earlier snapshot was replaced by this attempt
            status("rolled_back", version=version, previous=current, error=str(e), running=back)
            raise SystemExit(1) from None
    log(f"Updated {current} → {version}")
    status("success", version=version, previous=current, running=version)


def main(argv: list[str]) -> int:
    if len(argv) != 1:
        print(__doc__)
        return 2
    import fcntl  # Linux only (the updater never runs elsewhere)
    action = argv[0]
    lock = open("/run/tunnelstead-update.lock", "w")
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        print("another update is running", file=sys.stderr)
        return 3
    current = installed_version()
    try:
        if action == "rollback":
            status("running", step="rollback", previous=current)
            back = restore_snapshot()
            drop_snapshot()  # one rollback per update: the snapshot is now live
            log(f"Rolled back {current} → {back}")
            status("rolled_back", previous=current, running=back, manual=True)
            return 0
        m = re.fullmatch(r"install-(\d+\.\d+\.\d+)", action)
        if not m:
            raise UpdateError(f"unknown action {action!r}")
        status("running", version=m[1], previous=current, step="verify")
        install(m[1])
        return 0
    except UpdateError as e:
        log(f"Error: {e}")
        status("failed", previous=current, running=installed_version(), error=str(e))
        return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
