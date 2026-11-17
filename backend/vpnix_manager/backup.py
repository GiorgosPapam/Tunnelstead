"""Encrypted, self-verifying backups of the whole VPNix Manager state.

File format (.vbk):  b"VPNIXBK1" | salt (16) | nonce (12) | AES-256-GCM( tar.gz{manifest.json, vpnix.db} )
The key comes from the backup passphrase via Argon2id, so a backup can be restored on a new server, and nothing in
it (VPN keys, certificates, password hashes, the app secret key) is readable without the passphrase. GCM
authenticates the whole file; the manifest also carries a SHA-256 of the database for a second integrity check.
"""
import hashlib
import io
import json
import os
import re
import sqlite3
import tarfile
import tempfile
from datetime import UTC, datetime
from pathlib import Path

from argon2.low_level import Type, hash_secret_raw
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from . import __version__
from .config import get_settings

MAGIC = b"VPNIXBK1"
FORMAT = 1
MAX_SIZE = 512 * 1024 * 1024
NAME_RE = re.compile(r"^vpnix-backup-\d{8}-\d{6}-(manual|scheduled|pre-restore|uploaded)(-\d+)?\.vbk$")


class BackupError(ValueError):
    pass


def backup_dir() -> Path:
    url = get_settings().database_url
    if not url.startswith("sqlite:///"):
        raise BackupError("Backups need the default SQLite database")
    d = Path(os.environ.get("VPNIX_BACKUP_DIR") or Path(db_path()).parent / "backups")
    d.mkdir(mode=0o750, parents=True, exist_ok=True)
    return d


def db_path() -> str:
    return get_settings().database_url.removeprefix("sqlite:///")


def _key(passphrase: str, salt: bytes) -> bytes:
    if len(passphrase) < 12:
        raise BackupError("The backup passphrase must be at least 12 characters")
    return hash_secret_raw(passphrase.encode(), salt, time_cost=3, memory_cost=64 * 1024, parallelism=2,
                           hash_len=32, type=Type.ID)


def _snapshot() -> bytes:
    """A consistent copy of the live database (SQLite online backup: safe while the app is writing)."""
    with tempfile.TemporaryDirectory() as td:
        tmp = os.path.join(td, "snap.db")
        src, dst = sqlite3.connect(db_path()), sqlite3.connect(tmp)
        try:
            src.backup(dst)
        finally:
            src.close()
            dst.close()
        return Path(tmp).read_bytes()


def _counts(raw: bytes) -> dict:
    with tempfile.TemporaryDirectory() as td:
        p = os.path.join(td, "x.db")
        Path(p).write_bytes(raw)
        c = sqlite3.connect(p)
        try:
            q = lambda sql: c.execute(sql).fetchone()[0]  # noqa: E731
            return {"vpn_servers": q("select count(*) from vpn_instances"), "clients": q("select count(*) from clients"),
                    "users": q("select count(*) from users"), "firewall_rules": q("select count(*) from firewall_rules"),
                    "schema": q("select version_num from alembic_version")}
        finally:
            c.close()


def unique_name(kind: str) -> str:
    stamp = datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
    d, n = backup_dir(), 0
    while True:
        name = f"vpnix-backup-{stamp}-{kind}{f'-{n}' if n else ''}.vbk"
        if not (d / name).exists():
            return name
        n += 1


def create(passphrase: str, kind: str = "manual") -> dict:
    raw = _snapshot()
    counts = _counts(raw)
    manifest = {"format": FORMAT, "app": "vpnix-manager", "app_version": __version__, "kind": kind,
                "created_at": datetime.now(UTC).isoformat(), "db_sha256": hashlib.sha256(raw).hexdigest(),
                "contents": counts, "secret_key": get_settings().secret_key}
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for name, data in (("manifest.json", json.dumps(manifest).encode()), ("vpnix.db", raw)):
            info = tarfile.TarInfo(name)
            info.size, info.mode = len(data), 0o600
            tar.addfile(info, io.BytesIO(data))
    salt, nonce = os.urandom(16), os.urandom(12)
    blob = MAGIC + salt + nonce + AESGCM(_key(passphrase, salt)).encrypt(nonce, buf.getvalue(), MAGIC)
    path = backup_dir() / unique_name(kind)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(blob)
    return describe(path)


def open_backup(path: Path, passphrase: str) -> tuple[dict, bytes]:
    blob = path.read_bytes()
    if not blob.startswith(MAGIC) or len(blob) < 8 + 16 + 12 + 16:
        raise BackupError("This is not a VPNix Manager backup file")
    salt, nonce, ct = blob[8:24], blob[24:36], blob[36:]
    try:
        tgz = AESGCM(_key(passphrase, salt)).decrypt(nonce, ct, MAGIC)
    except InvalidTag:
        raise BackupError("Wrong passphrase, or the file is damaged") from None
    with tarfile.open(fileobj=io.BytesIO(tgz), mode="r:gz") as tar:
        names = tar.getnames()
        if sorted(names) != ["manifest.json", "vpnix.db"]:
            raise BackupError("Unexpected backup contents")
        manifest = json.loads(tar.extractfile("manifest.json").read())
        raw = tar.extractfile("vpnix.db").read()
    if manifest.get("format") != FORMAT or manifest.get("app") not in ("vpnix-manager", "vpnix-create"):  # 1.x was called VPNix Create
        raise BackupError("Unsupported backup format")
    if hashlib.sha256(raw).hexdigest() != manifest["db_sha256"]:
        raise BackupError("Integrity check failed: the database inside the backup is damaged")
    return manifest, raw


def preview(path: Path, passphrase: str) -> dict:
    """What a restore would bring back, after full decryption and integrity checks. Never includes secrets."""
    from alembic.script import ScriptDirectory

    from .cli import alembic_config
    m, _ = open_backup(path, passphrase)
    known = {r.revision for r in ScriptDirectory.from_config(alembic_config()).walk_revisions()}
    return {"created_at": m["created_at"], "app_version": m["app_version"], "kind": m["kind"], "contents": m["contents"],
            "integrity_ok": True, "same_secret_key": m["secret_key"] == get_settings().secret_key,
            "compatible": m["contents"]["schema"] in known}


def describe(path: Path) -> dict:
    st = path.stat()
    kind = NAME_RE.match(path.name)[1] if NAME_RE.match(path.name) else "unknown"
    return {"name": path.name, "size": st.st_size, "created_at": datetime.fromtimestamp(st.st_mtime, UTC), "kind": kind}


def listing() -> list[dict]:
    return sorted((describe(p) for p in backup_dir().iterdir() if NAME_RE.match(p.name)),
                  key=lambda b: b["created_at"], reverse=True)


def resolve(name: str) -> Path:
    if not NAME_RE.match(name):
        raise BackupError("Invalid backup name")
    p = backup_dir() / name
    if not p.is_file():
        raise BackupError("No such backup")
    return p


def prune(keep: int) -> list[str]:
    """Keep the newest `keep` scheduled backups; manual, uploaded and pre-restore ones are never removed here."""
    sched = [b for b in listing() if b["kind"] == "scheduled"]
    gone = [b["name"] for b in sched[keep:]]
    for n in gone:
        (backup_dir() / n).unlink(missing_ok=True)
    return gone


def write_database(raw: bytes) -> None:
    """Replace the live database contents in place (SQLite online backup into the open file)."""
    with tempfile.TemporaryDirectory() as td:
        p = os.path.join(td, "restore.db")
        Path(p).write_bytes(raw)
        src = sqlite3.connect(p)
        src.execute("DELETE FROM user_sessions")  # sessions are never restored: everyone signs in again
        src.commit()
        dst = sqlite3.connect(db_path(), timeout=30)
        try:
            src.backup(dst)
        finally:
            src.close()
            dst.close()
