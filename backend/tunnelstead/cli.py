"""tunnelstead-cli: installer-side operations. Never reachable over HTTP."""
import argparse
import base64
import os
import sys

from sqlalchemy import func, select

ALEMBIC_INI = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "alembic.ini")


def alembic_config(engine=None):
    from alembic.config import Config
    cfg = Config(ALEMBIC_INI)
    if engine is not None:
        cfg.set_main_option("sqlalchemy.url", engine.url.render_as_string(hide_password=False).replace("%", "%%"))
    return cfg


def migrate(engine) -> None:
    from alembic import command
    command.upgrade(alembic_config(engine), "head")


def _passphrase(confirm: bool) -> str:
    pw = os.environ.get("TUNNELSTEAD_BACKUP_PASSPHRASE")
    if pw:
        return pw
    import getpass
    pw = getpass.getpass("Backup passphrase: ")
    if confirm and getpass.getpass("Repeat passphrase: ") != pw:
        raise SystemExit("Passphrases do not match")
    return pw


ENV_FILE = "/etc/tunnelstead/tunnelstead.env"


def _set_secret_key(key: str) -> None:
    """Restoring onto another server: the database secrets were encrypted with the backup's key, so adopt it."""
    import re as _re
    text = open(ENV_FILE, encoding="utf-8").read()
    text = _re.sub(r"(?m)^TUNNELSTEAD_SECRET_KEY=.*$", f"TUNNELSTEAD_SECRET_KEY={key}", text)
    tmp = ENV_FILE + ".new"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o640)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(text)
    os.replace(tmp, ENV_FILE)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="tunnelstead-cli")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("gen-secret", help="print a new TUNNELSTEAD_SECRET_KEY")
    sub.add_parser("migrate", help="apply database migrations (safe to re-run)")
    ia = sub.add_parser("init-admin", help="create the first administrator with a random temporary password")
    ia.add_argument("--username", default="admin")
    ra = sub.add_parser("reset-admin", help="emergency: reset an administrator's password (prints it once)")
    ra.add_argument("--username", required=True)
    sub.add_parser("backup", help="create an encrypted backup now (passphrase from TUNNELSTEAD_BACKUP_PASSPHRASE or prompt)")
    rs = sub.add_parser("restore", help="restore a backup file (the API service must be stopped)")
    rs.add_argument("file")
    rs.add_argument("--yes", action="store_true", help="do not ask for confirmation")
    sub.add_parser("resync", help="make WireGuard/OpenVPN/firewall on this server match the database")
    a = ap.parse_args(argv)

    if a.cmd == "gen-secret":
        print(base64.urlsafe_b64encode(os.urandom(32)).decode().rstrip("="))
        return 0
    from .db import get_db, init_engine
    engine = init_engine()
    if a.cmd == "migrate":
        migrate(engine)
        print("Database schema is up to date")
        return 0
    if a.cmd == "backup":
        from . import backup
        b = backup.create(_passphrase(confirm=True), "manual")
        print(f"Backup written: {backup.backup_dir() / b['name']} ({b['size']} bytes)")
        return 0
    if a.cmd == "restore":
        from pathlib import Path

        from . import backup
        from .config import get_settings
        m, raw = backup.open_backup(Path(a.file), _passphrase(confirm=False))
        print(f"Backup from {m['created_at']} (Tunnelstead {m['app_version']}): {m['contents']}")
        if not a.yes and input("Replace ALL current data with this backup? Type 'restore': ").strip() != "restore":
            print("Cancelled; nothing changed.")
            return 1
        try:
            backup.create(_passphrase(confirm=False), "pre-restore")
        except Exception as e:  # noqa: BLE001 - empty/new install has nothing worth saving
            print(f"(no safety backup of the current data: {e})", file=sys.stderr)
        backup.write_database(raw)
        if m["secret_key"] != get_settings().secret_key:
            _set_secret_key(m["secret_key"])
            print("Adopted the secret key from the backup.")
        engine.dispose()
        migrate(engine)
        print("Restored. Start the API and run 'tunnelstead-cli resync'.")
        return 0
    if a.cmd == "resync":
        from .helper_client import Helper
        from .services import resync_all
        db = next(get_db())
        errors = resync_all(db, Helper())
        for w in errors:
            print(f"warning: {w}", file=sys.stderr)
        print("Server configuration matches the database." if not errors else "Resync finished with warnings.")
        return 1 if errors else 0
    from .models import Role, User
    from .security import generate_password, hash_password
    db = next(get_db())
    if a.cmd == "init-admin":
        if db.scalar(select(func.count()).select_from(User).where(User.role == Role.ADMIN)):
            print("An administrator already exists; nothing changed.", file=sys.stderr)
            return 0
        pw = generate_password()
        db.add(User(username=a.username.lower(), role=Role.ADMIN, password_hash=hash_password(pw),
                    must_change_password=True))
        db.commit()
        print(f"TUNNELSTEAD_ADMIN_USERNAME={a.username.lower()}\nTUNNELSTEAD_ADMIN_PASSWORD={pw}")
        return 0
    if a.cmd == "reset-admin":
        u = db.scalar(select(User).where(User.username == a.username.lower(), User.role == Role.ADMIN))
        if not u:
            print("No administrator with that username", file=sys.stderr)
            return 2
        pw = generate_password()
        u.password_hash, u.must_change_password, u.failed_logins, u.locked_until = hash_password(pw), True, 0, None
        db.commit()
        print(f"TUNNELSTEAD_ADMIN_PASSWORD={pw}")
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())
