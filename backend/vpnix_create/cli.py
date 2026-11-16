"""vpnix-create-cli: installer-side operations. Never reachable over HTTP."""
import argparse
import base64
import os
import sys

from sqlalchemy import func, select

ALEMBIC_INI = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "alembic.ini")


def migrate(engine) -> None:
    from alembic import command
    from alembic.config import Config
    cfg = Config(ALEMBIC_INI)
    cfg.set_main_option("sqlalchemy.url", engine.url.render_as_string(hide_password=False).replace("%", "%%"))
    command.upgrade(cfg, "head")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="vpnix-create-cli")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("gen-secret", help="print a new VPNIX_SECRET_KEY")
    sub.add_parser("migrate", help="apply database migrations (safe to re-run)")
    ia = sub.add_parser("init-admin", help="create the first administrator with a random temporary password")
    ia.add_argument("--username", default="admin")
    ra = sub.add_parser("reset-admin", help="emergency: reset an administrator's password (prints it once)")
    ra.add_argument("--username", required=True)
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
        print(f"VPNIX_ADMIN_USERNAME={a.username.lower()}\nVPNIX_ADMIN_PASSWORD={pw}")
        return 0
    if a.cmd == "reset-admin":
        u = db.scalar(select(User).where(User.username == a.username.lower(), User.role == Role.ADMIN))
        if not u:
            print("No administrator with that username", file=sys.stderr)
            return 2
        pw = generate_password()
        u.password_hash, u.must_change_password, u.failed_logins, u.locked_until = hash_password(pw), True, 0, None
        db.commit()
        print(f"VPNIX_ADMIN_PASSWORD={pw}")
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())
