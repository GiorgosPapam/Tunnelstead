from sqlalchemy import create_engine, event
from sqlalchemy.orm import DeclarativeBase, sessionmaker

from .config import get_settings


class Base(DeclarativeBase):
    pass


_engine = None
_Session = None


def init_engine(url: str | None = None):
    global _engine, _Session
    url = url or get_settings().database_url
    sqlite = url.startswith("sqlite")
    kw = {"connect_args": {"check_same_thread": False, "timeout": 15}} if sqlite else {"pool_pre_ping": True}
    _engine = create_engine(url, **kw)
    if url.startswith("sqlite"):
        @event.listens_for(_engine, "connect")
        def _pragmas(conn, _):
            cur = conn.cursor()
            cur.execute("PRAGMA foreign_keys=ON")
            cur.execute("PRAGMA journal_mode=WAL")  # readers do not block the writer
            cur.close()
    _Session = sessionmaker(_engine, expire_on_commit=False)
    return _engine


def get_db():
    if _Session is None:
        init_engine()
    db = _Session()
    try:
        yield db
    finally:
        db.close()
