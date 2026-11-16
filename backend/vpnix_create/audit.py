"""Hash-chained audit trail: altering or deleting any entry breaks every later hash."""
import hashlib
import json
from datetime import UTC

from sqlalchemy import select
from sqlalchemy.orm import Session

from .models import AuditEntry, utcnow

GENESIS = "0" * 64
FIELDS = ("actor_id", "actor", "category", "action", "target", "ip", "success", "meta")


def _digest(prev: str, ts, row: dict) -> str:
    ts = ts if ts.tzinfo else ts.replace(tzinfo=UTC)
    body = json.dumps({"ts": ts.isoformat(), **row}, sort_keys=True, default=str)
    return hashlib.sha256((prev + body).encode()).hexdigest()


def record(db: Session, category: str, action: str, *, user=None, target=None, ip=None, success=True, **meta):
    last = db.scalar(select(AuditEntry.hash).order_by(AuditEntry.id.desc()).limit(1))
    prev = last or GENESIS
    row = {"actor_id": getattr(user, "id", None), "actor": getattr(user, "username", None), "category": category,
           "action": action, "target": None if target is None else str(target), "ip": ip, "success": success,
           "meta": meta}
    ts = utcnow()
    db.add(AuditEntry(ts=ts, prev_hash=prev, hash=_digest(prev, ts, row), **row))


def verify(db: Session) -> tuple[bool, int | None]:
    prev = GENESIS
    for e in db.scalars(select(AuditEntry).order_by(AuditEntry.id)):
        row = {f: getattr(e, f) for f in FIELDS}
        if e.prev_hash != prev or e.hash != _digest(prev, e.ts, row):
            return False, e.id
        prev = e.hash
    return True, None
