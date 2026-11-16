"""Real host metrics (psutil, unprivileged), overview counters and the audit log."""
import time
from datetime import timedelta

import psutil
from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select
from sqlalchemy.orm import Session as DB

from .. import __version__, audit
from ..db import get_db
from ..deps import require
from ..models import AuditEntry, User, utcnow

router = APIRouter(prefix="/api/system", tags=["system"])
_net_prev: dict = {}


def metrics() -> dict:
    vm, du = psutil.virtual_memory(), psutil.disk_usage("/")
    net = psutil.net_io_counters()
    now = time.monotonic()
    rate = None
    if _net_prev:  # bytes/s since the previous sample (None on the very first call)
        dt = now - _net_prev["t"]
        if dt > 0:
            rate = {"rx": (net.bytes_recv - _net_prev["rx"]) / dt, "tx": (net.bytes_sent - _net_prev["tx"]) / dt}
    _net_prev.update(t=now, rx=net.bytes_recv, tx=net.bytes_sent)
    return {"cpu_percent": psutil.cpu_percent(interval=0.2), "cpu_count": psutil.cpu_count(),
            "load": list(psutil.getloadavg()), "mem_total": vm.total, "mem_used": vm.total - vm.available,
            "disk_total": du.total, "disk_used": du.used, "net_rx_total": net.bytes_recv,
            "net_tx_total": net.bytes_sent, "net_rate": rate, "uptime_s": int(time.time() - psutil.boot_time())}


@router.get("/metrics")
def get_metrics(_: User = Depends(require("view"))):
    return metrics()


@router.get("/overview")
def overview(_: User = Depends(require("view")), db: DB = Depends(get_db)):
    ok, bad = audit.verify(db)
    recent = db.scalars(select(AuditEntry).order_by(AuditEntry.id.desc()).limit(8))
    failed_24h = db.scalar(select(func.count()).select_from(AuditEntry).where(
        AuditEntry.category == "auth", AuditEntry.success.is_(False),
        AuditEntry.ts > utcnow() - timedelta(days=1)))
    return {
        "version": __version__,
        # VPN counters arrive with the WireGuard engine in Phase 2; reported as null, never faked.
        "instances": None, "clients": None,
        "audit_chain_ok": ok, "audit_first_bad": bad, "failed_logins_24h": failed_24h,
        "metrics": metrics(),
        "recent_events": [{"ts": e.ts, "actor": e.actor, "category": e.category, "action": e.action,
                           "success": e.success, "ip": e.ip} for e in recent],
    }


@router.get("/audit")
def audit_log(category: str | None = Query(None, pattern=r"^(auth|admin|vpn|system)$"),
              q: str | None = Query(None, max_length=64), limit: int = Query(100, ge=1, le=1000),
              _: User = Depends(require("audit.view")), db: DB = Depends(get_db)):
    stmt = select(AuditEntry).order_by(AuditEntry.id.desc()).limit(limit)
    if category:
        stmt = stmt.where(AuditEntry.category == category)
    if q:
        like = f"%{q}%"
        stmt = stmt.where(AuditEntry.action.like(like) | AuditEntry.actor.like(like) | AuditEntry.target.like(like))
    ok, bad = audit.verify(db)
    return {"chain_ok": ok, "first_bad": bad,
            "entries": [{"id": e.id, "ts": e.ts, "actor": e.actor, "category": e.category, "action": e.action,
                         "target": e.target, "ip": e.ip, "success": e.success, "meta": e.meta}
                        for e in db.scalars(stmt)]}
