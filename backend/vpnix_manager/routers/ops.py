"""Phase 5 operations: monitoring history, service logs, encrypted backups/restore and notifications."""
import os
from datetime import timedelta

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import select
from sqlalchemy.orm import Session as DB

from .. import audit, backup, notify
from ..db import get_db
from ..deps import client_ip, require
from ..helper_client import HelperError, get_helper
from ..models import HostMetric, InstanceMetric, Setting, User, VpnInstance, utcnow
from ..security import encrypt

router = APIRouter(prefix="/api", tags=["operations"])
RANGES = {"1h": (timedelta(hours=1), 60), "24h": (timedelta(days=1), 15 * 60), "7d": (timedelta(days=7), 3600),
          "30d": (timedelta(days=30), 4 * 3600)}


def _bucket(rows, step: int, fields: list[str], agg_max: tuple = ()) -> list[dict]:
    """Average samples into fixed time buckets (max for counters like clients online)."""
    out: dict[int, dict] = {}
    for r in rows:
        k = int(r.ts.timestamp()) // step * step
        b = out.setdefault(k, {"t": k, "_n": 0, **{f: 0.0 for f in fields}})
        b["_n"] += 1
        for f in fields:
            v = float(getattr(r, f))
            b[f] = max(b[f], v) if f in agg_max else b[f] + v
    for b in out.values():
        n = b.pop("_n")
        for f in fields:
            if f not in agg_max:
                b[f] /= n
    return [out[k] for k in sorted(out)]


@router.get("/monitoring")
def monitoring(range: str = Query("24h", pattern="^(1h|24h|7d|30d)$"), _: User = Depends(require("view")),  # noqa: A002
               db: DB = Depends(get_db)):
    span, step = RANGES[range]
    since = utcnow() - span
    if range == "1h":
        step = 60
    host = list(db.scalars(select(HostMetric).where(HostMetric.ts >= since).order_by(HostMetric.ts)))
    insts = {i.id: i for i in db.scalars(select(VpnInstance))}
    per = {}
    for iid, inst in insts.items():
        rows = list(db.scalars(select(InstanceMetric).where(InstanceMetric.instance_id == iid, InstanceMetric.ts >= since)
                               .order_by(InstanceMetric.ts)))
        avail = round(100 * sum(r.up for r in rows) / len(rows), 2) if rows else None
        per[iid] = {"id": iid, "name": inst.name, "protocol": inst.protocol, "state": inst.state.value,
                    "availability": avail, "series": _bucket(rows, step, ["rx", "tx", "online"], agg_max=("online",))}
    st = db.get(Setting, "instance_down")
    down = set(st.value.get("ids", [])) if st else set()
    latest = host[-1] if host else None
    return {"range": range, "step": step,
            "host": _bucket(host, step, ["cpu", "mem_used", "mem_total", "disk_used", "disk_total", "net_rx", "net_tx",
                                         "clients_online"], agg_max=("clients_online",)),
            "instances": list(per.values()),
            "health": {"down": [insts[i].name for i in down if i in insts], "samples": len(host),
                       "last_sample": latest.ts if latest else None}}


@router.get("/logs/services")
def service_logs(unit: str = Query("all", max_length=40), priority: str = Query("info", pattern="^(error|warning|info)$"),
                 hours: int = Query(24, ge=1, le=720), lines: int = Query(300, ge=1, le=2000),
                 q: str | None = Query(None, max_length=64), _: User = Depends(require("audit.view")),
                 db: DB = Depends(get_db), helper=Depends(get_helper)):
    units = ["vpnix-manager-api", "vpnix-manager-helper", "caddy"]
    for i in db.scalars(select(VpnInstance)):
        units.append(f"wg-quick@{i.iface}" if i.protocol == "wireguard" else f"openvpn-server@{i.iface}")
    chosen = units if unit == "all" else [unit]
    if unit != "all" and unit not in units:
        raise HTTPException(422, "Unknown service")
    try:
        entries = helper.call("sys.journal", units=chosen, lines=lines, priority=priority, since_hours=hours)["entries"]
    except HelperError as e:
        raise HTTPException(502, f"Could not read service logs: {e}") from None
    if q:
        entries = [e for e in entries if q.lower() in e["message"].lower()]
    return {"units": units, "entries": entries[::-1]}


# ---------------------------------------------------------------- backups

class BackupIn(BaseModel):
    passphrase: str = Field(min_length=12, max_length=256)


class ScheduleIn(BaseModel):
    enabled: bool
    hour: int = Field(3, ge=0, le=23)
    keep: int = Field(7, ge=1, le=90)
    passphrase: str | None = Field(None, min_length=12, max_length=256)


class RestoreIn(BaseModel):
    passphrase: str = Field(min_length=1, max_length=256)
    confirm: str | None = None


def _berr(fn):
    try:
        return fn()
    except backup.BackupError as e:
        raise HTTPException(422, str(e)) from None


@router.get("/backups")
def list_backups(_: User = Depends(require("system.manage")), db: DB = Depends(get_db)):
    st = db.get(Setting, "backup_schedule")
    cfg = st.value if st else {}
    return {"backups": _berr(backup.listing), "directory": str(_berr(backup.backup_dir)),
            "schedule": {"enabled": cfg.get("enabled", False), "hour": cfg.get("hour", 3), "keep": cfg.get("keep", 7),
                         "has_passphrase": bool(cfg.get("passphrase_enc")), "last_day": cfg.get("last_day")}}


@router.post("/backups", status_code=201)
def create_backup(body: BackupIn, request: Request, user: User = Depends(require("system.manage")), db: DB = Depends(get_db)):
    b = _berr(lambda: backup.create(body.passphrase, "manual"))
    audit.record(db, "system", "backup_created", user=user, ip=client_ip(request), target=b["name"], kind="manual")
    db.commit()
    return b


@router.put("/backups/schedule")
def set_schedule(body: ScheduleIn, request: Request, user: User = Depends(require("system.manage")), db: DB = Depends(get_db)):
    st = db.get(Setting, "backup_schedule")
    old = st.value if st else {}
    if body.enabled and not (body.passphrase or old.get("passphrase_enc")):
        raise HTTPException(422, "Set a passphrase for scheduled backups")
    value = {**old, "enabled": body.enabled, "hour": body.hour, "keep": body.keep}
    if body.passphrase:
        value["passphrase_enc"] = encrypt(body.passphrase, "backup-passphrase")
    if st:
        st.value = value
    else:
        db.add(Setting(key="backup_schedule", value=value))
    audit.record(db, "system", "backup_schedule", user=user, ip=client_ip(request), enabled=body.enabled, hour=body.hour, keep=body.keep)
    db.commit()
    return list_backups(user, db)


@router.get("/backups/{name}/download")
def download_backup(name: str, request: Request, user: User = Depends(require("system.manage")), db: DB = Depends(get_db)):
    p = _berr(lambda: backup.resolve(name))
    audit.record(db, "system", "backup_downloaded", user=user, ip=client_ip(request), target=name)
    db.commit()
    return FileResponse(p, media_type="application/octet-stream", filename=name)


@router.delete("/backups/{name}", status_code=204)
def delete_backup(name: str, request: Request, user: User = Depends(require("system.manage")), db: DB = Depends(get_db)):
    _berr(lambda: backup.resolve(name)).unlink()
    audit.record(db, "system", "backup_deleted", user=user, ip=client_ip(request), target=name)
    db.commit()


@router.post("/backups/upload", status_code=201)
async def upload_backup(request: Request, user: User = Depends(require("system.manage")), db: DB = Depends(get_db)):
    """Raw file body (application/octet-stream). Stored as-is; it is only decrypted when previewed or restored."""
    data = bytearray()
    async for chunk in request.stream():
        data += chunk
        if len(data) > backup.MAX_SIZE:
            raise HTTPException(413, "Backup file is too large")
    if not bytes(data[:8]) == backup.MAGIC:
        raise HTTPException(422, "This is not a VPNix Manager backup file")
    name = _berr(lambda: backup.unique_name("uploaded"))
    fd = os.open(backup.backup_dir() / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(bytes(data))
    audit.record(db, "system", "backup_uploaded", user=user, ip=client_ip(request), target=name)
    db.commit()
    return backup.describe(backup.backup_dir() / name)


@router.post("/backups/{name}/preview")
def preview_backup(name: str, body: RestoreIn, _: User = Depends(require("system.manage"))):
    return _berr(lambda: backup.preview(backup.resolve(name), body.passphrase))


@router.post("/backups/{name}/restore")
def restore_backup(name: str, body: RestoreIn, request: Request, user: User = Depends(require("system.manage")),
                   db: DB = Depends(get_db), helper=Depends(get_helper)):
    from .. import services
    from ..cli import migrate
    from ..db import init_engine
    path = _berr(lambda: backup.resolve(name))
    if body.confirm != name:
        raise HTTPException(422, "Type the backup name to confirm the restore")
    info = _berr(lambda: backup.preview(path, body.passphrase))
    if not info["compatible"]:
        raise HTTPException(409, "This backup was made by a newer VPNix Manager version. Update first, then restore.")
    if not info["same_secret_key"]:
        raise HTTPException(409, "This backup comes from another server. Restore it there with: "
                                 "sudo /opt/vpnix-manager/installer/restore.sh FILE")
    _, raw = backup.open_backup(path, body.passphrase)
    previous = [(i.protocol, i.iface) for i in db.scalars(select(VpnInstance))]
    safety = _berr(lambda: backup.create(body.passphrase, "pre-restore"))
    actor, ip = user.username, client_ip(request)
    db.close()
    from .. import db as dbmod
    if dbmod._engine is not None:
        dbmod._engine.dispose()
    backup.write_database(raw)
    engine = init_engine()  # fresh connections onto the restored file
    migrate(engine)
    fresh = next(get_db())
    try:
        errors = services.resync_all(fresh, helper, previous)
        audit.record(fresh, "system", "backup_restored", ip=ip, target=name, by=actor, safety_backup=safety["name"],
                     warnings=errors[:10])
        fresh.commit()
    finally:
        fresh.close()
    return {"restored": name, "safety_backup": safety["name"], "warnings": errors,
            "message": "Restored. Everyone has to sign in again with the accounts from the backup."}


# ---------------------------------------------------------------- notifications

class EmailIn(BaseModel):
    host: str = Field("", max_length=253, pattern=r"^[A-Za-z0-9.-]*$")
    port: int = Field(587, ge=1, le=65535)
    username: str = Field("", max_length=128)
    password: str | None = Field(None, max_length=256)   # None = keep the stored one, "" = remove
    sender: str = Field("", max_length=254)
    recipients: list[str] = Field(default_factory=list, max_length=10)
    starttls: bool = True


class NotifyIn(BaseModel):
    webhook_url: str = Field("", max_length=500)
    email: EmailIn = Field(default_factory=EmailIn)
    events: list[str] = Field(default_factory=list, max_length=20)

    @field_validator("webhook_url")
    @classmethod
    def https_only(cls, v: str) -> str:
        if v and not v.startswith("https://"):
            raise ValueError("The webhook URL must start with https://")
        return v


@router.get("/notifications")
def get_notifications(_: User = Depends(require("system.manage")), db: DB = Depends(get_db)):
    return notify.public_config(db)


@router.put("/notifications")
def put_notifications(body: NotifyIn, request: Request, user: User = Depends(require("system.manage")), db: DB = Depends(get_db)):
    e = body.email
    if e.host and (not e.sender or not e.recipients):
        raise HTTPException(422, "E-mail needs a sender and at least one recipient")
    email = e.model_dump(exclude={"password"})
    if e.password == "":
        notify.save_config(db, body.webhook_url, email, body.events, None)
        cfg = db.get(Setting, "notifications")
        cfg.value = {**cfg.value, "email": {k: v for k, v in cfg.value["email"].items() if k != "password_enc"}}
    else:
        notify.save_config(db, body.webhook_url, email, body.events, e.password)
    audit.record(db, "system", "notifications_updated", user=user, ip=client_ip(request), events=body.events,
                 webhook=bool(body.webhook_url), email=bool(e.host))
    db.commit()
    return notify.public_config(db)


@router.post("/notifications/test")
def test_notification(user: User = Depends(require("system.manage")), db: DB = Depends(get_db)):
    cfg = notify.get_config(db)
    if not (cfg["webhook_url"] or cfg["email"].get("host")):
        raise HTTPException(422, "Configure a webhook or e-mail first")
    errors = notify.deliver(cfg, "Test notification", f"Notifications from VPNix Manager work. Sent by {user.username}.")
    return {"ok": not errors, "errors": errors}
