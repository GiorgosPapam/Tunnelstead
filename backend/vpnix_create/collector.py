"""Background work: real WireGuard statistics, plus expiry and quota enforcement. Nothing is simulated."""
import asyncio
import logging
from datetime import UTC, datetime, timedelta

from sqlalchemy import delete, select
from sqlalchemy.orm import Session as DB

from . import audit, services
from .engines.registry import engine
from .helper_client import HelperError
from .models import Client, ClientStat, ClientStatus, InstanceState, UserSession, VpnInstance, utcnow

log = logging.getLogger("vpnix.collector")
INTERVAL = 30
RETENTION = timedelta(days=30)


def _aware(dt):
    return dt if dt is None or dt.tzinfo else dt.replace(tzinfo=UTC)


def collect(db: DB, helper) -> dict:
    out = {"instances": 0, "clients_updated": 0, "blocked": 0, "errors": 0}
    for inst in db.scalars(select(VpnInstance).where(VpnInstance.state == InstanceState.RUNNING)):
        try:
            peers = {p["public_key"]: p for p in engine(inst.protocol).collect_stats(helper, inst)}
        except HelperError as e:
            log.warning("stats for %s failed: %s", inst.name, e)
            out["errors"] += 1
            continue
        out["instances"] += 1
        for c in db.scalars(select(Client).where(Client.instance_id == inst.id)):
            p = peers.get(c.public_key)
            if not p:
                continue
            # Kernel counters restart with the interface; keep lifetime totals monotonic.
            c.rx_bytes, c.tx_bytes = max(c.rx_bytes, p["rx_bytes"]), max(c.tx_bytes, p["tx_bytes"])
            if p.get("latest_handshake"):
                c.last_handshake = datetime.fromtimestamp(p["latest_handshake"], UTC)
            c.last_endpoint = p.get("endpoint")
            db.add(ClientStat(client_id=c.id, rx_bytes=c.rx_bytes, tx_bytes=c.tx_bytes))
            out["clients_updated"] += 1
    db.commit()
    out["blocked"] = enforce(db, helper)
    return out


def enforce(db: DB, helper) -> int:
    """Expired or over-quota clients are removed from the live interface, then marked."""
    now, changed = utcnow(), {}
    for c in db.scalars(select(Client).where(Client.status == ClientStatus.ACTIVE)):
        status = (ClientStatus.EXPIRED if c.expires_at and _aware(c.expires_at) <= now else
                  ClientStatus.OVER_QUOTA if c.quota_bytes and c.rx_bytes + c.tx_bytes >= c.quota_bytes else None)
        if status:
            c.status = status
            changed.setdefault(c.instance_id, []).append(c)
    for iid, clients in changed.items():
        try:
            services.sync(db, helper, db.get(VpnInstance, iid))
        except HelperError as e:
            log.warning("could not block clients on instance %s: %s", iid, e)
            db.rollback()  # retried next cycle; never marked blocked while still live
            return 0
        for c in clients:
            audit.record(db, "vpn", f"client_{c.status.value}", target=c.name)
    db.commit()
    return sum(len(v) for v in changed.values())


def prune(db: DB) -> None:
    cutoff = utcnow() - RETENTION
    db.execute(delete(ClientStat).where(ClientStat.ts < cutoff))
    db.execute(delete(UserSession).where(UserSession.expires_at < utcnow()))
    db.commit()


async def run_forever(make_db, make_helper) -> None:
    n = 0
    while True:
        def cycle(n=n):
            db = make_db()
            try:
                collect(db, make_helper())
                if n % 120 == 0:
                    prune(db)
            except Exception:  # keep the loop alive; logged with traceback
                log.exception("collector cycle failed")
            finally:
                db.close()
        await asyncio.to_thread(cycle)
        n += 1
        await asyncio.sleep(INTERVAL)
