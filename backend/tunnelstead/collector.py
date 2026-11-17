"""Background work: real WireGuard statistics, plus expiry and quota enforcement. Nothing is simulated."""
import asyncio
import logging
import time
from datetime import UTC, datetime, timedelta

from sqlalchemy import delete, select
from sqlalchemy.orm import Session as DB

from . import audit, notify, services
from .engines.registry import engine
from .helper_client import HelperError
from .models import Client, ClientStat, ClientStatus, HostMetric, InstanceMetric, InstanceState, Setting, UserSession, VpnInstance, utcnow

log = logging.getLogger("tunnelstead.collector")
INTERVAL = 30
RETENTION = timedelta(days=30)
_prev: dict = {}   # instance id -> (monotonic time, total rx, total tx) for throughput rates


def _aware(dt):
    return dt if dt is None or dt.tzinfo else dt.replace(tzinfo=UTC)


def collect(db: DB, helper) -> dict:
    out = {"instances": 0, "clients_updated": 0, "blocked": 0, "errors": 0}
    for inst in db.scalars(select(VpnInstance).where(VpnInstance.state == InstanceState.RUNNING)):
        eng = engine(inst.protocol)
        up = _service_up(db, helper, inst)
        try:
            peers = {p["key"]: p for p in eng.collect_stats(helper, inst)} if up else {}
        except HelperError as e:
            log.warning("stats for %s failed: %s", inst.name, e)
            out["errors"] += 1
            peers = {}
        out["instances"] += 1
        clients = list(db.scalars(select(Client).where(Client.instance_id == inst.id)))
        for c in clients:
            p = peers.get(c.stats_key or c.public_key)
            if not p:
                c.session_rx = c.session_tx = None  # not connected: the next session starts from zero
                continue
            if eng.session_counters:
                # OpenVPN counts per session: add what changed since the last sample (a new session restarts at 0).
                same = (c.session_rx is not None and c.last_endpoint == p["endpoint"]
                        and p["rx_bytes"] >= c.session_rx and p["tx_bytes"] >= c.session_tx)
                c.rx_bytes += p["rx_bytes"] - (c.session_rx if same else 0)
                c.tx_bytes += p["tx_bytes"] - (c.session_tx if same else 0)
                c.session_rx, c.session_tx = p["rx_bytes"], p["tx_bytes"]
            else:
                # WireGuard counters restart with the interface; keep lifetime totals monotonic.
                c.rx_bytes, c.tx_bytes = max(c.rx_bytes, p["rx_bytes"]), max(c.tx_bytes, p["tx_bytes"])
            if p.get("latest_handshake"):
                c.last_handshake = datetime.fromtimestamp(p["latest_handshake"], UTC)
            elif p.get("connected"):
                c.last_handshake = utcnow()  # listed in the live session table right now
            c.last_endpoint = p.get("endpoint")
            db.add(ClientStat(client_id=c.id, rx_bytes=c.rx_bytes, tx_bytes=c.tx_bytes))
            out["clients_updated"] += 1
        _instance_sample(db, inst, clients, up)
    db.commit()
    from .routers.firewall import reconcile
    reconcile(db, helper)
    out["blocked"] = enforce(db, helper)
    return out


def _service_up(db: DB, helper, inst) -> bool:
    """A server that should run but does not raises one alert, and one more when it recovers."""
    try:
        up = bool(engine(inst.protocol).status(helper, inst).get("active"))
    except HelperError:
        return True  # helper unreachable: unknown, not "down"
    st = db.get(Setting, "instance_down")
    down = set(st.value.get("ids", [])) if st else set()
    if not up and inst.id not in down:
        down.add(inst.id)
        audit.record(db, "system", "instance_down", target=inst.name, success=False)
        notify.notify(db, "instance_down", f"{inst.name} ({inst.protocol}, {inst.iface}) is not running.", key=str(inst.id))
    elif up and inst.id in down:
        down.discard(inst.id)
        audit.record(db, "system", "instance_recovered", target=inst.name)
        notify.clear(db, "instance_down", str(inst.id))
        notify.notify(db, "instance_recovered", f"{inst.name} is running again.", key=str(inst.id))
    if st:
        st.value = {"ids": sorted(down)}
    elif down:
        db.add(Setting(key="instance_down", value={"ids": sorted(down)}))
    return up


def _instance_sample(db: DB, inst, clients, up: bool) -> None:
    from .routers.vpn import connected
    now, rx, tx = time.monotonic(), sum(c.rx_bytes for c in clients), sum(c.tx_bytes for c in clients)
    prev = _prev.get(inst.id)
    _prev[inst.id] = (now, rx, tx)
    if not prev or now <= prev[0]:
        return  # first sample after start: no rate yet
    dt = now - prev[0]
    db.add(InstanceMetric(instance_id=inst.id, rx=max(0, rx - prev[1]) / dt, tx=max(0, tx - prev[2]) / dt,
                          online=sum(connected(c) for c in clients), up=up))


def host_sample(db: DB) -> None:
    from .routers.system import metrics
    from .routers.vpn import connected
    m = metrics()
    rate = m["net_rate"] or {"rx": 0.0, "tx": 0.0}
    db.add(HostMetric(cpu=m["cpu_percent"], mem_used=m["mem_used"], mem_total=m["mem_total"], disk_used=m["disk_used"],
                      disk_total=m["disk_total"], net_rx=rate["rx"], net_tx=rate["tx"],
                      clients_online=sum(connected(c) for c in db.scalars(select(Client)))))
    if m["disk_total"] and m["disk_used"] / m["disk_total"] > 0.9:
        notify.notify(db, "disk_full", f"Disk is {m['disk_used'] * 100 // m['disk_total']} % full.")
    db.commit()


def check_certificates(db: DB) -> None:
    soon = utcnow() + timedelta(days=30)
    for i in db.scalars(select(VpnInstance).where(VpnInstance.protocol == "openvpn")):
        for label, exp in (("CA", i.ca_expires_at), ("server certificate", i.server_cert_expires_at)):
            if exp and _aware(exp) <= soon:
                notify.notify(db, "cert_expiring", f"The {label} of {i.name} expires on {_aware(exp):%Y-%m-%d}.", key=f"{i.id}:{label}")
    for c in db.scalars(select(Client).where(Client.cert_expires_at.is_not(None), Client.status == ClientStatus.ACTIVE)):
        if _aware(c.cert_expires_at) <= soon:
            notify.notify(db, "cert_expiring", f"The certificate of client {c.name} expires on {_aware(c.cert_expires_at):%Y-%m-%d}.", key=f"c{c.id}")


def scheduled_backup(db: DB) -> str | None:
    """Daily at the configured UTC hour, at most once per day; keeps the newest N scheduled backups."""
    from . import backup
    from .security import decrypt
    st = db.get(Setting, "backup_schedule")
    cfg = st.value if st else {}
    now = datetime.now(UTC)
    if not cfg.get("enabled") or now.hour != cfg.get("hour", 3) or cfg.get("last_day") == now.strftime("%Y-%m-%d"):
        return None
    st.value = {**cfg, "last_day": now.strftime("%Y-%m-%d")}
    db.commit()
    try:
        b = backup.create(decrypt(cfg["passphrase_enc"], "backup-passphrase"), "scheduled")
        backup.prune(int(cfg.get("keep", 7)))
        audit.record(db, "system", "backup_created", target=b["name"], kind="scheduled")
        notify.notify(db, "backup_ok", f"Backup {b['name']} ({b['size']} bytes) created.", key=b["name"])
        db.commit()
        return b["name"]
    except Exception as e:  # noqa: BLE001 - alert instead of crashing the loop
        log.exception("scheduled backup failed")
        audit.record(db, "system", "backup_failed", success=False, error=str(e)[:200])
        notify.notify(db, "backup_failed", f"The scheduled backup failed: {e}", key=now.strftime("%Y-%m-%d"))
        db.commit()
        return None


def update_result(db: DB) -> None:
    """Report the outcome of an update once (the updater only writes a status file)."""
    from . import updates
    st = updates.status()
    if st.get("state") not in ("success", "rolled_back", "failed"):
        return
    seen = db.get(Setting, "update_reported")
    if seen and seen.value.get("at") == st.get("updated_at"):
        return
    if seen:
        seen.value = {"at": st.get("updated_at")}
    else:
        db.add(Setting(key="update_reported", value={"at": st.get("updated_at")}))
    ok = st["state"] == "success" or (st["state"] == "rolled_back" and st.get("manual"))
    audit.record(db, "system", f"update_{st['state']}", success=ok, target=st.get("version") or st.get("running"),
                 error=st.get("error"))
    db.commit()
    if st["state"] == "success":
        notify.notify(db, "update_done", f"Updated from {st.get('previous')} to {st.get('version')}.", key=st.get("updated_at"))
    elif not st.get("manual"):
        notify.notify(db, "update_failed", f"Update to {st.get('version')} failed: {st.get('error')}. "
                      f"Version {st.get('running')} is running.", key=st.get("updated_at"))


def enforce(db: DB, helper) -> int:
    """Expired or over-quota clients are removed from the live interface, then marked."""
    now, changed = utcnow(), {}  # type: tuple[datetime, dict[int, list[Client]]]
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
            notify.notify(db, "client_blocked", f"Client {c.name} was blocked: {c.status.value.replace('_', ' ')}.", key=str(c.id))
    db.commit()
    return sum(len(v) for v in changed.values())


def prune(db: DB) -> None:
    cutoff = utcnow() - RETENTION
    db.execute(delete(ClientStat).where(ClientStat.ts < cutoff))
    db.execute(delete(HostMetric).where(HostMetric.ts < cutoff))
    db.execute(delete(InstanceMetric).where(InstanceMetric.ts < cutoff))
    db.execute(delete(UserSession).where(UserSession.expires_at < utcnow()))
    db.commit()


async def run_forever(make_db, make_helper) -> None:
    n = 0
    while True:
        def cycle(n=n):
            db = make_db()
            try:
                collect(db, make_helper())
                host_sample(db)
                scheduled_backup(db)
                update_result(db)
                if n % 20 == 0:  # every ~10 min: periodic check (cached 6 h) and the auto-update window
                    from . import updates
                    updates.scheduled(db, make_helper())
                if n % 120 == 0:
                    prune(db)
                    check_certificates(db)
            except Exception:  # keep the loop alive; logged with traceback
                log.exception("collector cycle failed")
            finally:
                db.close()
        await asyncio.to_thread(cycle)
        n += 1
        await asyncio.sleep(INTERVAL)
