"""VPN instances and clients. Admins manage instances; operators manage clients; viewers read (no secrets)."""
import io
import ipaddress
import re
from datetime import UTC, datetime

import qrcode
import qrcode.image.svg
from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session as DB

from .. import audit, services
from ..db import get_db
from ..deps import client_ip, require
from ..engines.registry import ENGINES, engine
from ..engines.wireguard import valid_key
from ..helper_client import HelperError, get_helper
from ..models import Client, ClientStat, ClientStatus, InstanceState, RetiredCert, User, VpnInstance, utcnow
from ..security import decrypt, encrypt

router = APIRouter(prefix="/api", tags=["vpn"])
view, manage_clients = require("view"), require("clients.manage")
manage_instances, client_secrets = require("instances.manage"), require("clients.secrets")
RECENT_S = 180  # a handshake within 3 minutes means "connected" (WireGuard has no session state)


class InstanceIn(BaseModel):
    name: str = Field(max_length=64)
    protocol: str = "wireguard"
    transport: str = "udp"
    iface: str = Field(max_length=15)
    listen_port: int
    endpoint_host: str = Field(max_length=253)
    egress_iface: str | None = Field(None, max_length=15)
    ipv4_cidr: str = Field(max_length=18)
    ipv6_cidr: str | None = Field(None, max_length=43)
    dns: list[str] = Field(default_factory=list, max_length=4)
    mtu: int = 1420
    keepalive: int = Field(25, ge=0, le=600)
    routing_mode: str = "full"
    split_routes: list[str] = Field(default_factory=list, max_length=32)
    nat: bool = True
    isolate_clients: bool = True
    start: bool = True


class InstanceEdit(BaseModel):
    name: str | None = Field(None, max_length=64)
    endpoint_host: str | None = Field(None, max_length=253)
    dns: list[str] | None = Field(None, max_length=4)
    mtu: int | None = None
    keepalive: int | None = Field(None, ge=0, le=600)
    routing_mode: str | None = None
    split_routes: list[str] | None = Field(None, max_length=32)
    nat: bool | None = None
    isolate_clients: bool | None = None


class ClientIn(BaseModel):
    instance_id: int
    name: str = Field(min_length=1, max_length=64, pattern=r"^[\w .'@()-]+$")
    description: str = Field("", max_length=500)
    tags: list[str] = Field(default_factory=list, max_length=10)
    public_key: str | None = None  # bring your own key: the server then never holds the private key
    allowed_ips: list[str] | None = Field(None, max_length=32)
    dns: list[str] | None = Field(None, max_length=4)
    keepalive: int | None = Field(None, ge=0, le=600)
    expires_at: datetime | None = None
    quota_gb: float | None = Field(None, gt=0, le=100000)


class ClientEdit(BaseModel):
    name: str | None = Field(None, min_length=1, max_length=64, pattern=r"^[\w .'@()-]+$")
    description: str | None = Field(None, max_length=500)
    tags: list[str] | None = Field(None, max_length=10)
    allowed_ips: list[str] | None = Field(None, max_length=32)
    dns: list[str] | None = Field(None, max_length=4)
    keepalive: int | None = Field(None, ge=0, le=600)
    expires_at: datetime | None = None
    clear_expiry: bool = False
    quota_gb: float | None = Field(None, gt=0, le=100000)
    clear_quota: bool = False


def _aware(dt):
    return dt if dt is None or dt.tzinfo else dt.replace(tzinfo=UTC)


def _helper_call(fn):
    try:
        return fn()
    except HelperError as e:
        raise HTTPException(502, f"The server could not apply the change: {e}") from None


def _inst(db: DB, iid: int) -> VpnInstance:
    i = db.get(VpnInstance, iid)
    if not i:
        raise HTTPException(404, "VPN instance not found")
    return i


def _client(db: DB, cid: int) -> Client:
    c = db.get(Client, cid)
    if not c:
        raise HTTPException(404, "Client not found")
    return c


def connected(c: Client) -> bool:
    return bool(c.last_handshake and (utcnow() - _aware(c.last_handshake)).total_seconds() < RECENT_S)


def inst_out(db: DB, i: VpnInstance, live: dict | None = None) -> dict:
    clients = list(db.scalars(select(Client).where(Client.instance_id == i.id)))
    return {"id": i.id, "name": i.name, "protocol": i.protocol, "transport": i.transport, "iface": i.iface,
            "listen_port": i.listen_port, "endpoint_host": i.endpoint_host, "egress_iface": i.egress_iface,
            "ipv4_cidr": i.ipv4_cidr, "ipv6_cidr": i.ipv6_cidr, "dns": i.dns, "mtu": i.mtu, "keepalive": i.keepalive,
            "routing_mode": i.routing_mode, "split_routes": i.split_routes, "nat": i.nat,
            "isolate_clients": i.isolate_clients, "public_key": i.public_key, "state": i.state.value,
            "ca_expires_at": i.ca_expires_at, "server_cert_expires_at": i.server_cert_expires_at,
            "live": live, "clients_total": len(clients),
            "clients_active": sum(c.status == ClientStatus.ACTIVE for c in clients),
            "clients_connected": sum(connected(c) for c in clients),
            "rx_bytes": sum(c.rx_bytes for c in clients), "tx_bytes": sum(c.tx_bytes for c in clients),
            "created_at": i.created_at}


def client_out(db: DB, c: Client) -> dict:
    i = db.get(VpnInstance, c.instance_id)
    return {"id": c.id, "instance_id": c.instance_id, "instance_name": i.name, "name": c.name,
            "description": c.description, "tags": c.tags, "public_key": c.public_key, "ipv4": c.ipv4, "ipv6": c.ipv6,
            "allowed_ips": c.allowed_ips, "dns": c.dns, "keepalive": c.keepalive, "status": c.status.value,
            "connected": connected(c), "expires_at": c.expires_at,
            "quota_bytes": c.quota_bytes, "rx_bytes": c.rx_bytes, "tx_bytes": c.tx_bytes,
            "last_handshake": c.last_handshake, "last_endpoint": c.last_endpoint,
            "has_private_key": c.private_key_enc is not None, "created_at": c.created_at, "protocol": i.protocol,
            "cert_expires_at": c.cert_expires_at}


def _validate_routes(routes: list[str] | None):
    for r in routes or []:
        try:
            ipaddress.ip_network(r, strict=False)
        except ValueError:
            raise HTTPException(422, f"{r} is not a valid network") from None


def _validate_dns(dns: list[str] | None):
    for d in dns or []:
        try:
            ipaddress.ip_address(d)
        except ValueError:
            raise HTTPException(422, f"{d} is not a valid DNS server address") from None


# ------------------------------------------------------------------ helpers for the wizard
@router.get("/network/facts")
def network_facts(_: User = Depends(manage_instances), helper=Depends(get_helper)):
    return _helper_call(lambda: {"interfaces": helper.call("net.interfaces"), "system": helper.call("sys.status"),
                                 "dns_presets": services.DNS_PRESETS, "protocols": sorted(ENGINES)})


@router.get("/instances/recommend")
def recommend(protocol: str = Query("wireguard", pattern=r"^[a-z]{2,16}$"), transport: str = Query("udp", pattern=r"^(udp|tcp)$"),
              _: User = Depends(manage_instances), db: DB = Depends(get_db), helper=Depends(get_helper)):
    try:
        engine(protocol)
    except ValueError as e:
        raise HTTPException(422, str(e)) from None
    return _helper_call(lambda: services.recommend(db, helper, protocol, transport))


@router.get("/instances/port-check")
def port_check(port: int = Query(ge=1024, le=65535), transport: str = Query("udp", pattern=r"^(udp|tcp)$"),
               exclude_id: int | None = None, _: User = Depends(manage_instances), db: DB = Depends(get_db),
               helper=Depends(get_helper)):
    msg = _helper_call(lambda: services.port_free(helper, db, port, transport, exclude_id))
    return {"free": msg is None, "message": msg or f"{transport.upper()} {port} is free"}


@router.post("/instances/validate")
def validate_instance(body: InstanceIn, _: User = Depends(manage_instances), db: DB = Depends(get_db),
                      helper=Depends(get_helper)):
    chk = _helper_call(lambda: services.validate(db, helper, body.model_dump()))
    return {"ok": chk.ok, "errors": chk.errors, "warnings": chk.warnings, "preview": _preview(body)}


def _preview(body: InstanceIn) -> dict:
    """Human-readable summary of what deployment will do (no secrets)."""
    full = body.routing_mode == "full"
    return {
        "server_config": [f"Interface {body.iface} listening on {body.transport.upper()} {body.listen_port}",
                          f"Tunnel network {body.ipv4_cidr}" + (f" and {body.ipv6_cidr}" if body.ipv6_cidr else ""),
                          f"MTU {body.mtu}, PersistentKeepalive {body.keepalive or 'off'}"],
        "client_routes": (["All IPv4 traffic (0.0.0.0/0)"] + (["All IPv6 traffic (::/0)"] if body.ipv6_cidr else [])) if full
        else [body.ipv4_cidr] + ([body.ipv6_cidr] if body.ipv6_cidr else []) + body.split_routes,
        "firewall": [f"Allow {body.transport.upper()} {body.listen_port} inbound",
                     "Forward traffic from VPN clients"
                     + (f" and NAT it out of {body.egress_iface or 'the default interface'}" if body.nat else ""),
                     "Block client-to-client traffic" if body.isolate_clients else "Allow client-to-client traffic",
                     "Enable IP forwarding (IPv4" + (" and IPv6)" if body.ipv6_cidr else ")")],
        "dns": body.dns or ["clients keep their own DNS"],
    }


# ------------------------------------------------------------------ instances
@router.get("/instances")
def list_instances(_: User = Depends(view), db: DB = Depends(get_db), helper=Depends(get_helper)):
    out = []
    for i in db.scalars(select(VpnInstance).order_by(VpnInstance.name)):
        try:
            live = engine(i.protocol).status(helper, i)
        except HelperError:
            live = None  # shown as "status unavailable", never guessed
        out.append(inst_out(db, i, live))
    return out


@router.get("/instances/{iid}")
def get_instance(iid: int, _: User = Depends(view), db: DB = Depends(get_db), helper=Depends(get_helper)):
    inst = _inst(db, iid)
    try:
        live = engine(inst.protocol).status(helper, inst)
    except HelperError:
        live = None  # shown as "status unavailable", never guessed
    return inst_out(db, inst, live)


@router.post("/instances", status_code=201)
def create_instance(body: InstanceIn, request: Request, user: User = Depends(manage_instances), db: DB = Depends(get_db),
                    helper=Depends(get_helper)):
    chk = _helper_call(lambda: services.validate(db, helper, body.model_dump()))
    if not chk.ok:
        raise HTTPException(422, {"errors": chk.errors, "warnings": chk.warnings})
    eng = engine(body.protocol)
    priv, pub = eng.create_keys(body.iface)
    data = body.model_dump(exclude={"start"})
    data["name"] = data["name"].strip()
    inst = VpnInstance(**data, private_key_enc="", public_key=pub,
                       state=InstanceState.RUNNING if body.start else InstanceState.STOPPED)
    db.add(inst)
    db.flush()
    inst.private_key_enc = encrypt(priv, f"instance:{inst.id}")
    if hasattr(eng, "cert_expiry"):
        exp = eng.cert_expiry(priv)
        inst.ca_expires_at, inst.server_cert_expires_at = exp["ca"], exp["server"]
    try:
        services.sync(db, helper, inst)
        if body.start:
            eng.start(helper, inst)
    except HelperError as e:
        db.rollback()
        _helper_call(lambda: eng.delete(helper, inst))  # leave nothing half-deployed
        raise HTTPException(502, f"Deployment failed and was rolled back: {e}") from None
    audit.record(db, "vpn", "instance_create", user=user, ip=client_ip(request), target=inst.name, iface=inst.iface,
                 port=inst.listen_port)
    db.commit()
    return inst_out(db, inst)


@router.patch("/instances/{iid}")
def edit_instance(iid: int, body: InstanceEdit, request: Request, user: User = Depends(manage_instances),
                  db: DB = Depends(get_db), helper=Depends(get_helper)):
    inst = _inst(db, iid)
    current = {k: getattr(inst, k) for k in InstanceIn.model_fields if k != "start"}
    current.update(body.model_dump(exclude_none=True))
    chk = _helper_call(lambda: services.validate(db, helper, current, exclude_id=inst.id))
    if not chk.ok:
        raise HTTPException(422, {"errors": chk.errors, "warnings": chk.warnings})
    for k, v in body.model_dump(exclude_none=True).items():
        setattr(inst, k, v.strip() if isinstance(v, str) else v)
    _helper_call(lambda: services.sync(db, helper, inst))
    audit.record(db, "vpn", "instance_edit", user=user, ip=client_ip(request), target=inst.name,
                 changes=sorted(body.model_dump(exclude_none=True)))
    db.commit()
    return inst_out(db, inst)


@router.post("/instances/{iid}/{action}")
def instance_action(iid: int, action: str, request: Request, user: User = Depends(manage_instances),
                    db: DB = Depends(get_db), helper=Depends(get_helper)):
    if action not in ("start", "stop", "restart"):
        raise HTTPException(404, "Unknown action")
    inst = _inst(db, iid)
    eng = engine(inst.protocol)
    if action == "stop":
        _helper_call(lambda: eng.stop(helper, inst))
        inst.state = InstanceState.STOPPED
    else:
        inst.state = InstanceState.RUNNING
        _helper_call(lambda: services.sync(db, helper, inst))
        _helper_call(lambda: eng.start(helper, inst))
    _helper_call(lambda: services.sync_firewall(db, helper))
    audit.record(db, "vpn", f"instance_{action}", user=user, ip=client_ip(request), target=inst.name)
    db.commit()
    return inst_out(db, inst, _helper_call(lambda: eng.status(helper, inst)))


@router.delete("/instances/{iid}", status_code=204)
def delete_instance(iid: int, request: Request, confirm: str = Query(...), user: User = Depends(manage_instances),
                    db: DB = Depends(get_db), helper=Depends(get_helper)):
    inst = _inst(db, iid)
    if confirm != inst.name:
        raise HTTPException(422, "Type the instance name to confirm deletion")
    _helper_call(lambda: engine(inst.protocol).delete(helper, inst))
    audit.record(db, "vpn", "instance_delete", user=user, ip=client_ip(request), target=inst.name, iface=inst.iface)
    db.delete(inst)
    db.flush()
    _helper_call(lambda: services.sync_firewall(db, helper))
    db.commit()


# ------------------------------------------------------------------ clients
@router.get("/clients")
def list_clients(instance_id: int | None = None, q: str | None = Query(None, max_length=64), _: User = Depends(view),
                 db: DB = Depends(get_db)):
    stmt = select(Client).order_by(Client.name)
    if instance_id:
        stmt = stmt.where(Client.instance_id == instance_id)
    rows = [client_out(db, c) for c in db.scalars(stmt)]
    if q:
        ql = q.lower()
        rows = [r for r in rows if ql in (r["name"] + r["description"] + " ".join(r["tags"]) + r["ipv4"]).lower()]
    return rows


@router.post("/clients", status_code=201)
def create_client(body: ClientIn, request: Request, user: User = Depends(manage_clients), db: DB = Depends(get_db),
                  helper=Depends(get_helper)):
    inst = _inst(db, body.instance_id)
    _validate_routes(body.allowed_ips)
    _validate_dns(body.dns)
    eng = engine(inst.protocol)
    secret = decrypt(inst.private_key_enc, f"instance:{inst.id}")
    if body.public_key:
        if not eng.supports_own_key:
            raise HTTPException(422, f"{inst.protocol} clients use certificates issued by this server; leave the key empty")
        if not valid_key(body.public_key):
            raise HTTPException(422, "That is not a valid WireGuard public key")
        creds = {"private_key": None, "public_key": body.public_key, "psk": eng.new_client_credentials(secret)["psk"]}
    else:
        creds = eng.new_client_credentials(secret)
    if db.scalar(select(Client).where(Client.public_key == creds["public_key"])):
        raise HTTPException(409, "That public key is already in use")
    try:
        v4, v6 = services.allocate_ip(db, inst)
    except ValueError as e:
        raise HTTPException(409, str(e)) from None
    tags = [t.strip()[:24] for t in body.tags if t.strip()]
    c = Client(instance_id=inst.id, name=body.name.strip(), description=body.description, tags=tags,
               public_key=creds["public_key"], psk_enc="", ipv4=v4, ipv6=v6, allowed_ips=body.allowed_ips, dns=body.dns,
               keepalive=body.keepalive, expires_at=body.expires_at,
               quota_bytes=int(body.quota_gb * 1024**3) if body.quota_gb else None)
    db.add(c)
    db.flush()
    c.psk_enc = encrypt(creds["psk"], f"client-psk:{c.id}")
    if creds["private_key"]:
        c.private_key_enc = encrypt(creds["private_key"], f"client-key:{c.id}")
    _set_identity(c, inst, creds)
    try:
        services.sync(db, helper, inst)
    except HelperError as e:
        db.rollback()
        raise HTTPException(502, f"The server could not add the client: {e}") from None
    audit.record(db, "vpn", "client_create", user=user, ip=client_ip(request), target=c.name, instance=inst.name)
    db.commit()
    return client_out(db, c)


@router.patch("/clients/{cid}")
def edit_client(cid: int, body: ClientEdit, request: Request, user: User = Depends(manage_clients), db: DB = Depends(get_db),
                helper=Depends(get_helper)):
    c = _client(db, cid)
    _validate_routes(body.allowed_ips)
    _validate_dns(body.dns)
    data = body.model_dump(exclude_none=True, exclude={"clear_expiry", "clear_quota", "quota_gb"})
    for k, v in data.items():
        setattr(c, k, v)
    if body.quota_gb:
        c.quota_bytes = int(body.quota_gb * 1024**3)
    if body.clear_quota:
        c.quota_bytes = None
    if body.clear_expiry:
        c.expires_at = None
    # Lifting an expiry or quota that had blocked the client re-activates it.
    if c.status in (ClientStatus.EXPIRED, ClientStatus.OVER_QUOTA) and not _blocked(c):
        c.status = ClientStatus.ACTIVE
    _helper_call(lambda: services.sync(db, helper, db.get(VpnInstance, c.instance_id)))
    audit.record(db, "vpn", "client_edit", user=user, ip=client_ip(request), target=c.name)
    db.commit()
    return client_out(db, c)


def _set_identity(c: Client, inst: VpnInstance, creds: dict) -> None:
    """How live statistics find this client, and when its certificate expires (OpenVPN)."""
    if inst.protocol == "openvpn":
        from .. import pki
        i = pki.info(creds["psk"])
        c.stats_key, c.cert_expires_at = i["cn"], i["not_after"]
    else:
        c.stats_key = creds["public_key"]
    c.session_rx = c.session_tx = None


def _blocked(c: Client) -> ClientStatus | None:
    if c.expires_at and _aware(c.expires_at) <= utcnow():
        return ClientStatus.EXPIRED
    if c.quota_bytes and c.rx_bytes + c.tx_bytes >= c.quota_bytes:
        return ClientStatus.OVER_QUOTA
    return None


@router.post("/clients/{cid}/{action}")
def client_action(cid: int, action: str, request: Request, user: User = Depends(manage_clients), db: DB = Depends(get_db),
                  helper=Depends(get_helper)):
    c = _client(db, cid)
    inst = db.get(VpnInstance, c.instance_id)
    if action not in ("enable", "disable", "revoke", "regenerate"):
        raise HTTPException(404, "Unknown action")
    if c.status == ClientStatus.REVOKED:
        raise HTTPException(409, "Revoked clients cannot be changed; create a new client instead")
    if action == "enable":
        if blocked := _blocked(c):
            raise HTTPException(409, f"Client is {blocked.value.replace('_', ' ')}: change its expiry or quota first")
        c.status = ClientStatus.ACTIVE
    elif action == "disable":
        c.status = ClientStatus.DISABLED
    elif action == "revoke":
        c.status = ClientStatus.REVOKED
        c.private_key_enc = None  # nothing left to download
    else:
        old_cert = decrypt(c.psk_enc, f"client-psk:{c.id}")
        creds = engine(inst.protocol).new_client_credentials(decrypt(inst.private_key_enc, f"instance:{inst.id}"))
        c.public_key = creds["public_key"]
        c.private_key_enc = encrypt(creds["private_key"], f"client-key:{c.id}")
        c.psk_enc = encrypt(creds["psk"], f"client-psk:{c.id}")
        _set_identity(c, inst, creds)
        if inst.protocol == "openvpn":  # the old certificate must never work again: keep it on the CRL
            db.add(RetiredCert(instance_id=inst.id, cert_enc=encrypt(old_cert, f"retired:{inst.id}")))
    try:
        services.sync(db, helper, inst)  # removed from / re-added to the live interface before we report success
    except HelperError as e:
        db.rollback()
        raise HTTPException(502, f"The server could not apply the change: {e}") from None
    audit.record(db, "vpn", f"client_{action}", user=user, ip=client_ip(request), target=c.name)
    db.commit()
    return client_out(db, c)


@router.delete("/clients/{cid}", status_code=204)
def delete_client(cid: int, request: Request, user: User = Depends(manage_clients), db: DB = Depends(get_db),
                  helper=Depends(get_helper)):
    c = _client(db, cid)
    inst = db.get(VpnInstance, c.instance_id)
    name = c.name
    db.delete(c)
    db.flush()
    try:
        services.sync(db, helper, inst)
    except HelperError as e:
        db.rollback()
        raise HTTPException(502, f"The server could not remove the client: {e}") from None
    audit.record(db, "vpn", "client_delete", user=user, ip=client_ip(request), target=name)
    db.commit()


def _config(db: DB, cid: int) -> tuple[Client, str]:
    c = _client(db, cid)
    if c.status == ClientStatus.REVOKED:
        raise HTTPException(409, "This client is revoked")
    if not c.private_key_enc:
        raise HTTPException(410, "The private key is not stored on the server (bring-your-own key). Use the device's own config.")
    inst = db.get(VpnInstance, c.instance_id)
    return c, engine(inst.protocol).render_client_config(inst, c, decrypt(c.private_key_enc, f"client-key:{c.id}"),
                                                         decrypt(c.psk_enc, f"client-psk:{c.id}"),
                                                         decrypt(inst.private_key_enc, f"instance:{inst.id}"))


@router.get("/clients/{cid}/config")
def download_config(cid: int, request: Request, user: User = Depends(client_secrets), db: DB = Depends(get_db)):
    c, text = _config(db, cid)
    audit.record(db, "vpn", "client_config_download", user=user, ip=client_ip(request), target=c.name)
    db.commit()
    safe = re.sub(r"[^A-Za-z0-9_-]+", "-", c.name).strip("-")[:40] or f"client-{c.id}"
    ext = engine(db.get(VpnInstance, c.instance_id).protocol).file_ext
    return Response(text, media_type="text/plain", headers={"Content-Disposition": f'attachment; filename="{safe}.{ext}"'})


@router.get("/clients/{cid}/qr")
def config_qr(cid: int, request: Request, user: User = Depends(client_secrets), db: DB = Depends(get_db)):
    if not engine(db.get(VpnInstance, _client(db, cid).instance_id).protocol).supports_qr:
        raise HTTPException(409, "OpenVPN profiles are too large for a QR code; download the .ovpn file instead")
    c, text = _config(db, cid)
    buf = io.BytesIO()
    qrcode.make(text, image_factory=qrcode.image.svg.SvgPathImage, box_size=10).save(buf)
    audit.record(db, "vpn", "client_qr_view", user=user, ip=client_ip(request), target=c.name)
    db.commit()
    return Response(buf.getvalue(), media_type="image/svg+xml")


@router.get("/clients/{cid}/stats")
def client_stats(cid: int, hours: int = Query(24, ge=1, le=720), _: User = Depends(view), db: DB = Depends(get_db)):
    _client(db, cid)
    since = utcnow().timestamp() - hours * 3600
    rows = [r for r in db.scalars(select(ClientStat).where(ClientStat.client_id == cid).order_by(ClientStat.ts))
            if _aware(r.ts).timestamp() >= since]
    pts, prev = [], None
    for r in rows:
        if prev:
            pts.append({"ts": r.ts, "rx": max(0, r.rx_bytes - prev.rx_bytes), "tx": max(0, r.tx_bytes - prev.tx_bytes)})
        prev = r
    return {"points": pts}


@router.get("/vpn/summary")
def vpn_summary(_: User = Depends(view), db: DB = Depends(get_db)):
    insts = list(db.scalars(select(VpnInstance)))
    clients = list(db.scalars(select(Client)))
    return {"instances": len(insts), "running": sum(i.state == InstanceState.RUNNING for i in insts),
            "stopped": sum(i.state == InstanceState.STOPPED for i in insts), "clients": len(clients),
            "connected": sum(connected(c) for c in clients),
            "rx_bytes": db.scalar(select(func.coalesce(func.sum(Client.rx_bytes), 0))),
            "tx_bytes": db.scalar(select(func.coalesce(func.sum(Client.tx_bytes), 0)))}


@router.get("/certificates")
def certificates(_: User = Depends(view), db: DB = Depends(get_db)):
    """Expiry overview of every certificate Tunnelstead issued (no key material)."""
    now, out = utcnow(), []

    def row(kind, name, instance, expires):
        days = int((_aware(expires) - now).total_seconds() // 86400) if expires else None
        state = "unknown" if days is None else "expired" if days < 0 else "expiring" if days <= 30 else "ok"
        out.append({"kind": kind, "name": name, "instance": instance, "expires_at": expires, "days_left": days, "state": state})
    for i in db.scalars(select(VpnInstance).where(VpnInstance.protocol == "openvpn")):
        row("ca", f"{i.name} CA", i.name, i.ca_expires_at)
        row("server", f"{i.name} server", i.name, i.server_cert_expires_at)
        for c in db.scalars(select(Client).where(Client.instance_id == i.id, Client.status != ClientStatus.REVOKED)):
            row("client", c.name, i.name, c.cert_expires_at)
    return sorted(out, key=lambda r: (r["days_left"] is None, r["days_left"] or 0))
