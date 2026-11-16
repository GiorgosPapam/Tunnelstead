"""Firewall and network health. Every firewall change is applied with a timed automatic rollback: it only stays
if the administrator confirms it from the browser within the window, so a lock-out undoes itself."""
import ipaddress
import re
import time
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session as DB

from .. import audit, services
from ..db import get_db
from ..deps import client_ip, require
from ..helper_client import HelperError, get_helper
from ..models import Client, ClientStatus, FirewallRule, InstanceState, Setting, User, VpnInstance

router = APIRouter(prefix="/api", tags=["firewall"])
view, manage = require("view"), require("firewall.manage")
ROLLBACK_SECONDS = 60
COMMENT_RE = re.compile(r"^[A-Za-z0-9 _.,:()-]{0,64}$")
PRIVATE_V4 = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
ROUTING_PRESETS: dict[str, dict[str, Any]] = {
    "full": {"label": "Full tunnel", "mode": "full", "routes": [],
             "explain": "All internet traffic (IPv4 and, with an IPv6 subnet, IPv6) goes through the VPN."},
    "vpn_only": {"label": "VPN network only", "mode": "split", "routes": [],
                 "explain": "Only traffic to the VPN subnet uses the tunnel; everything else goes direct."},
    "private": {"label": "Private networks (LAN access)", "mode": "split", "routes": PRIVATE_V4,
                "explain": "Reach private networks behind the server (10/8, 172.16/12, 192.168/16) through the VPN; internet goes direct."},
    "custom": {"label": "Custom networks", "mode": "split", "routes": None,
               "explain": "Only the networks you list (plus the VPN subnet) use the tunnel."},
}


class RuleIn(BaseModel):
    action: str = Field(pattern=r"^(accept|drop)$")
    proto: str = Field(pattern=r"^(tcp|udp|any)$")
    ports: str | None = Field(None, pattern=r"^\d{1,5}(-\d{1,5})?$")
    source: str | None = Field(None, max_length=43)
    comment: str = Field("", max_length=64)


class ManagementIn(BaseModel):
    enabled: bool
    networks: list[str] = Field(default_factory=list, max_length=64)
    include_ssh: bool = False
    i_understand_lockout_risk: bool = False


class ConfirmIn(BaseModel):
    token: str = Field(min_length=10, max_length=64)


def _validate_rule(r: RuleIn) -> RuleIn:
    if r.ports:
        lo, _, hi = r.ports.partition("-")
        if not 1 <= int(lo) <= 65535 or (hi and not int(lo) < int(hi) <= 65535):
            raise HTTPException(422, "Ports must be 1-65535 (a range as low-high)")
        if r.proto == "any":
            raise HTTPException(422, "Choose TCP or UDP when you specify ports")
    if r.source:
        try:
            r.source = str(ipaddress.ip_network(r.source, strict=False))
        except ValueError:
            raise HTTPException(422, "Source must be an IP address or network (CIDR)") from None
    if not COMMENT_RE.match(r.comment):
        raise HTTPException(422, "Comment: letters, numbers, spaces and . , : ( ) - _ only")
    return r


def _snapshot(db: DB) -> dict:
    m = db.get(Setting, "management")
    return {"rules": [{"position": r.position, "action": r.action, "proto": r.proto, "ports": r.ports, "source": r.source,
                       "comment": r.comment, "enabled": r.enabled} for r in db.scalars(select(FirewallRule))],
            "management": m.value if m else None}


def _restore(db: DB, snap: dict) -> None:
    db.query(FirewallRule).delete()
    for r in snap["rules"]:
        db.add(FirewallRule(**r))
    m = db.get(Setting, "management")
    if snap["management"] is None:
        if m:
            db.delete(m)
    elif m:
        m.value = snap["management"]
    else:
        db.add(Setting(key="management", value=snap["management"]))


def reconcile(db: DB, helper) -> None:
    """If a change was not confirmed in time, the helper already restored the old table: restore the DB to match."""
    pend = db.get(Setting, "fw_pending")
    if not pend or pend.value["deadline"] > time.time():
        return
    try:
        still = helper.call("fw.pending")["pending"]
    except HelperError:
        return
    if not still:
        _restore(db, pend.value["previous"])
        db.delete(pend)
        audit.record(db, "system", "firewall_rolled_back", success=False)
        db.commit()
        from .. import notify
        notify.notify(db, "firewall_rolled_back", "A firewall change was not confirmed within 60 seconds and was undone automatically.")


def _apply_with_rollback(db: DB, helper, previous: dict, user: User, request: Request, event: str, **meta) -> dict:
    try:
        r = services.sync_firewall(db, helper, rollback_seconds=ROLLBACK_SECONDS)
    except HelperError as e:
        db.rollback()
        raise HTTPException(502, f"The firewall change was not applied: {e}") from None
    pend = db.get(Setting, "fw_pending")
    value = {"token": r["confirm_token"], "deadline": time.time() + ROLLBACK_SECONDS, "previous": previous}
    if pend:  # a newer change supersedes the older unconfirmed one; keep the oldest known-good snapshot
        value["previous"] = pend.value["previous"]
        pend.value = value
    else:
        db.add(Setting(key="fw_pending", value=value))
    audit.record(db, "admin", event, user=user, ip=client_ip(request), **meta)
    db.commit()
    return {"confirm_token": r["confirm_token"], "rollback_seconds": ROLLBACK_SECONDS}


@router.get("/firewall")
def firewall_state(request: Request, _: User = Depends(view), db: DB = Depends(get_db), helper=Depends(get_helper)):
    reconcile(db, helper)
    m = db.get(Setting, "management")
    pend = db.get(Setting, "fw_pending")
    try:
        ruleset, own = helper.call("fw.ruleset")["ruleset"], helper.call("fw.show")["ruleset"]
    except HelperError as e:
        ruleset, own = f"(unavailable: {e})", ""
    insts = list(db.scalars(select(VpnInstance).where(VpnInstance.state == InstanceState.RUNNING)))
    return {
        "rules": [{"id": r.id, "action": r.action, "proto": r.proto, "ports": r.ports, "source": r.source, "comment": r.comment,
                   "enabled": r.enabled} for r in db.scalars(select(FirewallRule).order_by(FirewallRule.position, FirewallRule.id))],
        "management": m.value if m else {"enabled": False, "networks": [], "include_ssh": False},
        "your_ip": client_ip(request),
        "pending": {"seconds_left": max(0, int(pend.value["deadline"] - time.time()))} if pend else None,
        "managed_ports": [{"instance": i.name, "port": i.listen_port, "transport": i.transport} for i in insts],
        "own_table": own, "host_ruleset": ruleset,
    }


@router.post("/firewall/rules", status_code=201)
def add_rule(body: RuleIn, request: Request, user: User = Depends(manage), db: DB = Depends(get_db), helper=Depends(get_helper)):
    reconcile(db, helper)
    body = _validate_rule(body)
    prev = _snapshot(db)
    pos = (db.scalar(select(func.max(FirewallRule.position))) or 0) + 1
    db.add(FirewallRule(position=pos, **body.model_dump()))
    db.flush()
    return _apply_with_rollback(db, helper, prev, user, request, "firewall_rule_add", rule=body.model_dump())


@router.patch("/firewall/rules/{rid}")
def toggle_rule(rid: int, enabled: bool, request: Request, user: User = Depends(manage), db: DB = Depends(get_db),
                helper=Depends(get_helper)):
    reconcile(db, helper)
    r = db.get(FirewallRule, rid)
    if not r:
        raise HTTPException(404, "Rule not found")
    prev = _snapshot(db)
    r.enabled = enabled
    db.flush()
    return _apply_with_rollback(db, helper, prev, user, request, "firewall_rule_toggle", rule=rid, enabled=enabled)


@router.delete("/firewall/rules/{rid}")
def delete_rule(rid: int, request: Request, user: User = Depends(manage), db: DB = Depends(get_db), helper=Depends(get_helper)):
    reconcile(db, helper)
    r = db.get(FirewallRule, rid)
    if not r:
        raise HTTPException(404, "Rule not found")
    prev = _snapshot(db)
    db.delete(r)
    db.flush()
    return _apply_with_rollback(db, helper, prev, user, request, "firewall_rule_delete", rule=rid)


@router.put("/firewall/management")
def set_management(body: ManagementIn, request: Request, user: User = Depends(manage), db: DB = Depends(get_db),
                   helper=Depends(get_helper)):
    reconcile(db, helper)
    nets = []
    for n in body.networks:
        try:
            nets.append(ipaddress.ip_network(n, strict=False))
        except ValueError:
            raise HTTPException(422, f"{n} is not a valid network") from None
    if body.enabled and not nets:
        raise HTTPException(422, "Add at least one allowed network")
    try:
        me = ipaddress.ip_address(client_ip(request))
    except ValueError:
        me = None  # unknown client address: cannot check, rely on the timed rollback
    if body.enabled and me and not any(me in n for n in nets) and not body.i_understand_lockout_risk:
        raise HTTPException(409, f"Your current address {me} is not in the allowed networks: this would lock you out. "
                                 "Add it, or confirm that you understand the risk.")
    prev = _snapshot(db)
    value = {"enabled": body.enabled, "networks": [str(n) for n in nets], "include_ssh": body.include_ssh}
    m = db.get(Setting, "management")
    if m:
        m.value = value
    else:
        db.add(Setting(key="management", value=value))
    db.flush()
    return _apply_with_rollback(db, helper, prev, user, request, "firewall_management", **value)


@router.post("/firewall/confirm")
def confirm(body: ConfirmIn, request: Request, user: User = Depends(manage), db: DB = Depends(get_db), helper=Depends(get_helper)):
    pend = db.get(Setting, "fw_pending")
    if not pend or pend.value["token"] != body.token:
        reconcile(db, helper)
        raise HTTPException(409, "Nothing to confirm: the change was already rolled back")
    try:
        helper.call("fw.confirm", token=body.token)
    except HelperError as e:
        reconcile(db, helper)
        raise HTTPException(409, f"Too late, the change was rolled back: {e}") from None
    db.delete(pend)
    audit.record(db, "admin", "firewall_confirm", user=user, ip=client_ip(request))
    db.commit()
    return {"ok": True}


# ---------------------------------------------------------------- network health and routing
@router.get("/network/checks")
def network_checks(_: User = Depends(view), db: DB = Depends(get_db), helper=Depends(get_helper)):
    try:
        sysst, own = helper.call("sys.status"), helper.call("fw.show")["ruleset"]
    except HelperError as e:
        raise HTTPException(502, f"System helper unavailable: {e}") from None
    out = []
    for i in db.scalars(select(VpnInstance).order_by(VpnInstance.name)):
        running = i.state == InstanceState.RUNNING
        full = i.routing_mode == "full"
        checks = [
            ("IPv4 forwarding", sysst["ipv4_forwarding"], "Required to route client traffic.", "error"),
            ("Firewall allows the VPN port", (not running) or f"{i.transport} dport {i.listen_port}" in own,
             f"{i.transport.upper()} {i.listen_port} must be open here and in your provider's firewall.", "error"),
            ("NAT for internet access", (not full) or (not i.nat) or "masquerade" in own,
             "Full-tunnel clients need NAT to reach the internet.", "error"),
            ("IPv6 leak protection", (not full) or bool(i.ipv6_cidr),
             "Full tunnel without an IPv6 subnet: client IPv6 traffic bypasses the VPN unless the client blocks it.", "warning"),
            ("IPv6 forwarding", (not i.ipv6_cidr) or sysst["ipv6_forwarding"], "Needed to route the IPv6 subnet.", "error"),
            ("DNS leak protection", (not full) or bool(i.dns), "Full tunnel without DNS servers: lookups may go to the local network.", "warning"),
            ("Client isolation", i.isolate_clients, "Clients can reach each other on this VPN.", "info"),
        ]
        out.append({"instance": i.name, "id": i.id, "state": i.state.value, "routing_mode": i.routing_mode,
                    "checks": [{"name": n, "ok": bool(ok), "detail": d, "severity": sev} for n, ok, d, sev in checks]})
    return out


@router.get("/network/presets")
def routing_presets(_: User = Depends(view)):
    return ROUTING_PRESETS


class RoutingIn(BaseModel):
    preset: str = Field(pattern=r"^(full|vpn_only|private|custom)$")
    routes: list[str] = Field(default_factory=list, max_length=32)
    apply: bool = False


@router.post("/instances/{iid}/routing")
def change_routing(iid: int, body: RoutingIn, request: Request, user: User = Depends(require("instances.manage")),
                   db: DB = Depends(get_db), helper=Depends(get_helper)):
    """Preview (apply=false) or apply a routing preset. Shows the client routes before/after and which clients must
    re-import their configuration (client routes live in the client config)."""
    from ..engines.wireguard import client_routes
    inst = db.get(VpnInstance, iid)
    if not inst:
        raise HTTPException(404, "VPN instance not found")
    p = ROUTING_PRESETS[body.preset]
    routes = body.routes if p["routes"] is None else p["routes"]
    for r in routes:
        try:
            ipaddress.ip_network(r, strict=False)
        except ValueError:
            raise HTTPException(422, f"{r} is not a valid network") from None

    class _Shadow:  # the instance as it would look after the change
        pass
    after = _Shadow()
    after.__dict__.update({k: getattr(inst, k) for k in ("ipv4_cidr", "ipv6_cidr")}, routing_mode=p["mode"], split_routes=routes)
    clients = list(db.scalars(select(Client).where(Client.instance_id == iid, Client.status != ClientStatus.REVOKED)))
    affected = [c.name for c in clients if not c.allowed_ips]  # clients with their own routes keep them
    preview = {"before": client_routes(inst, type("C", (), {"allowed_ips": None})()),
               "after": client_routes(after, type("C", (), {"allowed_ips": None})()),
               "affected_clients": affected, "explain": p["explain"]}
    if not body.apply:
        return preview
    inst.routing_mode, inst.split_routes = p["mode"], routes
    try:
        services.sync(db, helper, inst)
    except HelperError as e:
        db.rollback()
        raise HTTPException(502, f"The server could not apply the change: {e}") from None
    audit.record(db, "vpn", "instance_routing", user=user, ip=client_ip(request), target=inst.name, preset=body.preset)
    db.commit()
    return {**preview, "applied": True}
