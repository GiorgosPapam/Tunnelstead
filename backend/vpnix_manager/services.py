"""VPN instance and client logic: validation, conflict detection, recommendations, IP allocation, sync."""
import ipaddress
import re
from collections.abc import Sequence
from dataclasses import dataclass, field

from sqlalchemy import select
from sqlalchemy.orm import Session as DB

from .engines.registry import engine
from .engines.wireguard import gateway
from .models import Client, ClientStatus, InstanceState, VpnInstance
from .security import decrypt

NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 _.-]{1,63}$")
HOST_RE = re.compile(r"^(?=.{1,253}$)([A-Za-z0-9-]{1,63}\.)*[A-Za-z0-9-]{1,63}$")
DNS_PRESETS = {
    "cloudflare": ["1.1.1.1", "1.0.0.1", "2606:4700:4700::1111"],
    "quad9": ["9.9.9.9", "149.112.112.112", "2620:fe::fe"],
    "google": ["8.8.8.8", "8.8.4.4", "2001:4860:4860::8888"],
}


@dataclass
class Check:
    errors: dict = field(default_factory=dict)    # field -> message (blocks deployment)
    warnings: list = field(default_factory=list)  # informational

    @property
    def ok(self):
        return not self.errors


def host_facts(helper) -> dict:
    """Live state of the server, so conflicts with things VPNix did not create are detected too."""
    ifaces = helper.call("net.interfaces")
    # Every tunnel config on the host (managed or foreign), for conflict detection across protocols.
    tunnels = helper.call("net.wg_interfaces")["interfaces"] + helper.call("net.ovpn_interfaces")["interfaces"]
    return {"interfaces": ifaces, "wg": tunnels,
            "addresses": [a for i in ifaces["interfaces"] for a in i["addresses"]]}


def port_free(helper, db: DB, port: int, transport: str, exclude_id: int | None = None) -> str | None:
    clash = db.scalar(select(VpnInstance).where(VpnInstance.listen_port == port, VpnInstance.transport == transport,
                                                VpnInstance.id != (exclude_id or 0)))
    if clash:
        return f"{transport.upper()} {port} is used by VPN instance '{clash.name}'"
    if helper.call("net.port_in_use", port=port, transport=transport)["in_use"]:
        mine = exclude_id and db.get(VpnInstance, exclude_id)
        if not (mine and mine.listen_port == port and mine.transport == transport):
            return f"{transport.upper()} {port} is already in use by another program on this server"
    return None


def recommend(db: DB, helper, protocol: str = "wireguard", transport: str = "udp") -> dict:
    eng = engine(protocol)
    lo, hi = eng.port_range
    port = next((p for p in range(lo, hi) if port_free(helper, db, p, transport) is None), None)
    facts = host_facts(helper)
    taken = {i.iface for i in db.scalars(select(VpnInstance))} | {w["name"] for w in facts["wg"]} | \
            {i["name"] for i in facts["interfaces"]["interfaces"]}
    iface = next(f"{eng.iface_prefix}{n}" for n in range(1000) if f"{eng.iface_prefix}{n}" not in taken)
    used = [ipaddress.ip_network(i.ipv4_cidr) for i in db.scalars(select(VpnInstance))] + \
           [ipaddress.ip_interface(a).network for a in facts["addresses"] if ipaddress.ip_interface(a).version == 4]
    subnet = next(str(n) for k in range(8, 255) for n in [ipaddress.ip_network(f"10.{k}.0.0/24")]
                  if not any(n.overlaps(u) for u in used))
    k6 = int(subnet.split(".")[1])
    return {"port": port, "transport": transport, "iface": iface, "ipv4_cidr": subnet,
            "ipv6_cidr": f"fd{k6:02x}:{k6:x}::/64", "egress_iface": facts["interfaces"]["default"],
            "port_note": f"{protocol} uses {transport.upper()}. Suggestions skip ports already used on this server."}


def validate(db: DB, helper, data: dict, exclude_id: int | None = None) -> Check:
    c = Check()
    try:
        eng = engine(data.get("protocol", "wireguard"))
    except ValueError as e:
        c.errors["protocol"] = str(e)
        return c
    name = (data.get("name") or "").strip()
    if not NAME_RE.match(name):
        c.errors["name"] = "2-64 characters: letters, numbers, space, dot, dash or underscore"
    elif db.scalar(select(VpnInstance).where(VpnInstance.name == name, VpnInstance.id != (exclude_id or 0))):
        c.errors["name"] = "Another instance already has this name"
    transport = data.get("transport", "udp")
    if transport not in eng.transports:
        c.errors["transport"] = f"{eng.protocol} supports {', '.join(sorted(eng.transports)).upper()} only"
    port = data.get("listen_port")
    if not isinstance(port, int) or not 1024 <= port <= 65535:
        c.errors["listen_port"] = "Choose a port between 1024 and 65535"
    elif "transport" not in c.errors and (msg := port_free(helper, db, port, transport, exclude_id)):
        c.errors["listen_port"] = msg
    facts = host_facts(helper)
    iface = data.get("iface", "")
    if not re.fullmatch(rf"{eng.iface_prefix}[0-9]{{1,3}}", iface or ""):
        c.errors["iface"] = f"Use {eng.iface_prefix}0 … {eng.iface_prefix}999"
    elif db.scalar(select(VpnInstance).where(VpnInstance.iface == iface, VpnInstance.id != (exclude_id or 0))):
        c.errors["iface"] = "Another VPN instance uses this interface"
    elif not exclude_id and any(w["name"] == iface for w in facts["wg"]):
        c.errors["iface"] = f"{iface} already exists on this server (not created by VPNix Manager); it will not be touched"
    elif not exclude_id and any(i["name"] == iface for i in facts["interfaces"]["interfaces"]):
        c.errors["iface"] = f"A network interface named {iface} already exists"
    others = [i for i in db.scalars(select(VpnInstance)) if i.id != exclude_id]
    ours = {i.iface for i in db.scalars(select(VpnInstance))}  # VPNix interfaces: covered by the DB check above
    host_nets = [ipaddress.ip_interface(a).network for i in facts["interfaces"]["interfaces"]
                 if i["name"] not in ours for a in i["addresses"]]
    for key, version in (("ipv4_cidr", 4), ("ipv6_cidr", 6)):
        val = data.get(key)
        if not val:
            if key == "ipv4_cidr":
                c.errors[key] = "An IPv4 subnet is required"
            continue
        try:
            net = ipaddress.ip_network(val, strict=True)
        except ValueError:
            c.errors[key] = "Not a valid network (example: 10.8.0.0/24)" if version == 4 else "Not a valid IPv6 network"
            continue
        ula = ipaddress.IPv6Network("fc00::/7")
        if net.version != version or not net.is_private or (
                isinstance(net, ipaddress.IPv6Network) and not net.subnet_of(ula)):
            c.errors[key] = "Use a private range (10.x, 172.16-31.x, 192.168.x)" if version == 4 else "Use a ULA range (fd00::/8)"
        elif version == 4 and not 16 <= net.prefixlen <= 29:
            c.errors[key] = "Use a /16 to /29 network"
        elif version == 6 and not 64 <= net.prefixlen <= (112 if eng.protocol == "openvpn" else 120):
            c.errors[key] = f"Use a /64 to /{112 if eng.protocol == 'openvpn' else 120} network"
        else:
            for o in others:
                theirs = o.ipv4_cidr if version == 4 else o.ipv6_cidr
                if theirs and net.overlaps(ipaddress.ip_network(theirs)):
                    c.errors[key] = f"Overlaps {theirs} used by '{o.name}'"
            for hn in host_nets:
                if hn.version == version and net.overlaps(hn):
                    c.errors[key] = f"Overlaps {hn}, already used by a network interface on this server"
    host = (data.get("endpoint_host") or "").strip()
    try:
        ipaddress.ip_address(host)
    except ValueError:
        if not HOST_RE.match(host):
            c.errors["endpoint_host"] = "Enter the public IP address or DNS name clients connect to"
    for d in data.get("dns") or []:
        try:
            ipaddress.ip_address(d)
        except ValueError:
            c.errors["dns"] = f"{d} is not an IP address"
    if not 1280 <= int(data.get("mtu", 1420)) <= 1500:
        c.errors["mtu"] = "MTU must be 1280-1500 (WireGuard 1420, OpenVPN 1500)"
    if data.get("routing_mode", "full") not in ("full", "split"):
        c.errors["routing_mode"] = "Choose full or split tunnel"
    for r in data.get("split_routes") or []:
        try:
            ipaddress.ip_network(r, strict=False)
        except ValueError:
            c.errors["split_routes"] = f"{r} is not a valid network"
    egress = data.get("egress_iface")
    if egress and egress not in {i["name"] for i in facts["interfaces"]["interfaces"]}:
        c.errors["egress_iface"] = "That network interface does not exist"
    if data.get("routing_mode", "full") == "full":
        if not data.get("nat", True):
            c.warnings.append("Full tunnel without NAT only works if your network routes the VPN subnet back to this server.")
        if not data.get("ipv6_cidr"):
            c.warnings.append("No IPv6 subnet: clients route IPv6 outside the tunnel unless they block it (possible IPv6 leak).")
        if not data.get("dns"):
            c.warnings.append("No DNS servers: clients keep using their local DNS, which can leak lookups.")
    return c


def allocate_ip(db: DB, inst: VpnInstance) -> tuple[str, str | None]:
    used = {c.ipv4 for c in db.scalars(select(Client).where(Client.instance_id == inst.id))}
    gw4 = gateway(inst.ipv4_cidr)
    v4 = next((str(h) for h in ipaddress.ip_network(inst.ipv4_cidr).hosts() if str(h) not in used and str(h) != gw4),
              None)
    if v4 is None:
        raise ValueError(f"No free addresses left in {inst.ipv4_cidr}")
    v6 = None
    if inst.ipv6_cidr:  # mirror the IPv4 host number, so both addresses are easy to match
        offset = int(ipaddress.ip_address(v4)) - int(ipaddress.ip_network(inst.ipv4_cidr).network_address)
        v6 = str(ipaddress.ip_network(inst.ipv6_cidr).network_address + offset)
    return v4, v6


def sync(db: DB, helper, inst: VpnInstance) -> None:
    """Push the instance's complete desired state to the server, then refresh the firewall."""
    clients = list(db.scalars(select(Client).where(Client.instance_id == inst.id)))
    active = [{"public_key": c.public_key, "psk": decrypt(c.psk_enc, f"client-psk:{c.id}"), "ipv4": c.ipv4,
               "ipv6": c.ipv6} for c in clients if c.status == ClientStatus.ACTIVE]
    # Certificates of every non-active client go on the CRL (OpenVPN); WireGuard ignores this list.
    # Regenerated (retired) certificates stay on the CRL too, so an old .ovpn file never works again.
    inactive = []
    if inst.protocol == "openvpn":
        from .models import RetiredCert
        inactive = [decrypt(c.psk_enc, f"client-psk:{c.id}") for c in clients if c.status != ClientStatus.ACTIVE]
        inactive += [decrypt(r.cert_enc, f"retired:{inst.id}")
                     for r in db.scalars(select(RetiredCert).where(RetiredCert.instance_id == inst.id))]
    engine(inst.protocol).apply(helper, inst, active, decrypt(inst.private_key_enc, f"instance:{inst.id}"), inactive)
    sync_firewall(db, helper)


def firewall_config(db: DB) -> tuple[list[dict], dict | None]:
    from .models import FirewallRule, Setting
    rules = [{"action": r.action, "proto": r.proto, "ports": r.ports, "source": r.source, "comment": r.comment}
             for r in db.scalars(select(FirewallRule).where(FirewallRule.enabled.is_(True)).order_by(FirewallRule.position, FirewallRule.id))]
    m = db.get(Setting, "management")
    mgmt = None
    if m and m.value.get("enabled") and m.value.get("networks"):
        mgmt = {"networks": m.value["networks"], "ports": [80, 443] + ([22] if m.value.get("include_ssh") else [])}
    return rules, mgmt


def sync_firewall(db: DB, helper, rollback_seconds: int | None = None) -> dict:
    insts = list(db.scalars(select(VpnInstance).where(VpnInstance.state == InstanceState.RUNNING)))
    egress = next((i.egress_iface for i in insts if i.egress_iface), None)
    if any(i.nat for i in insts):
        helper.call("sys.forwarding", ipv4=True, ipv6=any(i.ipv6_cidr for i in insts))
    rules, mgmt = firewall_config(db)
    return helper.call("fw.apply", egress=egress, custom_rules=rules, management=mgmt, rollback_seconds=rollback_seconds, instances=[
        {"iface": i.iface, "port": i.listen_port, "transport": i.transport, "nat": i.nat,
         "isolate_clients": i.isolate_clients, "subnets": [s for s in (i.ipv4_cidr, i.ipv6_cidr) if s]} for i in insts])


def resync_all(db: DB, helper, previous: Sequence[tuple[str, str]] = ()) -> list[str]:
    """After a restore: make the server match the database. Removes managed interfaces that are no longer in it
    (`previous` = (protocol, iface) pairs that existed before), redeploys every instance and the firewall."""
    from .engines.registry import engine as eng_for
    errors, now = [], {i.iface: i for i in db.scalars(select(VpnInstance))}
    for proto, iface in previous:
        if iface not in now:
            try:
                eng_for(proto).delete(helper, type("I", (), {"iface": iface})())
            except Exception as e:  # noqa: BLE001 - collected and reported
                errors.append(f"remove {iface}: {e}")
    for inst in now.values():
        eng = eng_for(inst.protocol)
        try:
            sync(db, helper, inst)
            (eng.start if inst.state == InstanceState.RUNNING else eng.stop)(helper, inst)
        except Exception as e:  # noqa: BLE001
            errors.append(f"{inst.name}: {e}")
    try:
        sync_firewall(db, helper)
    except Exception as e:  # noqa: BLE001
        errors.append(f"firewall: {e}")
    return errors
