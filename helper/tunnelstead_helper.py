#!/usr/bin/env python3
"""tunnelstead-helper: the ONLY Tunnelstead component that runs as root.

Listens on /run/tunnelstead/helper.sock (0660 root:tunnelstead) and serves a fixed allowlist of operations.
Rules enforced here, independently of the API:
  * every argument is validated (interface names, ports, keys, CIDRs, addresses) before anything happens;
  * external programs are run with argv lists only, never a shell;
  * WireGuard operations only touch interfaces whose config file carries the Tunnelstead marker, so
    pre-existing, hand-made WireGuard setups are never modified (module isolation);
  * firewall operations only replace the application's own nftables table.
Standard library only, so the privileged code has no third-party dependencies.
"""
import base64
import ipaddress
import json
import os
import re
import socketserver
import subprocess
import sys
from typing import Any

SOCKET = os.environ.get("TUNNELSTEAD_HELPER_SOCKET", "/run/tunnelstead/helper.sock")
WG_DIR = "/etc/wireguard"
MARKER = "# Managed by Tunnelstead - do not edit by hand"
NFT_TABLE = "tunnelstead"
WG_IFACE = re.compile(r"^wg[0-9]{1,3}$")
TUN_IFACE = re.compile(r"^(wg|ovpn)[0-9]{1,3}$")  # interfaces the firewall may reference
ANY_IFACE = re.compile(r"^[a-zA-Z0-9_.:-]{1,15}$")
BIN = {"wg": "/usr/bin/wg", "wg-quick": "/usr/bin/wg-quick", "ip": "/usr/sbin/ip", "ss": "/usr/bin/ss",
       "nft": "/usr/sbin/nft", "systemctl": "/usr/bin/systemctl", "sysctl": "/usr/sbin/sysctl",
       "journalctl": "/usr/bin/journalctl"}


class Invalid(ValueError):
    pass


# ---------------------------------------------------------------- validation
def v_wg_iface(x):
    if not isinstance(x, str) or not WG_IFACE.match(x):
        raise Invalid("WireGuard interface must look like wg0 … wg999")
    return x


def v_iface(x):
    if not isinstance(x, str) or not ANY_IFACE.match(x):
        raise Invalid("bad interface name")
    return x


def v_port(x):
    if isinstance(x, int) and not isinstance(x, bool) and 1 <= x <= 65535:
        return x
    raise Invalid("bad port")


def v_key(x):
    try:
        if isinstance(x, str) and len(base64.b64decode(x, validate=True)) == 32:
            return x
    except ValueError:
        pass
    raise Invalid("bad key")


def v_ifaddr(x):
    return str(ipaddress.ip_interface(x))


def v_host_cidr(x):
    n = ipaddress.ip_network(x, strict=True)
    if n.prefixlen != n.max_prefixlen:
        raise Invalid("peer AllowedIPs on the server must be single addresses")
    return str(n)


def v_net(x):
    return str(ipaddress.ip_network(x, strict=True))


def run(name, *args, stdin=None, check=True):
    r = subprocess.run([BIN[name], *args], input=stdin, capture_output=True, text=True, timeout=30)
    if check and r.returncode:
        raise RuntimeError(f"{name} failed: {(r.stderr or r.stdout).strip()[:300]}")
    return r


def _conf_path(iface):
    return os.path.join(WG_DIR, f"{iface}.conf")


def _managed(iface) -> bool:
    try:
        with open(_conf_path(iface)) as f:
            return f.readline().rstrip("\n") == MARKER
    except FileNotFoundError:
        return False


def _require_managed_or_free(iface):
    exists = os.path.exists(_conf_path(iface)) or run("ip", "link", "show", iface, check=False).returncode == 0
    if exists and not _managed(iface):
        raise Invalid(f"{iface} exists and is not managed by Tunnelstead; refusing to touch it")


def _write_secret(path, content):
    tmp = path + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(content)
    os.replace(tmp, path)


# ---------------------------------------------------------------- network facts
def net_interfaces():
    out = json.loads(run("ip", "-j", "addr").stdout or "[]")
    route = run("ip", "-j", "route", "show", "default", check=False).stdout
    default = (json.loads(route or "[]") or [{}])[0].get("dev")
    return {"default": default, "interfaces": [
        {"name": i["ifname"], "up": "UP" in i.get("flags", []), "managed_wg": _managed(i["ifname"]),
         "addresses": [f"{a['local']}/{a['prefixlen']}" for a in i.get("addr_info", [])]}
        for i in out if i["ifname"] != "lo"]}


def net_port_in_use(port, transport):
    port = v_port(port)
    if transport not in ("udp", "tcp"):
        raise Invalid("transport must be udp or tcp")
    r = run("ss", "-H", "-ln", "-u" if transport == "udp" else "-t", f"sport = :{port}", check=False)
    return {"in_use": bool(r.stdout.strip())}


def net_wg_interfaces():
    """Every WireGuard interface on the host (managed or not), for conflict detection."""
    names = set(run("wg", "show", "interfaces", check=False).stdout.split())
    if os.path.isdir(WG_DIR):
        names |= {f[:-5] for f in os.listdir(WG_DIR) if f.endswith(".conf")}
    return {"interfaces": [{"name": n, "managed": _managed(n)} for n in sorted(names)]}


# ---------------------------------------------------------------- WireGuard
def wg_sync(iface, listen_port, private_key, addresses, mtu, peers):
    """Write the complete desired state and apply it live with `wg syncconf` (no reconnect for others)."""
    iface, listen_port, private_key = v_wg_iface(iface), v_port(listen_port), v_key(private_key)
    addresses = [v_ifaddr(a) for a in addresses][:4]
    if not addresses or not (isinstance(mtu, int) and 1280 <= mtu <= 1500):
        raise Invalid("addresses and MTU 1280-1500 required")
    if not isinstance(peers, list) or len(peers) > 5000:
        raise Invalid("bad peer list")
    lines = [MARKER, "[Interface]", f"PrivateKey = {private_key}", f"ListenPort = {listen_port}",
             f"Address = {', '.join(addresses)}", f"MTU = {mtu}", ""]
    for p in peers:
        lines += ["[Peer]", f"PublicKey = {v_key(p['public_key'])}"]
        if p.get("preshared_key"):
            lines.append(f"PresharedKey = {v_key(p['preshared_key'])}")
        lines += [f"AllowedIPs = {', '.join(v_host_cidr(a) for a in p['allowed_ips'][:4])}", ""]
    _require_managed_or_free(iface)  # only after every input has been validated
    os.makedirs(WG_DIR, mode=0o700, exist_ok=True)
    _write_secret(_conf_path(iface), "\n".join(lines))
    if run("ip", "link", "show", iface, check=False).returncode == 0:
        stripped = run("wg-quick", "strip", iface).stdout
        run("wg", "syncconf", iface, "/dev/stdin", stdin=stripped)
        shown = json.loads(run("ip", "-j", "addr", "show", iface).stdout)
        live = {a["local"] + "/" + str(a["prefixlen"]) for i in shown for a in i.get("addr_info", [])}
        for a in addresses:  # addresses/MTU may have changed
            if a not in live:
                run("ip", "address", "add", a, "dev", iface)
        run("ip", "link", "set", "dev", iface, "mtu", str(mtu))
    return {"ok": True, "peers": len(peers)}


def wg_service(iface, action):
    iface = v_wg_iface(iface)
    if action not in ("start", "stop", "restart", "enable", "disable", "status"):
        raise Invalid("bad action")
    if not _managed(iface):
        raise Invalid(f"{iface} is not managed by Tunnelstead")
    unit = f"wg-quick@{iface}.service"
    if action == "status":
        return {"active": run("systemctl", "is-active", unit, check=False).stdout.strip() == "active",
                "enabled": run("systemctl", "is-enabled", unit, check=False).stdout.strip() == "enabled"}
    run("systemctl", action, unit)
    return {"ok": True}


def wg_delete(iface):
    iface = v_wg_iface(iface)
    if not _managed(iface):
        if not os.path.exists(_conf_path(iface)):
            return {"ok": True, "note": "already gone"}
        raise Invalid(f"{iface} is not managed by Tunnelstead")
    run("systemctl", "disable", "--now", f"wg-quick@{iface}.service", check=False)
    run("ip", "link", "del", "dev", iface, check=False)
    os.unlink(_conf_path(iface))
    return {"ok": True}


def wg_dump(iface):
    iface = v_wg_iface(iface)
    r = run("wg", "show", iface, "dump", check=False)
    if r.returncode:
        return {"running": False, "peers": []}
    peers = []
    for ln in r.stdout.strip().splitlines()[1:]:
        pub, _psk, endpoint, _allowed, hs, rx, tx, _ka = ln.split("\t")
        peers.append({"public_key": pub, "endpoint": None if endpoint == "(none)" else endpoint,
                      "latest_handshake": int(hs) or None, "rx_bytes": int(rx), "tx_bytes": int(tx)})
    return {"running": True, "peers": peers}


# ---------------------------------------------------------------- firewall / routing
COMMENT = re.compile(r"^[A-Za-z0-9 _.,:()-]{0,64}$")
_pending = {"token": None, "timer": None, "deadline": None}
_pending_lock = __import__("threading").Lock()


def _v_ports(x):
    """None, a port, or "low-high"."""
    if x is None:
        return None
    if isinstance(x, int):
        return str(v_port(x))
    if isinstance(x, str) and re.fullmatch(r"\d{1,5}", x):
        return str(v_port(int(x)))
    m = re.fullmatch(r"(\d{1,5})-(\d{1,5})", str(x))
    if not m or not 1 <= int(m[1]) < int(m[2]) <= 65535:
        raise Invalid("bad port range")
    return f"{int(m[1])}-{int(m[2])}"


def _render(instances, egress, custom_rules, management):
    if not isinstance(instances, list) or len(instances) > 256:
        raise Invalid("bad instance list")
    egress = v_iface(egress) if egress else None
    accept_in, fwd, nat, guard, custom = [], [], [], [], []
    for i in instances:
        if not isinstance(i.get("iface"), str) or not TUN_IFACE.match(i["iface"]):
            raise Invalid("firewall entries must reference a managed tunnel interface")
        iface, port = i["iface"], v_port(i["port"])
        proto = i.get("transport", "udp")
        if proto not in ("udp", "tcp"):
            raise Invalid("bad transport")
        nets = [v_net(n) for n in i.get("subnets", [])][:4]
        accept_in.append(f"    {proto} dport {port} accept")
        if not i.get("isolate_clients", True):
            fwd.append(f'    iifname "{iface}" oifname "{iface}" accept')
        fwd.append(f'    iifname "{iface}" oifname != "{iface}" accept')
        if i.get("nat") and egress:
            for n in nets:
                fam = "ip" if ipaddress.ip_network(n).version == 4 else "ip6"
                nat.append(f'    {fam} saddr {n} oifname "{egress}" masquerade')
    if management:  # only these networks may reach the management ports
        mports = sorted({v_port(p) for p in management.get("ports", [])})
        nets = [ipaddress.ip_network(n, strict=False) for n in management.get("networks", [])][:64]
        if mports and nets:
            plist = ", ".join(map(str, mports))
            for fam, ver in (("ip", 4), ("ip6", 6)):
                allowed = ", ".join(str(n) for n in nets if n.version == ver)
                guard.append(f"    meta nfproto {'ipv4' if ver == 4 else 'ipv6'} tcp dport {{ {plist} }} "
                             + (f"{fam} saddr != {{ {allowed} }} drop" if allowed else "drop"))
    for r in custom_rules or []:
        if len(custom) >= 256:
            raise Invalid("too many rules")
        action = r.get("action")
        if action not in ("accept", "drop"):
            raise Invalid("action must be accept or drop")
        proto, ports = r.get("proto", "tcp"), _v_ports(r.get("ports"))
        if proto not in ("tcp", "udp", "any") or (ports and proto == "any"):
            raise Invalid("bad protocol (ports need tcp or udp)")
        comment = r.get("comment", "")
        if not isinstance(comment, str) or not COMMENT.match(comment):
            raise Invalid("bad comment")
        parts = []
        if r.get("source"):
            n = ipaddress.ip_network(r["source"], strict=False)
            parts.append(f"{'ip' if n.version == 4 else 'ip6'} saddr {n}")
        if proto != "any":
            parts.append(f"{proto} dport {ports}" if ports else f"meta l4proto {proto}")
        custom.append("    " + " ".join(parts + [action] + ([f'comment "{comment}"'] if comment else [])))
    rules = "\n".join([
        f"table inet {NFT_TABLE}", f"delete table inet {NFT_TABLE}", f"table inet {NFT_TABLE} {{",
        "  chain input {", "    type filter hook input priority 0; policy accept;",
        "    ct state established,related accept", '    iif "lo" accept', *guard, *custom, *accept_in, "  }",
        "  chain forward {", "    type filter hook forward priority 0; policy accept;",
        "    ct state established,related accept", *fwd,
        '    iifname { "wg*", "ovpn*" } drop  # anything else from a managed tunnel (client-to-client) is refused', "  }",
        "  chain postrouting {", "    type nat hook postrouting priority 100;", *nat, "  }", "}"])
    return rules, len(accept_in) + len(fwd) + len(nat) + len(guard) + len(custom)


def _current_table() -> str:
    r = run("nft", "list", "table", "inet", NFT_TABLE, check=False)
    return r.stdout if r.returncode == 0 else ""


def _restore(saved: str) -> None:
    text = f"table inet {NFT_TABLE}\ndelete table inet {NFT_TABLE}\n" + saved
    run("nft", "-f", "-", stdin=text)


def fw_apply(instances, egress=None, custom_rules=None, management=None, rollback_seconds=None):
    """Replace ONLY the application's own nftables table, atomically (dry-run checked first).
    With rollback_seconds, the previous table is restored automatically unless fw.confirm(token) arrives in time:
    a rule that locks the administrator out undoes itself even if the dashboard becomes unreachable."""
    import threading
    rules, count = _render(instances, egress, custom_rules, management)
    if rollback_seconds is not None and not (isinstance(rollback_seconds, int) and 15 <= rollback_seconds <= 600):
        raise Invalid("rollback window must be 15-600 seconds")
    run("nft", "-c", "-f", "-", stdin=rules)
    saved = _current_table()
    run("nft", "-f", "-", stdin=rules)
    if not rollback_seconds:
        return {"ok": True, "rules": count}
    import secrets as _secrets
    import time as _time
    token = _secrets.token_hex(16)

    def revert():
        with _pending_lock:
            if _pending["token"] != token:
                return
            _pending.update(token=None, timer=None, deadline=None)
        _restore(saved)

    with _pending_lock:
        if _pending["timer"]:
            _pending["timer"].cancel()
        t = threading.Timer(rollback_seconds, revert)
        t.daemon = True
        _pending.update(token=token, timer=t, deadline=_time.time() + rollback_seconds)
        t.start()
    return {"ok": True, "rules": count, "confirm_token": token, "rollback_seconds": rollback_seconds}


def fw_confirm(token):
    with _pending_lock:
        if not isinstance(token, str) or token != _pending["token"]:
            raise Invalid("nothing to confirm (the change may already have been rolled back)")
        _pending["timer"].cancel()
        _pending.update(token=None, timer=None, deadline=None)
    return {"ok": True}


def fw_pending():
    import time as _time
    with _pending_lock:
        d = _pending["deadline"]
        return {"pending": d is not None, "seconds_left": max(0, int(d - _time.time())) if d else 0}


def fw_ruleset():
    """Read-only view of the whole host ruleset (all tables), for display."""
    r = run("nft", "list", "ruleset", check=False)
    return {"ruleset": r.stdout[:200000]}


def fw_show():
    r = run("nft", "list", "table", "inet", NFT_TABLE, check=False)
    return {"ruleset": r.stdout if r.returncode == 0 else ""}


def sys_forwarding(ipv4=True, ipv6=True):
    conf = []
    if ipv4:
        run("sysctl", "-qw", "net.ipv4.ip_forward=1")
        conf.append("net.ipv4.ip_forward=1")
    if ipv6:
        run("sysctl", "-qw", "net.ipv6.conf.all.forwarding=1")
        conf.append("net.ipv6.conf.all.forwarding=1")
    _write_secret("/etc/sysctl.d/90-tunnelstead.conf", "\n".join(conf) + "\n")
    os.chmod("/etc/sysctl.d/90-tunnelstead.conf", 0o644)
    return {"ok": True}


def sys_status():
    v4 = open("/proc/sys/net/ipv4/ip_forward").read().strip() == "1"
    v6 = open("/proc/sys/net/ipv6/conf/all/forwarding").read().strip() == "1"
    return {"ipv4_forwarding": v4, "ipv6_forwarding": v6, "wireguard_tools": os.path.exists(BIN["wg"]),
            "nftables": os.path.exists(BIN["nft"]), "kernel": os.uname().release}


JOURNAL_UNIT = re.compile(r"^(tunnelstead-api|tunnelstead-helper|caddy|wg-quick@wg[0-9]{1,3}|openvpn-server@ovpn[0-9]{1,3})$")
PRIORITY = {"error": "3", "warning": "4", "info": "6"}


def sys_journal(units, lines=200, priority="info", since_hours=24):
    """Read-only service logs for Tunnelstead's own units (journald handles storage and rotation)."""
    if not isinstance(units, list) or not 1 <= len(units) <= 20 or not all(isinstance(u, str) and JOURNAL_UNIT.match(u) for u in units):
        raise Invalid("bad unit")
    if not isinstance(lines, int) or isinstance(lines, bool) or not 1 <= lines <= 2000:
        raise Invalid("bad lines")
    if priority not in PRIORITY:
        raise Invalid("bad priority")
    if not isinstance(since_hours, int) or isinstance(since_hours, bool) or not 1 <= since_hours <= 24 * 30:
        raise Invalid("bad since")
    args = ["--no-pager", "-o", "json", "-n", str(lines), "-p", PRIORITY[priority], "--since", f"-{since_hours}h"]
    for u in units:
        args += ["-u", u]
    r = run("journalctl", *args, check=False)
    out = []
    for line in r.stdout.splitlines():
        try:
            e = json.loads(line)
        except ValueError:
            continue
        msg = e.get("MESSAGE", "")
        if isinstance(msg, list):  # binary messages arrive as byte arrays
            msg = bytes(x for x in msg if isinstance(x, int) and 0 <= x < 256).decode("utf-8", "replace")
        out.append({"ts": int(e.get("__REALTIME_TIMESTAMP", "0")) // 1_000_000, "unit": e.get("_SYSTEMD_UNIT", ""),
                    "priority": int(e.get("PRIORITY", 6)), "message": str(msg)[:2000]})
    return {"entries": out}


UPDATE_VERSION = re.compile(r"^\d{1,4}\.\d{1,4}\.\d{1,4}$")


def sys_update(action, version=None):
    """Start the root updater unit. It verifies the signature itself; nothing here trusts the caller's file."""
    if action == "install":
        if not isinstance(version, str) or not UPDATE_VERSION.match(version):
            raise Invalid("bad version")
        unit = f"tunnelstead-updater@install-{version}.service"
    elif action == "rollback" and version is None:
        unit = "tunnelstead-updater@rollback.service"
    else:
        raise Invalid("bad action")
    run("systemctl", "reset-failed", unit, check=False)
    run("systemctl", "start", "--no-block", unit)
    return {"ok": True, "unit": unit}


sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ovpn_ops  # noqa: E402  (installed next to this file)


def ovpn_interfaces():
    names = set()
    if os.path.isdir(ovpn_ops.SERVER_DIR):
        names = {f[:-5] for f in os.listdir(ovpn_ops.SERVER_DIR) if f.endswith(".conf")}
    return {"interfaces": [{"name": n, "managed": ovpn_ops.managed(n)} for n in sorted(names)]}


METHODS: dict[str, Any] = {
    "net.interfaces": net_interfaces, "net.port_in_use": net_port_in_use, "net.wg_interfaces": net_wg_interfaces,
    "wg.sync": wg_sync, "wg.service": wg_service, "wg.delete": wg_delete, "wg.dump": wg_dump,
    "ovpn.apply": ovpn_ops.apply, "ovpn.service": ovpn_ops.service, "ovpn.status": ovpn_ops.status,
    "ovpn.delete": ovpn_ops.delete, "net.ovpn_interfaces": ovpn_interfaces,
    "fw.apply": fw_apply, "fw.confirm": fw_confirm, "fw.pending": fw_pending, "fw.ruleset": fw_ruleset,
    "fw.show": fw_show, "sys.forwarding": sys_forwarding, "sys.status": sys_status,
    "sys.journal": sys_journal, "sys.update": sys_update,
}


def dispatch(raw: bytes) -> dict:
    try:
        req = json.loads(raw)
        fn = METHODS.get(req.get("method"))
        if fn is None:
            return {"error": "unknown method"}
        params = req.get("params") or {}
        if not isinstance(params, dict):
            return {"error": "params must be an object"}
        return {"result": fn(**params)}
    except (Invalid, ovpn_ops.Invalid, TypeError, ValueError, KeyError) as e:
        return {"error": f"invalid request: {e}"}
    except (RuntimeError, OSError, subprocess.SubprocessError) as e:
        return {"error": str(e)}


class Handler(socketserver.StreamRequestHandler):
    def handle(self):
        self.wfile.write(json.dumps(dispatch(self.rfile.readline(1 << 20))).encode() + b"\n")


def main():
    if os.geteuid() != 0:
        sys.exit("tunnelstead-helper must run as root")
    import grp
    gid = grp.getgrnam("tunnelstead").gr_gid
    rundir = os.path.dirname(SOCKET)
    os.makedirs(rundir, exist_ok=True)
    os.chown(rundir, 0, gid)
    os.chmod(rundir, 0o750)  # noqa: S103  # nosec B103 (service group may traverse; others nothing)
    if os.path.exists(SOCKET):
        os.unlink(SOCKET)
    srv = socketserver.ThreadingUnixStreamServer(SOCKET, Handler)
    os.chown(SOCKET, 0, gid)
    os.chmod(SOCKET, 0o660)  # noqa: S103  # nosec B103 (root + service group only)
    srv.serve_forever()


if __name__ == "__main__":
    main()
