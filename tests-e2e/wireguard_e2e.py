#!/usr/bin/env python3
"""Real-host end-to-end test for the WireGuard engine. Run as root on an installed server:

    sudo vpnix-manager-e2e   (or: python3 tests-e2e/wireguard_e2e.py with the service env loaded)

Uses a temporary admin and throwaway instances/clients, a WireGuard client in a network namespace, and removes
everything afterwards. Nothing pre-existing on the host is modified.
"""
import json
import os
import secrets
import socket
import subprocess
import sys
import urllib.parse
import urllib.request

API = "http://127.0.0.1:8090"
NS, VH, VC = "vxce2e", "vxce2eh", "vxce2ec"
results: list[tuple[str, bool]] = []


def sh(*argv, check=True, ns=False, stdin=None):
    if ns:
        argv = ("ip", "netns", "exec", NS, *argv)
    r = subprocess.run(argv, capture_output=True, text=True, input=stdin)
    if check and r.returncode:
        raise RuntimeError(f"{' '.join(argv)}: {r.stderr.strip()}")
    return r


def check(name, ok, detail=""):
    results.append((name, bool(ok)))
    print(f"[{'PASS' if ok else 'FAIL'}] {name} {detail}".rstrip())


class Api:
    def __init__(self):
        self.cookie = self.csrf = None

    def req(self, method, path, body=None):
        data = json.dumps(body).encode() if body is not None else None
        r = urllib.request.Request(API + path, data=data, method=method)
        r.add_header("Content-Type", "application/json")
        if self.cookie:
            r.add_header("Cookie", f"vpnix_session={self.cookie}")
        if self.csrf and method != "GET":
            r.add_header("X-CSRF-Token", self.csrf)
        try:
            with urllib.request.urlopen(r, timeout=60) as resp:
                status, raw, headers = resp.status, resp.read(), resp.headers
        except urllib.error.HTTPError as e:
            status, raw, headers = e.code, e.read(), e.headers
        for c in headers.get_all("Set-Cookie") or []:
            if c.startswith("vpnix_session="):
                self.cookie = c.split(";")[0].split("=", 1)[1]
        try:
            return status, json.loads(raw) if raw else None
        except json.JSONDecodeError:
            return status, raw.decode()

    def login(self, user, pw):
        s, b = self.req("POST", "/api/auth/login", {"username": user, "password": pw})
        assert s == 200, b
        self.csrf = b["csrf_token"]
        return self


def temp_admin(create, name, pw=""):
    sys.path.insert(0, "/opt/vpnix-manager/backend")
    from vpnix_manager.db import get_db
    from vpnix_manager.models import Role, User
    from vpnix_manager.security import hash_password
    db = next(get_db())
    if create:
        db.add(User(username=name, role=Role.ADMIN, password_hash=hash_password(pw)))
    else:
        u = db.query(User).filter_by(username=name).first()
        u and db.delete(u)
    db.commit()
    db.close()


def collect():
    from vpnix_manager import collector
    from vpnix_manager.db import get_db
    from vpnix_manager.helper_client import Helper
    db = next(get_db())
    try:
        return collector.collect(db, Helper())
    finally:
        db.close()


def netns_client(conf: str, public_ip: str, subnets: list[str]):
    teardown()
    sh("ip", "netns", "add", NS)
    sh("ip", "link", "add", VH, "type", "veth", "peer", "name", VC)
    sh("ip", "link", "set", VC, "netns", NS)
    sh("ip", "addr", "add", "10.254.252.1/30", "dev", VH)
    sh("ip", "link", "set", VH, "up")
    sh("ip", "addr", "add", "10.254.252.2/30", "dev", VC, ns=True)
    sh("ip", "link", "set", VC, "up", ns=True)
    sh("ip", "link", "set", "lo", "up", ns=True)
    sh("ip", "route", "add", f"{public_ip}/32", "via", "10.254.252.1", ns=True)
    lines = conf.splitlines()
    addrs = next(ln.split(" = ")[1] for ln in lines if ln.startswith("Address")).split(", ")
    core = "\n".join(ln for ln in lines if not ln.startswith(("Address", "DNS", "MTU")))
    sh("ip", "link", "add", "wgc", "type", "wireguard", ns=True)
    sh("wg", "setconf", "wgc", "/dev/stdin", ns=True, stdin=core)
    for a in addrs:
        sh("ip", "addr", "add", a, "dev", "wgc", ns=True)
    sh("ip", "link", "set", "wgc", "up", ns=True)
    # Only specific routes in the namespace (it has no default route); full-tunnel NAT is exercised via 1.1.1.1.
    sh("ip", "route", "add", "1.1.1.1/32", "dev", "wgc", ns=True)
    for net in subnets:  # what a WireGuard app derives from AllowedIPs for the tunnel networks
        sh("ip", "-6" if ":" in net else "-4", "route", "add", net, "dev", "wgc", ns=True)


def teardown():
    sh("ip", "netns", "del", NS, check=False)
    sh("ip", "link", "del", VH, check=False)


def ping(target, count=3, v6=False):
    return sh("ping", *(["-6"] if v6 else []), "-c", str(count), "-W", "2", target, check=False, ns=True).returncode == 0


def main():
    public_ip = os.environ.get("VPNIX_E2E_PUBLIC_IP") or sh("hostname", "-I").stdout.split()[0]
    tag = secrets.token_hex(3)
    admin, pw = f"e2e-{tag}", secrets.token_urlsafe(18)
    temp_admin(True, admin, pw)
    api = Api().login(admin, pw)
    created, foreign = [], "/etc/wireguard/wg97.conf"
    blocker = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # A foreign WireGuard config (not made by VPNix Manager) must be detected and never touched.
        os.makedirs("/etc/wireguard", exist_ok=True)
        with open(foreign, "w") as f:
            f.write("[Interface]\nPrivateKey = foreign\n")
        _, rec = api.req("GET", "/api/instances/recommend")
        check("recommendation skips foreign interface wg97", rec["iface"] != "wg97", rec["iface"])
        base = {"name": f"E2E-A-{tag}", "iface": rec["iface"], "listen_port": rec["port"], "endpoint_host": public_ip,
                "egress_iface": rec["egress_iface"], "ipv4_cidr": rec["ipv4_cidr"], "ipv6_cidr": rec["ipv6_cidr"],
                "dns": ["1.1.1.1"], "routing_mode": "full", "nat": True}
        s, b = api.req("POST", "/api/instances/validate", {**base, "iface": "wg97"})
        check("validation refuses the foreign interface", "not created by VPNix Manager" in b["errors"].get("iface", ""))
        blocker.bind(("0.0.0.0", 51999))  # a real port held by another program
        s, b = api.req("GET", "/api/instances/port-check?port=51999&transport=udp")
        check("port check detects a real port in use", b["free"] is False, b["message"])

        s, a = api.req("POST", "/api/instances", base)
        check("instance A deployed", s == 201, str(a)[:200])
        created.append(a)
        s, rec2 = api.req("GET", "/api/instances/recommend")
        check("next recommendation avoids instance A", rec2["port"] != a["listen_port"] and rec2["iface"] != a["iface"]
              and rec2["ipv4_cidr"] != a["ipv4_cidr"], f"{rec2['iface']} {rec2['port']} {rec2['ipv4_cidr']}")
        s, bb = api.req("POST", "/api/instances", {**base, "name": f"E2E-B-{tag}", "iface": rec2["iface"],
                                                    "listen_port": rec2["port"], "ipv4_cidr": rec2["ipv4_cidr"],
                                                    "ipv6_cidr": rec2["ipv6_cidr"]})
        check("instance B deployed alongside A", s == 201, str(bb)[:200])
        created.append(bb)
        for inst in created:
            active = sh("systemctl", "is-active", f"wg-quick@{inst['iface']}", check=False).stdout.strip()
            check(f"{inst['iface']} running on UDP {inst['listen_port']}", active == "active" and
                  f"listening port: {inst['listen_port']}" in sh("wg", "show", inst["iface"]).stdout)
        check("foreign config untouched", open(foreign).read() == "[Interface]\nPrivateKey = foreign\n")

        s, cl = api.req("POST", "/api/clients", {"instance_id": a["id"], "name": "e2e-phone", "tags": ["e2e"]})
        check("client created", s == 201, str(cl)[:150])
        check("client on live interface", cl["public_key"] in sh("wg", "show", a["iface"], "peers").stdout)
        s, conf = api.req("GET", f"/api/clients/{cl['id']}/config")
        try:
            netns_client(conf, public_ip, [a["ipv4_cidr"], a["ipv6_cidr"]])
            gw4 = a["ipv4_cidr"].rsplit(".", 1)[0] + ".1"
            gw6 = a["ipv6_cidr"].split("/")[0] + "1"
            check(f"client reaches server over IPv4 ({gw4})", ping(gw4))
            check(f"client reaches server over IPv6 ({gw6})", ping(gw6, v6=True))
            check("internet (1.1.1.1) reachable through tunnel + NAT", ping("1.1.1.1"))
            out = collect()
            s, rows = api.req("GET", f"/api/clients?instance_id={a['id']}")
            me = rows[0]
            check("live stats: handshake + traffic recorded", me["connected"] and me["rx_bytes"] > 0, f"{out} rx={me['rx_bytes']}")

            api.req("POST", f"/api/clients/{cl['id']}/disable")
            check("disabled client removed from interface", cl["public_key"] not in sh("wg", "show", a["iface"], "peers").stdout)
            check("disabled client cannot reach server", not ping(gw4, 2))
            api.req("POST", f"/api/clients/{cl['id']}/enable")
            check("re-enabled client reconnects (within 80 s)", ping(gw4, 40))
            # Instance B is untouched by all of this (module/instance isolation).
            check("instance B unaffected", sh("systemctl", "is-active", f"wg-quick@{bb['iface']}", check=False).stdout.strip() == "active")
            api.req("POST", f"/api/instances/{a['id']}/stop")
            check("stopping A takes its interface down", sh("ip", "link", "show", a["iface"], check=False).returncode != 0)
            api.req("POST", f"/api/instances/{a['id']}/start")
            check("starting A brings it back with its clients", cl["public_key"] in sh("wg", "show", a["iface"], "peers").stdout)
            api.req("POST", f"/api/clients/{cl['id']}/revoke")
            check("revoked client removed", cl["public_key"] not in sh("wg", "show", a["iface"], "peers").stdout)
            check("revoked client cannot reach server", not ping(gw4, 2))
            rules = sh("nft", "list", "table", "inet", "vpnix_manager").stdout
            check("firewall: own table with both ports and NAT", f"udp dport {a['listen_port']}" in rules and
                  f"udp dport {bb['listen_port']}" in rules and "masquerade" in rules)
        finally:
            teardown()
    finally:
        blocker.close()
        for inst in created:
            api.req("DELETE", f"/api/instances/{inst['id']}?confirm={urllib.parse.quote(inst['name'])}")
        if created:
            check("cleanup removed managed interfaces", all(sh("ip", "link", "show", i["iface"], check=False).returncode != 0 for i in created))
            check("cleanup removed managed configs", all(not os.path.exists(f"/etc/wireguard/{i['iface']}.conf") for i in created))
        check("foreign config still intact after cleanup", os.path.exists(foreign))
        os.unlink(foreign)
        temp_admin(False, admin)
    failed = [n for n, ok in results if not ok]
    print(f"\n{len(results) - len(failed)}/{len(results)} checks passed")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    import urllib.parse  # noqa: F401
    main()
