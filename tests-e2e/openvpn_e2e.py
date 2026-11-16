#!/usr/bin/env python3
"""Real-host end-to-end test for the OpenVPN engine (UDP and TCP) with a real openvpn client in a namespace.
Run as root on an installed server with the service environment loaded. Leaves the host as it found it."""
import os
import secrets
import sys
import time
import urllib.parse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import wireguard_e2e as w  # noqa: E402  (shared helpers: Api, sh, check, temp_admin, collect)

NS, VH, VC = "vxco", "vxcoh", "vxcoc"


def ns(*argv, check=True):
    return w.sh("ip", "netns", "exec", NS, *argv, check=check)


def setup_ns(public_ip):
    teardown()
    w.sh("ip", "netns", "add", NS)
    w.sh("ip", "link", "add", VH, "type", "veth", "peer", "name", VC)
    w.sh("ip", "link", "set", VC, "netns", NS)
    w.sh("ip", "addr", "add", "10.254.251.1/30", "dev", VH)
    w.sh("ip", "link", "set", VH, "up")
    ns("ip", "addr", "add", "10.254.251.2/30", "dev", VC)
    ns("ip", "link", "set", VC, "up")
    ns("ip", "link", "set", "lo", "up")
    ns("ip", "route", "add", f"{public_ip}/32", "via", "10.254.251.1")


def teardown():
    w.sh("pkill", "-f", "[o]penvpn --config /run/vxco", check=False)
    w.sh("ip", "netns", "del", NS, check=False)
    w.sh("ip", "link", "del", VH, check=False)


def start_client(conf, name="vxco"):
    # Harness: the namespace has no default route, so full-tunnel redirects are replaced by explicit routes.
    conf = "\n".join(ln for ln in conf.splitlines() if not ln.startswith("redirect-gateway") and ln != "block-outside-dns")
    conf += "\nroute 1.1.1.1 255.255.255.255\nconnect-retry 2 2\n"
    path = f"/run/{name}.ovpn"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(conf)
    w.sh("pkill", "-f", "[o]penvpn --config /run/vxco", check=False)
    time.sleep(1)
    ns("openvpn", "--config", path, "--daemon", "vxco-client", "--log", f"/run/{name}.log")


def ping(target, count=3, v6=False):
    return ns("ping", *(["-6"] if v6 else []), "-c", str(count), "-W", "2", target, check=False).returncode == 0


def wait_ping(target, seconds, v6=False):
    end = time.time() + seconds
    while time.time() < end:
        if ping(target, 1, v6):
            return True
        time.sleep(2)
    return False


def run(api, public_ip, transport, rec, tag, created):
    s, inst = api.req("POST", "/api/instances", {
        "name": f"E2E-OVPN-{transport}-{tag}", "protocol": "openvpn", "transport": transport, "iface": rec["iface"],
        "listen_port": rec["port"], "endpoint_host": public_ip, "egress_iface": rec["egress_iface"],
        "ipv4_cidr": rec["ipv4_cidr"], "ipv6_cidr": rec["ipv6_cidr"], "dns": ["1.1.1.1"], "mtu": 1500})
    w.check(f"[{transport}] OpenVPN instance deployed ({rec['iface']}, {transport.upper()} {rec['port']})", s == 201, str(inst)[:160])
    if s != 201:
        return
    created.append(inst)
    time.sleep(2)
    w.check(f"[{transport}] openvpn-server@{inst['iface']} active",
            w.sh("systemctl", "is-active", f"openvpn-server@{inst['iface']}", check=False).stdout.strip() == "active")
    s, cl = api.req("POST", "/api/clients", {"instance_id": inst["id"], "name": f"e2e-{transport}"})
    s, conf = api.req("GET", f"/api/clients/{cl['id']}/config")
    gw4 = inst["ipv4_cidr"].rsplit(".", 1)[0] + ".1"
    gw6 = inst["ipv6_cidr"].split("/")[0] + "1"
    try:
        setup_ns(public_ip)
        start_client(conf)
        w.check(f"[{transport}] client connects, reaches {gw4}", wait_ping(gw4, 45))
        w.check(f"[{transport}] IPv6 in the tunnel ({gw6})", wait_ping(gw6, 15, v6=True))
        w.check(f"[{transport}] internet via tunnel + NAT", ping("1.1.1.1"))
        time.sleep(11)  # status file refresh
        w.collect()
        s, rows = api.req("GET", f"/api/clients?instance_id={inst['id']}")
        w.check(f"[{transport}] live session + traffic recorded", rows[0]["connected"] and rows[0]["rx_bytes"] > 0, f"rx={rows[0]['rx_bytes']}")
        api.req("POST", f"/api/clients/{cl['id']}/disable")
        time.sleep(3)
        w.check(f"[{transport}] disabled client is disconnected and refused", not wait_ping(gw4, 15))
        api.req("POST", f"/api/clients/{cl['id']}/enable")
        w.check(f"[{transport}] re-enabled client reconnects", wait_ping(gw4, 60))
        api.req("POST", f"/api/clients/{cl['id']}/regenerate")
        time.sleep(3)
        start_client(conf)  # the OLD profile, after regeneration
        w.check(f"[{transport}] old profile rejected after key regeneration", not wait_ping(gw4, 20))
        s, conf2 = api.req("GET", f"/api/clients/{cl['id']}/config")
        start_client(conf2)
        w.check(f"[{transport}] new profile works", wait_ping(gw4, 45))
        api.req("POST", f"/api/clients/{cl['id']}/revoke")
        time.sleep(3)
        w.check(f"[{transport}] revoked client cannot reconnect", not wait_ping(gw4, 20))
        log = w.sh("cat", "/run/vxco.log", check=False).stdout
        w.check(f"[{transport}] server refused the revoked certificate", "AUTH_FAILED" in log or "TLS" in log)
    finally:
        teardown()


def main():
    public_ip = os.environ.get("VPNIX_E2E_PUBLIC_IP") or w.sh("hostname", "-I").stdout.split()[0]
    tag = secrets.token_hex(3)
    admin, pw = f"e2e-{tag}", secrets.token_urlsafe(18)
    w.temp_admin(True, admin, pw)
    api = w.Api().login(admin, pw)
    created = []
    try:
        for transport in ("udp", "tcp"):
            s, rec = api.req("GET", f"/api/instances/recommend?protocol=openvpn&transport={transport}")
            run(api, public_ip, transport, rec, tag, created)
    finally:
        for inst in created:
            api.req("DELETE", f"/api/instances/{inst['id']}?confirm={urllib.parse.quote(inst['name'])}")
        w.check("cleanup removed OpenVPN servers", all(
            w.sh("systemctl", "is-active", f"openvpn-server@{i['iface']}", check=False).stdout.strip() != "active"
            and not os.path.exists(f"/etc/openvpn/server/{i['iface']}.conf") for i in created))
        w.temp_admin(False, admin)
    failed = [n for n, ok in w.results if not ok]
    print(f"\n{len(w.results) - len(failed)}/{len(w.results)} checks passed")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
