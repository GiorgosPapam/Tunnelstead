#!/usr/bin/env python3
"""Real-host end-to-end test for Phase 6 (signed updates). Run as root on a server running 0.1.0.

Needs signed bundles in FEED (default /srv/vpnix-feed): 0.1.0 (downgrade check), 0.1.1 (good update) and 0.1.2 (signed
but with a failing installer). Checks: tampered bundle refused, dashboard update 0.1.0 → 0.1.1 with a VPN server kept
running, downgrade refused, manual rollback, and automatic rollback of a failing update. Leaves the server on 0.1.0.
"""
import json
import os
import secrets
import shutil
import subprocess
import sys
import time
import urllib.parse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from wireguard_e2e import Api, check, results, sh, temp_admin  # noqa: E402

FEED = os.environ.get("VPNIX_E2E_FEED", "/srv/vpnix-feed")
ENV = "/etc/vpnix-create/vpnix-create.env"
UPDATE = "/opt/vpnix-create/installer/update.sh"
STATUS = "/var/lib/vpnix-create/updates/status.json"


def version():
    try:
        out = subprocess.run(["curl", "-fsS", "http://127.0.0.1:8090/api/health"], capture_output=True, text=True, timeout=10).stdout
        return json.loads(out)["version"]
    except (ValueError, KeyError):
        return None


def status():
    try:
        return json.load(open(STATUS))
    except (OSError, ValueError):
        return {}


def wait_status(states, timeout=600):
    end = time.time() + timeout
    while time.time() < end:
        st = status()
        if st.get("state") in states and subprocess.run(["systemctl", "is-active", "--quiet", "vpnix-create-updater@*"]).returncode:
            return st
        time.sleep(3)
    return status()


def login(admin, pw):
    for _ in range(30):
        try:
            return Api().login(admin, pw)
        except Exception:  # noqa: BLE001 - API restarting
            time.sleep(2)
    raise RuntimeError("API did not come back")


def set_feed(on: bool):
    lines = [x for x in open(ENV).read().splitlines() if not x.startswith("VPNIX_UPDATE_FEED_DIR=")]
    if on:
        lines.append(f"VPNIX_UPDATE_FEED_DIR={FEED}")
    open(ENV, "w").write("\n".join(lines) + "\n")
    sh("systemctl", "restart", "vpnix-create-api")
    time.sleep(3)


def wg_running(iface):
    return "listening port" in sh("wg", "show", iface, check=False).stdout


def main():
    check("starting on 0.1.0", version() == "0.1.0", str(version()))
    tag = secrets.token_hex(3)
    admin, pw = f"e2e-{tag}", secrets.token_urlsafe(18)
    temp_admin(True, admin, pw)
    api = login(admin, pw)
    inst = None
    try:
        _, rec = api.req("GET", "/api/instances/recommend")
        s, inst = api.req("POST", "/api/instances", {
            "name": f"E2E-UPD-{tag}", "iface": rec["iface"], "listen_port": rec["port"], "endpoint_host": "203.0.113.1",
            "egress_iface": rec["egress_iface"], "ipv4_cidr": rec["ipv4_cidr"], "ipv6_cidr": None, "dns": ["1.1.1.1"],
            "routing_mode": "full", "nat": True})
        check("VPN server running before the update", s == 201 and wg_running(inst["iface"]))
        api.req("POST", "/api/clients", {"instance_id": inst["id"], "name": f"laptop-{tag}"})

        # 1. tampered bundle (valid signature file, modified content) is refused
        tdir = "/root/vpnix-tampered"
        shutil.rmtree(tdir, ignore_errors=True)
        os.makedirs(tdir)
        data = bytearray(open(f"{FEED}/vpnix-create-0.1.1.tar.gz", "rb").read())
        data[len(data) // 2] ^= 0xFF
        open(f"{tdir}/vpnix-create-0.1.1.tar.gz", "wb").write(bytes(data))
        shutil.copy(f"{FEED}/vpnix-create-0.1.1.tar.gz.sig", tdir)
        out = subprocess.run([UPDATE, f"{tdir}/vpnix-create-0.1.1.tar.gz"], capture_output=True, text=True, timeout=300).stdout
        check("tampered bundle refused", "signature check failed" in out and version() == "0.1.0", out.strip().splitlines()[-1] if out.strip() else "")
        shutil.rmtree(tdir)

        # 2. update through the dashboard API
        set_feed(True)
        api = login(admin, pw)
        s, o = api.req("POST", "/api/updates/check")
        check("dashboard offers the newest signed release", s == 200 and o["check"]["latest"]["version"] == "0.1.2", str(o.get("check", o))[:150])
        s, d = api.req("POST", "/api/updates/0.1.1/download")
        check("download verified by the API", s == 200 and d["verified"], str(d)[:120])
        s, r = api.req("POST", "/api/updates/0.1.1/install")
        check("install started", s == 202, str(r)[:120])
        st = wait_status({"success", "failed", "rolled_back"})
        check("update to 0.1.1 succeeded", st.get("state") == "success" and version() == "0.1.1", f"{st.get('state')} {st.get('error', '')}")
        check("VPN server kept running", wg_running(inst["iface"]))
        api = login(admin, pw)
        i2 = next((i for i in api.req("GET", "/api/instances")[1] if i["id"] == inst["id"]), None)
        check("data kept (server and client)", i2 and i2["clients_total"] == 1)
        check("snapshot taken (root-only)", os.path.isdir("/opt/vpnix-create.prev") and
              oct(os.stat("/var/backups/vpnix-create").st_mode & 0o777) == "0o700")
        check("no password in the update log", "PASSWORD" not in json.dumps(status()).upper())

        # 3. downgrade refused (signed, but older)
        out = subprocess.run([UPDATE, f"{FEED}/vpnix-create-0.1.0.tar.gz"], capture_output=True, text=True, timeout=300).stdout
        check("downgrade refused", "not newer" in out and version() == "0.1.1")
        s, _ = api.req("POST", "/api/updates/0.1.0/download")
        check("dashboard refuses the downgrade too", s == 422)

        # 4. manual rollback through the dashboard
        s, _ = api.req("POST", "/api/updates/rollback")
        check("rollback started", s == 202)
        st = wait_status({"rolled_back", "failed"})
        check("rolled back to 0.1.0", st.get("state") == "rolled_back" and version() == "0.1.0", f"{st.get('state')} {st.get('error', '')}")
        check("VPN server running after rollback", wg_running(inst["iface"]))

        # 5. a signed update whose installer fails is undone automatically
        out = subprocess.run([UPDATE, f"{FEED}/vpnix-create-0.1.2.tar.gz"], capture_output=True, text=True, timeout=900).stdout
        st = status()
        check("failing update rolled back automatically", st.get("state") == "rolled_back" and not st.get("manual")
              and version() == "0.1.0", f"{st.get('state')} {st.get('error', '')}")
        check("VPN server running after the failed update", wg_running(inst["iface"]))
        api = login(admin, pw)
        time.sleep(35)  # collector reports the outcome
        s, a = api.req("GET", "/api/system/audit?q=update_rolled_back")
        check("failed update recorded in the audit log", bool(a["entries"]))
    finally:
        set_feed(False)
        api = login(admin, pw)
        if inst:
            api.req("DELETE", f"/api/instances/{inst['id']}?confirm={urllib.parse.quote(inst['name'])}")
            check("cleanup removed the test server", sh("ip", "link", "show", inst["iface"], check=False).returncode != 0)
        temp_admin(False, admin)
    check("ends on 0.1.0", version() == "0.1.0")
    failed = [n for n, ok in results if not ok]
    print(f"\n{len(results) - len(failed)}/{len(results)} checks passed")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
