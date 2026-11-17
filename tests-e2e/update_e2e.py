#!/usr/bin/env python3
"""Real-host end-to-end test for Phase 6 (signed updates). Run as root; VPNIX_E2E_BASE is the installed version (V0).

Needs signed bundles in FEED (default /srv/vpnix-feed): V0 (downgrade check), V1 (good update) and V2 (signed
but with a failing installer). Checks: tampered bundle refused, dashboard update V0 → V1 with a VPN server kept
running, downgrade refused, manual rollback, and automatic rollback of a failing update. Leaves the server on V0.
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
ENV = "/etc/vpnix-manager/vpnix-manager.env"
UPDATE = "/opt/vpnix-manager/installer/update.sh"
STATUS = "/var/lib/vpnix-manager/updates/status.json"


def _bump(v, n):
    a, b, c = (int(x) for x in v.split("."))
    return f"{a}.{b}.{c + n}"


# Versions follow the installed one: V0 installed, V1 good update, V2 signed but with a failing installer.
V0 = os.environ.get("VPNIX_E2E_BASE", "0.1.0")
V1, V2 = _bump(V0, 1), _bump(V0, 2)


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


def updater_busy():
    out = subprocess.run(["systemctl", "list-units", "--no-legend", "--state=activating,active,reloading",
                          "vpnix-manager-updater@*"], capture_output=True, text=True).stdout
    return bool(out.strip())


def wait_status(states, after: str, timeout=600):
    """Wait for a status written after `after` (ISO time) in one of `states`, with no updater still running."""
    end = time.time() + timeout
    while time.time() < end:
        st = status()
        if st.get("updated_at", "") > after and st.get("state") in states and not updater_busy():
            return st
        time.sleep(3)
    return status()


def now_iso():
    from datetime import UTC, datetime
    return datetime.now(UTC).isoformat()


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
    sh("systemctl", "restart", "vpnix-manager-api")
    time.sleep(3)


def wg_running(iface):
    return "listening port" in sh("wg", "show", iface, check=False).stdout


def main():
    check(f"starting on {V0}", version() == V0, str(version()))
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
        data = bytearray(open(f"{FEED}/vpnix-manager-{V1}.tar.gz", "rb").read())
        data[len(data) // 2] ^= 0xFF
        open(f"{tdir}/vpnix-manager-{V1}.tar.gz", "wb").write(bytes(data))
        shutil.copy(f"{FEED}/vpnix-manager-{V1}.tar.gz.sig", tdir)
        out = subprocess.run([UPDATE, f"{tdir}/vpnix-manager-{V1}.tar.gz"], capture_output=True, text=True, timeout=300).stdout
        check("tampered bundle refused", "signature check failed" in out and version() == V0, out.strip().splitlines()[-1] if out.strip() else "")
        shutil.rmtree(tdir)

        # 2. update through the dashboard API
        set_feed(True)
        api = login(admin, pw)
        s, o = api.req("POST", "/api/updates/check")
        check("dashboard offers the newest signed release", s == 200 and o["check"]["latest"]["version"] == V2, str(o.get("check", o))[:150])
        s, d = api.req("POST", f"/api/updates/{V1}/download")
        check("download verified by the API", s == 200 and d["verified"], str(d)[:120])
        t0 = now_iso()
        s, r = api.req("POST", f"/api/updates/{V1}/install")
        check("install started", s == 202, str(r)[:120])
        st = wait_status({"success", "failed", "rolled_back"}, t0)
        check(f"update to {V1} succeeded", st.get("state") == "success" and version() == V1, f"{st.get('state')} {st.get('error', '')}")
        check("VPN server kept running", wg_running(inst["iface"]))
        api = login(admin, pw)
        i2 = next((i for i in api.req("GET", "/api/instances")[1] if i["id"] == inst["id"]), None)
        check("data kept (server and client)", i2 and i2["clients_total"] == 1)
        check("snapshot taken (root-only)", os.path.isdir("/opt/vpnix-manager.prev") and
              oct(os.stat("/var/backups/vpnix-manager").st_mode & 0o777) == "0o700")
        check("no password in the update log", "PASSWORD" not in json.dumps(status()).upper())

        # 3. downgrade refused (signed, but older)
        out = subprocess.run([UPDATE, f"{FEED}/vpnix-manager-{V0}.tar.gz"], capture_output=True, text=True, timeout=300).stdout
        check("downgrade refused", "not newer" in out and version() == V1)
        s, _ = api.req("POST", f"/api/updates/{V0}/download")
        check("dashboard refuses the downgrade too", s == 422)
        s, o = api.req("GET", "/api/updates")
        check("rollback still offered after the refused downgrade", o.get("rollback_to") == V0, str(o.get("rollback_to")))

        # 4. manual rollback through the dashboard
        t0 = now_iso()
        s, _ = api.req("POST", "/api/updates/rollback")
        check("rollback started", s == 202)
        st = wait_status({"rolled_back", "failed"}, t0) if s == 202 else status()
        check(f"rolled back to {V0}", st.get("state") == "rolled_back" and version() == V0, f"{st.get('state')} {st.get('error', '')}")
        check("VPN server running after rollback", wg_running(inst["iface"]))

        # 5. a signed update whose installer fails is undone automatically
        out = subprocess.run([UPDATE, f"{FEED}/vpnix-manager-{V2}.tar.gz"], capture_output=True, text=True, timeout=900).stdout
        st = status()
        check("failing update rolled back automatically", st.get("state") == "rolled_back" and not st.get("manual")
              and version() == V0, f"{st.get('state')} {st.get('error', '')}")
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
    check(f"ends on {V0}", version() == V0)
    failed = [n for n, ok in results if not ok]
    print(f"\n{len(results) - len(failed)}/{len(results)} checks passed")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
