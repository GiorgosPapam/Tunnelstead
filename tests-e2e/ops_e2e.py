#!/usr/bin/env python3
"""Real-host end-to-end test for Phase 5 (monitoring, service logs, alerts, backup/restore). Run as root.

Creates a throwaway WireGuard server, measures, stops its service behind the app's back to see the outage detected,
then deletes it and brings it back twice: once through the API restore and once through installer/restore.sh.
Everything it creates is removed afterwards.
"""
import glob
import os
import secrets
import subprocess
import sys
import time
import urllib.parse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from wireguard_e2e import Api, check, results, sh, temp_admin  # noqa: E402

PASS = "e2e-" + secrets.token_urlsafe(16)
BACKUPS = "/var/lib/vpnix-create/backups"


def wait(pred, timeout=90, every=5):
    end = time.time() + timeout
    while time.time() < end:
        v = pred()
        if v:
            return v
        time.sleep(every)
    return None


def main():
    tag = secrets.token_hex(3)
    admin, pw = f"e2e-{tag}", secrets.token_urlsafe(18)
    temp_admin(True, admin, pw)
    api = Api().login(admin, pw)
    before_backups = set(os.listdir(BACKUPS))
    inst = None
    try:
        _, rec = api.req("GET", "/api/instances/recommend")
        s, inst = api.req("POST", "/api/instances", {
            "name": f"E2E-OPS-{tag}", "iface": rec["iface"], "listen_port": rec["port"], "endpoint_host": "203.0.113.1",
            "egress_iface": rec["egress_iface"], "ipv4_cidr": rec["ipv4_cidr"], "ipv6_cidr": rec["ipv6_cidr"],
            "dns": ["1.1.1.1"], "routing_mode": "full", "nat": True})
        check("test server deployed", s == 201, str(inst)[:150])
        iface = inst["iface"]
        s, cl = api.req("POST", "/api/clients", {"instance_id": inst["id"], "name": f"phone-{tag}"})
        check("client created", s == 201)

        # ---- monitoring: real samples from the collector
        m = wait(lambda: (lambda r: r if r["host"] and any(i["name"] == inst["name"] and i["series"] for i in r["instances"]) else None)(
            api.req("GET", "/api/monitoring?range=1h")[1]), timeout=100)
        check("collector records host and per-server samples", bool(m))
        if m:
            h = m["host"][-1]
            check("host sample has real CPU/memory/disk", 0 <= h["cpu"] <= 100 and h["mem_total"] > 0 and h["disk_total"] > 0)
            check("server availability is 100 %", next(i for i in m["instances"] if i["name"] == inst["name"])["availability"] == 100.0)

        # ---- service logs from journald through the helper
        s, logs = api.req("GET", "/api/logs/services?unit=vpnix-create-api&hours=24&lines=50")
        check("service logs read from journald", s == 200 and len(logs["entries"]) > 0, f"{len(logs.get('entries', []))} lines")
        check("per-server unit listed", f"wg-quick@{iface}" in logs["units"])
        s, _ = api.req("GET", "/api/logs/services?unit=ssh")
        check("other system units are refused", s == 422)

        # ---- outage detection
        s, _ = api.req("PUT", "/api/notifications", {"webhook_url": "https://127.0.0.1:9/hook", "events": ["instance_down"]})
        s, t = api.req("POST", "/api/notifications/test")
        check("notification delivery is attempted and the error reported", s == 200 and t["ok"] is False and t["errors"], str(t)[:120])
        sh("systemctl", "stop", f"wg-quick@{iface}")
        down = wait(lambda: inst["name"] in api.req("GET", "/api/monitoring?range=1h")[1]["health"]["down"], timeout=75)
        check("stopped service detected as down", bool(down))
        s, a = api.req("GET", "/api/system/audit?q=instance_down")
        check("outage written to the audit log", any(e["target"] == inst["name"] for e in a["entries"]))
        sh("systemctl", "start", f"wg-quick@{iface}")
        up = wait(lambda: inst["name"] not in api.req("GET", "/api/monitoring?range=1h")[1]["health"]["down"], timeout=75)
        check("recovery detected", bool(up))

        # ---- backup + API restore
        s, b = api.req("POST", "/api/backups", {"passphrase": PASS})
        check("encrypted backup created", s == 201, b.get("name", str(b))[:80])
        raw = open(os.path.join(BACKUPS, b["name"]), "rb").read()
        check("backup file is encrypted and private", raw[:8] == b"VPNIXBK1" and inst["name"].encode() not in raw
              and oct(os.stat(os.path.join(BACKUPS, b["name"])).st_mode & 0o777) == "0o600")
        api.req("DELETE", f"/api/instances/{inst['id']}?confirm={urllib.parse.quote(inst['name'])}")
        check("server deleted", sh("ip", "link", "show", iface, check=False).returncode != 0)
        s, r = api.req("POST", f"/api/backups/{b['name']}/restore", {"passphrase": PASS, "confirm": b["name"]})
        check("API restore succeeded", s == 200 and not r.get("warnings"), str(r)[:200])
        check("restored server is live again", "listening port" in sh("wg", "show", iface, check=False).stdout)
        api = Api().login(admin, pw)
        s, insts = api.req("GET", "/api/instances")
        restored = next((i for i in insts if i["name"] == inst["name"]), None)
        check("server and client back in the dashboard", restored and restored["clients_total"] == 1, str(restored)[:120])
        inst = restored or inst

        # ---- restore.sh (command line, API stopped)
        api.req("DELETE", f"/api/instances/{inst['id']}?confirm={urllib.parse.quote(inst['name'])}")
        env = {**os.environ, "VPNIX_BACKUP_PASSPHRASE": PASS}
        p = subprocess.run(["/opt/vpnix-create/installer/restore.sh", os.path.join(BACKUPS, b["name"]), "--yes"],
                           capture_output=True, text=True, env=env, timeout=300)
        check("restore.sh finished", p.returncode == 0, (p.stdout + p.stderr).strip().splitlines()[-1] if (p.stdout + p.stderr).strip() else "")
        check("server live again after restore.sh", "listening port" in sh("wg", "show", iface, check=False).stdout)
        check("API healthy after restore.sh", sh("systemctl", "is-active", "vpnix-create-api", check=False).stdout.strip() == "active")
        check("state files still owned by the service user",
              all(os.stat(f).st_uid == os.stat(BACKUPS).st_uid for f in glob.glob("/var/lib/vpnix-create/*")))
        api = Api().login(admin, pw)
        inst = next((i for i in api.req("GET", "/api/instances")[1] if i["name"] == inst["name"]), inst)
    finally:
        try:
            api.req("PUT", "/api/notifications", {"webhook_url": "", "events": []})
            api.req("DELETE", f"/api/instances/{inst['id']}?confirm={urllib.parse.quote(inst['name'])}") if inst else None
        except Exception as e:  # noqa: BLE001
            print("cleanup:", e)
        for f in set(os.listdir(BACKUPS)) - before_backups:
            os.unlink(os.path.join(BACKUPS, f))
        if inst:
            check("cleanup removed the test server", sh("ip", "link", "show", inst["iface"], check=False).returncode != 0)
        temp_admin(False, admin)
    failed = [n for n, ok in results if not ok]
    print(f"\n{len(results) - len(failed)}/{len(results)} checks passed")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
