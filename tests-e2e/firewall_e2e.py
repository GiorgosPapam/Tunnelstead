#!/usr/bin/env python3
"""Real-host end-to-end test for the Phase 4 firewall. Run as root on an installed server.

Adds throwaway rules through the API, checks they reach nftables, keeps one, lets another roll back on its own, and
verifies no other nftables table is touched. Everything is removed afterwards.
"""
import os
import secrets
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from wireguard_e2e import Api, check, results, sh, temp_admin  # noqa: E402


def own():
    return sh("nft", "list", "table", "inet", "tunnelstead", check=False).stdout


def others():
    tables = [t for t in sh("nft", "list", "tables").stdout.splitlines() if "tunnelstead" not in t]
    return {t: sh("nft", "list", *t.split()).stdout for t in tables}


def main():
    tag = secrets.token_hex(3)
    admin, pw = f"e2e-{tag}", secrets.token_urlsafe(18)
    temp_admin(True, admin, pw)
    api = Api().login(admin, pw)
    before = others()
    made = []
    try:
        s, r = api.req("POST", "/api/firewall/rules", {"action": "accept", "proto": "tcp", "ports": "8443",
                                                        "source": "198.51.100.0/24", "comment": f"keep-{tag}"})
        check("rule applied with a confirm token", s in (200, 201) and r.get("confirm_token"), str(r)[:200])
        check("rule is in nftables", "198.51.100.0/24" in own() and "8443" in own())
        s, _ = api.req("POST", "/api/firewall/confirm", {"token": r["confirm_token"]})
        check("change kept", s == 200)
        s, r2 = api.req("POST", "/api/firewall/rules", {"action": "drop", "proto": "udp", "ports": "9999",
                                                         "source": "203.0.113.7", "comment": f"undo-{tag}"})
        check("second rule applied", s in (200, 201) and "9999" in own())
        s, st = api.req("GET", "/api/firewall")
        check("pending confirmation reported", st["pending"] is not None, str(st["pending"]))
        s, bad = api.req("POST", "/api/firewall/rules", {"action": "accept", "proto": "tcp", "source": "1.2.3.4; flush ruleset"})
        check("injection attempt rejected", s == 422, str(s))
        print("waiting 70 s for the automatic rollback ...", flush=True)
        time.sleep(70)
        check("unconfirmed rule rolled back in nftables", "9999" not in own())
        check("kept rule survived the rollback", "8443" in own())
        time.sleep(35)  # collector reconcile interval
        s, st = api.req("GET", "/api/firewall")
        comments = [x["comment"] for x in st["rules"]]
        made = [x for x in st["rules"] if tag in x["comment"]]
        check("rolled-back rule removed from the dashboard", f"undo-{tag}" not in comments, str(comments))
        check("nothing left pending", st["pending"] is None)
        check("other nftables tables untouched", others() == before)
    finally:
        s, st = api.req("GET", "/api/firewall")
        for x in st["rules"]:
            if tag in x["comment"]:
                s, r = api.req("DELETE", f"/api/firewall/rules/{x['id']}")
                if r and r.get("confirm_token"):
                    api.req("POST", "/api/firewall/confirm", {"token": r["confirm_token"]})
        check("cleanup removed test rules", "8443" not in own() and "9999" not in own())
        temp_admin(False, admin)
    del made
    failed = [n for n, ok in results if not ok]
    print(f"\n{len(results) - len(failed)}/{len(results)} checks passed")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
