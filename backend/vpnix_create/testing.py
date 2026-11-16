"""Browser-test support ONLY: a simulated host instead of the privileged helper.

Enabled with VPNIX_UI_TEST_HELPER=1 and refused unless the database is SQLite, so a production install can never
run against a fake system. Real system behaviour is verified on Linux by tests-e2e/.
"""
import os

from .config import get_settings


class SimulatedHost:
    peers: dict = {}
    services: dict = {}
    fw_token: str | None = None

    def call(self, method, **p):
        import secrets
        if method == "fw.apply":
            if p.get("rollback_seconds"):
                SimulatedHost.fw_token = secrets.token_hex(8)
                return {"ok": True, "confirm_token": SimulatedHost.fw_token, "rollback_seconds": p["rollback_seconds"]}
            return {"ok": True}
        if method == "fw.confirm":
            from .helper_client import HelperError
            if p["token"] != SimulatedHost.fw_token:
                raise HelperError("invalid request: nothing to confirm")
            SimulatedHost.fw_token = None
            return {"ok": True}
        if method == "fw.pending":
            return {"pending": SimulatedHost.fw_token is not None, "seconds_left": 60}
        own = "table inet vpnix_create {\n\tchain input {\n\t\tudp dport 51820 accept\n\t}\n}\n"
        if method == "fw.show":
            return {"ruleset": own}
        if method == "fw.ruleset":
            return {"ruleset": "table inet filter {\n\tchain input { type filter hook input priority 0; policy accept; }\n}\n" + own}
        if method == "net.interfaces":
            return {"default": "eth0", "interfaces": [{"name": "eth0", "up": True, "managed_wg": False, "addresses": ["203.0.113.10/24"]}]}
        if method == "net.wg_interfaces":
            return {"interfaces": [{"name": n, "managed": True} for n in self.peers]}
        if method == "net.port_in_use":
            return {"in_use": False}
        if method == "net.ovpn_interfaces":
            return {"interfaces": []}
        if method in ("ovpn.apply", "ovpn.delete"):
            return {"ok": True}
        if method == "ovpn.service":
            if p["action"] == "status":
                return {"active": SimulatedHost.services.get(p["iface"], False), "enabled": True}
            SimulatedHost.services[p["iface"]] = p["action"] in ("start", "restart") or (
                SimulatedHost.services.get(p["iface"], False) and p["action"] != "stop")
            return {"ok": True}
        if method == "ovpn.status":
            return {"clients": []}
        if method == "wg.sync":
            SimulatedHost.peers[p["iface"]] = [x["public_key"] for x in p["peers"]]
            return {"ok": True}
        if method == "wg.service":
            if p["action"] == "status":
                return {"active": SimulatedHost.services.get(p["iface"], False), "enabled": True}
            SimulatedHost.services[p["iface"]] = p["action"] in ("start", "restart") or (
                SimulatedHost.services.get(p["iface"], False) and p["action"] != "stop")
            return {"ok": True}
        if method == "wg.delete":
            SimulatedHost.peers.pop(p["iface"], None)
            return {"ok": True}
        if method == "wg.dump":
            return {"running": True, "peers": []}
        if method == "sys.journal":
            return {"entries": [{"ts": 1763300000, "unit": "vpnix-create-api.service", "priority": 6, "message": "Application startup complete."},
                                {"ts": 1763300060, "unit": "vpnix-create-helper.service", "priority": 4, "message": "simulated warning"}]}
        if method == "sys.update":
            import json
            from pathlib import Path

            from . import updates
            st = {"state": "success", "version": p.get("version"), "previous": "0.1.0", "rollback_available": True,
                  "updated_at": "2026-01-01T00:00:00+00:00", "log": ["simulated update"]} if p["action"] == "install" else                  {"state": "rolled_back", "manual": True, "running": "0.1.0", "updated_at": "2026-01-01T00:01:00+00:00", "log": []}
            Path(updates.downloads(), "status.json").write_text(json.dumps(st))
            return {"ok": True}
        if method == "sys.status":
            return {"ipv4_forwarding": True, "ipv6_forwarding": True, "wireguard_tools": True, "nftables": True, "kernel": "simulated"}
        return {"ok": True}


def enabled() -> bool:
    if os.environ.get("VPNIX_UI_TEST_HELPER") != "1":
        return False
    if not get_settings().database_url.startswith("sqlite"):
        raise RuntimeError("VPNIX_UI_TEST_HELPER is only allowed with a SQLite test database")
    return True
