"""Browser-test support ONLY: a simulated host instead of the privileged helper.

Enabled with VPNIX_UI_TEST_HELPER=1 and refused unless the database is SQLite, so a production install can never
run against a fake system. Real system behaviour is verified on Linux by tests-e2e/.
"""
import os

from .config import get_settings


class SimulatedHost:
    peers: dict = {}
    services: dict = {}

    def call(self, method, **p):
        if method == "net.interfaces":
            return {"default": "eth0", "interfaces": [{"name": "eth0", "up": True, "managed_wg": False, "addresses": ["203.0.113.10/24"]}]}
        if method == "net.wg_interfaces":
            return {"interfaces": [{"name": n, "managed": True} for n in self.peers]}
        if method == "net.port_in_use":
            return {"in_use": False}
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
        if method == "sys.status":
            return {"ipv4_forwarding": True, "ipv6_forwarding": True, "wireguard_tools": True, "nftables": True, "kernel": "simulated"}
        return {"ok": True}


def enabled() -> bool:
    if os.environ.get("VPNIX_UI_TEST_HELPER") != "1":
        return False
    if not get_settings().database_url.startswith("sqlite"):
        raise RuntimeError("VPNIX_UI_TEST_HELPER is only allowed with a SQLite test database")
    return True
