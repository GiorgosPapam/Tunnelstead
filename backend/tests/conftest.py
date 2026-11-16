import base64
import os

os.environ.setdefault("VPNIX_SECRET_KEY", base64.urlsafe_b64encode(os.urandom(32)).decode())
os.environ.setdefault("VPNIX_COOKIE_SECURE", "false")
os.environ.setdefault("VPNIX_BACKGROUND_JOBS", "false")

import pytest
from fastapi.testclient import TestClient
from vpnix_create import db as dbmod
from vpnix_create.cli import migrate
from vpnix_create.config import get_settings
from vpnix_create.deps import auth_limiter
from vpnix_create.main import create_app
from vpnix_create.models import Role, User
from vpnix_create.security import hash_password

PW = "correct-horse-battery-9"


@pytest.fixture
def app(tmp_path):
    url = f"sqlite:///{tmp_path}/t.db"
    get_settings().database_url = url  # so code that opens its own engine (CLI) uses the test DB
    migrate(dbmod.init_engine(url))  # real migrations, not create_all
    auth_limiter.hits.clear()
    return create_app()


@pytest.fixture
def db(app):
    s = dbmod._Session()
    yield s
    s.close()


def make_user(db, name, role=Role.ADMIN, must_change=False):
    u = User(username=name, role=role, password_hash=hash_password(PW), must_change_password=must_change)
    db.add(u)
    db.commit()
    return u


def login(app, name, pw=PW):
    c = TestClient(app)
    r = c.post("/api/auth/login", json={"username": name, "password": pw})
    assert r.status_code == 200, r.text
    c.headers["X-CSRF-Token"] = r.json()["csrf_token"]
    return c


class FakeHelper:
    """Simulated host for API tests (the real helper is exercised on a Linux VPS by tests-e2e)."""
    def __init__(self):
        self.calls, self.ports_in_use = [], {("udp", 51820)}  # e.g. someone's own WireGuard
        self.foreign_wg = ["wg0"]
        self.ifaces = [{"name": "eth0", "up": True, "managed_wg": False, "addresses": ["203.0.113.10/24", "10.0.0.5/24"]},
                       {"name": "wg0", "up": True, "managed_wg": False, "addresses": ["10.99.0.1/24"]}]
        self.peers, self.services, self.fail = {}, {}, False
        self.dump = {}
        self.ovpn, self.crl, self.sessions = {}, {}, {}

    def call(self, method, **p):
        from vpnix_create.helper_client import HelperError
        if self.fail:
            raise HelperError("simulated failure")
        self.calls.append((method, p))
        if method == "net.interfaces":
            return {"default": "eth0", "interfaces": self.ifaces}
        if method == "net.wg_interfaces":
            return {"interfaces": [{"name": n, "managed": False} for n in self.foreign_wg] +
                    [{"name": n, "managed": True} for n in self.peers]}
        if method == "net.port_in_use":
            return {"in_use": (p["transport"], p["port"]) in self.ports_in_use}
        if method == "net.ovpn_interfaces":
            return {"interfaces": [{"name": n, "managed": True} for n in self.ovpn]}
        if method == "ovpn.apply":
            self.ovpn[p["iface"]] = {c["cn"]: c for c in p["clients"]}
            self.crl[p["iface"]] = p["crl"]
            return {"ok": True}
        if method == "ovpn.service":
            if p["action"] == "status":
                return {"active": self.services.get(p["iface"], False), "enabled": True}
            running = self.services.get(p["iface"], False)
            self.services[p["iface"]] = p["action"] in ("start", "restart") or (running and p["action"] != "stop")
            return {"ok": True}
        if method == "ovpn.delete":
            self.ovpn.pop(p["iface"], None)
            return {"ok": True}
        if method == "ovpn.status":
            return {"clients": self.sessions.get(p["iface"], [])}
        if method == "wg.sync":
            self.peers[p["iface"]] = {x["public_key"]: x for x in p["peers"]}
            return {"ok": True}
        if method == "wg.service":
            if p["action"] == "status":
                return {"active": self.services.get(p["iface"], False), "enabled": True}
            running = self.services.get(p["iface"], False)
            self.services[p["iface"]] = p["action"] in ("start", "restart") or (running and p["action"] != "stop")
            return {"ok": True}
        if method == "wg.delete":
            self.peers.pop(p["iface"], None)
            return {"ok": True}
        if method == "wg.dump":
            return {"running": True, "peers": self.dump.get(p["iface"], [])}
        if method == "sys.status":
            return {"ipv4_forwarding": True, "ipv6_forwarding": True, "wireguard_tools": True, "nftables": True, "kernel": "6.8"}
        return {"ok": True}


@pytest.fixture
def helper(app):
    from vpnix_create.helper_client import get_helper
    h = FakeHelper()
    app.dependency_overrides[get_helper] = lambda: h
    return h


WG1 = {"name": "WG-Primary", "iface": "wg1", "listen_port": 51821, "endpoint_host": "vpn.example.org",
       "ipv4_cidr": "10.8.0.0/24", "ipv6_cidr": "fd08:8::/64", "dns": ["1.1.1.1"]}
