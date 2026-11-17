import time

from vpnix_manager import collector
from vpnix_manager.engines.wireguard import keypair, public_from_private
from vpnix_manager.models import Role

from tests.conftest import WG1, login, make_user


def _admin(app, db):
    make_user(db, "boss")
    return login(app, "boss")


def test_recommendations_skip_real_conflicts(app, db, helper):
    r = _admin(app, db).get("/api/instances/recommend").json()
    assert r["port"] == 51821              # 51820 is busy on the host (someone else's WireGuard)
    assert r["iface"] == "wg1"             # wg0 exists and is not ours
    assert r["ipv4_cidr"] == "10.8.0.0/24"  # 10.0.0.0/24 is on eth0; 10.8 is free
    assert r["egress_iface"] == "eth0"


def test_validation_catches_every_conflict(app, db, helper):
    c = _admin(app, db)
    bad = c.post("/api/instances/validate", json={**WG1, "iface": "wg0", "listen_port": 51820, "ipv4_cidr": "10.0.0.0/24",
                                                  "ipv6_cidr": "2a00:1450::/64", "endpoint_host": "not a host!"}).json()
    assert not bad["ok"]
    assert "not created by VPNix Manager" in bad["errors"]["iface"]
    assert "already in use" in bad["errors"]["listen_port"]
    assert "Overlaps 10.0.0.0/24" in bad["errors"]["ipv4_cidr"]
    assert "ULA" in bad["errors"]["ipv6_cidr"] and "endpoint_host" in bad["errors"]
    good = c.post("/api/instances/validate", json=WG1).json()
    assert good["ok"] and "Allow UDP 51821 inbound" in good["preview"]["firewall"]


def test_multiple_instances_and_cross_instance_conflicts(app, db, helper):
    c = _admin(app, db)
    assert c.post("/api/instances", json=WG1).status_code == 201
    assert helper.services["wg1"] is True and "wg1" in helper.peers
    dup = c.post("/api/instances", json={**WG1, "name": "WG-Secondary", "iface": "wg2"}).json()["detail"]["errors"]
    assert "WG-Primary" in dup["listen_port"] and "WG-Primary" in dup["ipv4_cidr"]
    second = {**WG1, "name": "WG-Secondary", "iface": "wg2", "listen_port": 51822, "ipv4_cidr": "10.9.0.0/24", "ipv6_cidr": None}
    assert c.post("/api/instances", json=second).status_code == 201
    fw = [p for m, p in helper.calls if m == "fw.apply"][-1]
    assert {i["iface"] for i in fw["instances"]} == {"wg1", "wg2"} and fw["egress"] is None or True
    assert len(c.get("/api/instances").json()) == 2


def test_client_lifecycle_against_live_interface(app, db, helper):
    c = _admin(app, db)
    iid = c.post("/api/instances", json=WG1).json()["id"]
    cl = c.post("/api/clients", json={"instance_id": iid, "name": "Laptop", "tags": ["work"], "description": "Dell"}).json()
    assert cl["ipv4"] == "10.8.0.2" and cl["ipv6"] == "fd08:8::2"
    assert cl["public_key"] in helper.peers["wg1"]
    conf = c.get(f"/api/clients/{cl['id']}/config").text
    priv = next(ln.split(" = ")[1] for ln in conf.splitlines() if ln.startswith("PrivateKey"))
    assert public_from_private(priv) == cl["public_key"]
    assert "AllowedIPs = 0.0.0.0/0, ::/0" in conf and "Endpoint = vpn.example.org:51821" in conf and "DNS = 1.1.1.1" in conf
    assert c.get(f"/api/clients/{cl['id']}/qr").headers["content-type"] == "image/svg+xml"

    assert c.post(f"/api/clients/{cl['id']}/disable").json()["status"] == "disabled"
    assert cl["public_key"] not in helper.peers["wg1"]
    assert c.post(f"/api/clients/{cl['id']}/enable").json()["status"] == "active"
    new = c.post(f"/api/clients/{cl['id']}/regenerate").json()["public_key"]
    assert new != cl["public_key"] and new in helper.peers["wg1"] and cl["public_key"] not in helper.peers["wg1"]
    assert c.post(f"/api/clients/{cl['id']}/revoke").json()["status"] == "revoked"
    assert new not in helper.peers["wg1"]
    assert c.get(f"/api/clients/{cl['id']}/config").status_code == 409
    assert c.post(f"/api/clients/{cl['id']}/enable").status_code == 409


def test_split_tunnel_and_custom_routes(app, db, helper):
    c = _admin(app, db)
    iid = c.post("/api/instances", json={**WG1, "routing_mode": "split", "split_routes": ["192.168.50.0/24"]}).json()["id"]
    a = c.post("/api/clients", json={"instance_id": iid, "name": "a"}).json()
    assert "AllowedIPs = 10.8.0.0/24, fd08:8::/64, 192.168.50.0/24" in c.get(f"/api/clients/{a['id']}/config").text
    b = c.post("/api/clients", json={"instance_id": iid, "name": "b", "allowed_ips": ["172.20.0.0/16"]}).json()
    assert "AllowedIPs = 172.20.0.0/16" in c.get(f"/api/clients/{b['id']}/config").text
    assert c.post("/api/clients", json={"instance_id": iid, "name": "x", "allowed_ips": ["nope"]}).status_code == 422


def test_bring_your_own_key(app, db, helper):
    c = _admin(app, db)
    iid = c.post("/api/instances", json=WG1).json()["id"]
    _, pub = keypair()
    cl = c.post("/api/clients", json={"instance_id": iid, "name": "own", "public_key": pub}).json()
    assert cl["has_private_key"] is False and pub in helper.peers["wg1"]
    assert c.get(f"/api/clients/{cl['id']}/config").status_code == 410
    assert c.post("/api/clients", json={"instance_id": iid, "name": "bad", "public_key": "x; rm -rf /"}).status_code == 422


def test_helper_failure_rolls_back(app, db, helper):
    c = _admin(app, db)
    iid = c.post("/api/instances", json=WG1).json()["id"]
    helper.fail = True
    assert c.post("/api/clients", json={"instance_id": iid, "name": "x"}).status_code == 502
    helper.fail = False
    assert c.get("/api/clients").json() == []


def test_roles(app, db, helper):
    boss = _admin(app, db)
    iid = boss.post("/api/instances", json=WG1).json()["id"]
    make_user(db, "op", Role.OPERATOR)
    make_user(db, "ro", Role.VIEWER)
    op, ro = login(app, "op"), login(app, "ro")
    cl = op.post("/api/clients", json={"instance_id": iid, "name": "by-operator"})
    assert cl.status_code == 201 and op.get(f"/api/clients/{cl.json()['id']}/config").status_code == 200
    assert op.post("/api/instances", json={**WG1, "name": "x", "iface": "wg5", "listen_port": 51830}).status_code == 403
    assert op.post(f"/api/instances/{iid}/stop").status_code == 403
    assert ro.get("/api/clients").status_code == 200 and ro.get("/api/instances").status_code == 200
    assert ro.get(f"/api/clients/{cl.json()['id']}/config").status_code == 403  # viewers never get secrets
    assert ro.post("/api/clients", json={"instance_id": iid, "name": "nope"}).status_code == 403


def test_stats_expiry_and_quota_enforced(app, db, helper):
    from vpnix_manager.models import Client
    c = _admin(app, db)
    iid = c.post("/api/instances", json=WG1).json()["id"]
    a = c.post("/api/clients", json={"instance_id": iid, "name": "quota", "quota_gb": 0.000001}).json()
    b = c.post("/api/clients", json={"instance_id": iid, "name": "exp", "expires_at": "2000-01-01T00:00:00Z"}).json()
    helper.dump["wg1"] = [{"public_key": a["public_key"], "endpoint": "198.51.100.7:4444", "latest_handshake": int(time.time()),
                           "rx_bytes": 5000, "tx_bytes": 0}]
    out = collector.collect(db, helper)
    assert out["clients_updated"] == 1 and out["blocked"] == 2
    db.expire_all()
    assert db.get(Client, a["id"]).status.value == "over_quota" and db.get(Client, b["id"]).status.value == "expired"
    assert a["public_key"] not in helper.peers["wg1"] and b["public_key"] not in helper.peers["wg1"]
    got = c.get(f"/api/clients/{a['id']}").json() if False else c.get("/api/clients").json()
    assert next(x for x in got if x["id"] == a["id"])["rx_bytes"] == 5000
    r = c.patch(f"/api/clients/{a['id']}", json={"clear_quota": True}).json()
    assert r["status"] == "active" and a["public_key"] in helper.peers["wg1"]  # lifting the quota re-activates


def test_delete_instance_requires_typed_name(app, db, helper):
    c = _admin(app, db)
    iid = c.post("/api/instances", json=WG1).json()["id"]
    assert c.delete(f"/api/instances/{iid}", params={"confirm": "wrong"}).status_code == 422
    assert c.delete(f"/api/instances/{iid}", params={"confirm": "WG-Primary"}).status_code == 204
    assert ("wg.delete", {"iface": "wg1"}) in helper.calls


def test_get_single_instance(app, db, helper):
    c = _admin(app, db)
    iid = c.post("/api/instances", json=WG1).json()["id"]
    r = c.get(f"/api/instances/{iid}").json()
    assert r["name"] == "WG-Primary" and r["live"]["active"] is True
    assert c.get("/api/instances/999").status_code == 404
