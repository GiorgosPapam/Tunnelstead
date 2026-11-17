import time

from tunnelstead.models import Role, Setting

from tests.conftest import WG1, login, make_user


def _admin(app, db):
    make_user(db, "boss")
    return login(app, "boss")


def test_rule_requires_confirmation_or_rolls_back(app, db, helper):
    c = _admin(app, db)
    r = c.post("/api/firewall/rules", json={"action": "accept", "proto": "tcp", "ports": "8000-8100",
                                             "source": "198.51.100.7", "comment": "office"})
    assert r.status_code == 201 and r.json()["rollback_seconds"] == 60
    applied = helper.fw_applied[-1]
    assert applied["rollback_seconds"] == 60 and applied["custom_rules"][0]["source"] == "198.51.100.7/32"
    assert c.get("/api/firewall").json()["pending"]["seconds_left"] > 0
    assert c.post("/api/firewall/confirm", json={"token": r.json()["confirm_token"]}).json()["ok"]
    assert c.get("/api/firewall").json()["pending"] is None and len(c.get("/api/firewall").json()["rules"]) == 1

    # Second change is NOT confirmed: once the window has passed and the helper restored the table,
    # the database is restored too, so later VPN changes cannot re-apply the unconfirmed rule.
    c.post("/api/firewall/rules", json={"action": "drop", "proto": "tcp", "ports": "443"})
    assert len(c.get("/api/firewall").json()["rules"]) == 2
    pend = db.get(Setting, "fw_pending")
    db.refresh(pend)
    pend.value = {**pend.value, "deadline": time.time() - 1}
    db.commit()
    helper.fw_token = None  # the helper's timer fired
    st = c.get("/api/firewall").json()
    assert len(st["rules"]) == 1 and st["pending"] is None
    assert c.get("/api/system/audit", params={"q": "firewall_rolled_back"}).json()["entries"]


def test_lockout_protection(app, db, helper):
    c = _admin(app, db)  # TestClient connects from "testclient"
    r = c.put("/api/firewall/management", json={"enabled": True, "networks": ["192.0.2.0/24"]})
    assert r.status_code in (201, 200, 409, 422)
    me = c.get("/api/firewall").json()["your_ip"]
    if me != "testclient":
        assert r.status_code == 409 and "lock you out" in r.json()["detail"]
    r = c.put("/api/firewall/management", json={"enabled": True, "networks": ["192.0.2.0/24"], "include_ssh": True,
                                                "i_understand_lockout_risk": True})
    assert r.status_code == 200
    assert helper.fw_applied[-1]["management"] == {"networks": ["192.0.2.0/24"], "ports": [80, 443, 22]}
    assert c.put("/api/firewall/management", json={"enabled": True, "networks": []}).status_code == 422


def test_rule_validation(app, db, helper):
    c = _admin(app, db)
    for bad in ({"action": "accept", "proto": "any", "ports": "22"}, {"action": "drop", "proto": "tcp", "ports": "70000"},
                {"action": "drop", "proto": "tcp", "source": "nope"}, {"action": "drop", "proto": "tcp", "comment": 'x"; flush'},
                {"action": "reject", "proto": "tcp"}):
        assert c.post("/api/firewall/rules", json=bad).status_code == 422, bad


def test_only_admins_change_firewall(app, db, helper):
    _admin(app, db)
    make_user(db, "op", Role.OPERATOR)
    op = login(app, "op")
    assert op.get("/api/firewall").status_code == 200
    assert op.post("/api/firewall/rules", json={"action": "drop", "proto": "tcp", "ports": "22"}).status_code == 403
    assert op.put("/api/firewall/management", json={"enabled": False}).status_code == 403


def test_network_checks_and_routing_preview(app, db, helper):
    c = _admin(app, db)
    iid = c.post("/api/instances", json={**WG1, "ipv6_cidr": None, "dns": []}).json()["id"]
    checks = {x["name"]: x for x in c.get("/api/network/checks").json()[0]["checks"]}
    assert checks["IPv4 forwarding"]["ok"] and checks["Firewall allows the VPN port"]["ok"]
    assert not checks["IPv6 leak protection"]["ok"] and not checks["DNS leak protection"]["ok"]
    c.post("/api/clients", json={"instance_id": iid, "name": "a"})
    c.post("/api/clients", json={"instance_id": iid, "name": "own-routes", "allowed_ips": ["10.0.0.0/8"]})
    p = c.post(f"/api/instances/{iid}/routing", json={"preset": "private"}).json()
    assert p["before"] == ["0.0.0.0/0"] and p["after"] == ["10.8.0.0/24", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
    assert p["affected_clients"] == ["a"] and "applied" not in p
    assert c.get(f"/api/instances/{iid}").json()["routing_mode"] == "full"  # preview changed nothing
    assert c.post(f"/api/instances/{iid}/routing", json={"preset": "private", "apply": True}).json()["applied"]
    assert c.get(f"/api/instances/{iid}").json()["routing_mode"] == "split"
    assert c.post(f"/api/instances/{iid}/routing", json={"preset": "custom", "routes": ["bad"]}).status_code == 422
