"""Every route: anonymous requests are refused; lower roles cannot reach higher-privilege routes."""
import re

from fastapi.testclient import TestClient
from vpnix_manager.models import Role

from tests.conftest import login, make_user

PUBLIC = {"/api/health", "/api/auth/login"}


def _routes(app):
    for path, ops in app.openapi()["paths"].items():
        for method in ops:
            yield method.upper(), path, re.sub(r"\{[^}]+\}", "1", path)


def test_anonymous_refused_everywhere(app):
    c = TestClient(app)
    for method, path, url in _routes(app):
        if path not in PUBLIC:
            assert c.request(method, url, json={}).status_code in (401, 403), f"{method} {path}"


def test_viewer_and_operator_cannot_manage_users_or_audit(app, db):
    make_user(db, "boss")
    for role in (Role.VIEWER, Role.OPERATOR):
        make_user(db, f"u-{role}", role)
        c = login(app, f"u-{role}")
        assert c.get("/api/system/metrics").status_code == 200  # may view
        for method, url in (("GET", "/api/users"), ("POST", "/api/users"), ("PATCH", "/api/users/1"),
                            ("DELETE", "/api/users/1"), ("POST", "/api/users/1/reset-password"),
                            ("GET", "/api/system/audit")):
            assert c.request(method, url, json={}).status_code == 403, f"{role} {method} {url}"


def test_last_admin_protected(app, db):
    make_user(db, "boss")
    c = login(app, "boss")
    me = c.get("/api/auth/me").json()["id"]
    assert c.patch(f"/api/users/{me}", json={"role": "viewer"}).status_code == 409
    assert c.delete(f"/api/users/{me}").status_code == 409


def test_admin_user_lifecycle(app, db):
    make_user(db, "boss")
    c = login(app, "boss")
    r = c.post("/api/users", json={"username": "Bob", "role": "operator", "password": "initial-pass-for-user-1"})
    assert r.status_code == 201 and r.json()["username"] == "bob" and r.json()["must_change_password"]
    uid = r.json()["id"]
    assert c.post("/api/users", json={"username": "bob", "password": "initial-pass-for-user-1"}).status_code == 409
    temp = c.post(f"/api/users/{uid}/reset-password").json()["temporary_password"]
    assert login(app, "bob", temp).get("/api/auth/me").json()["must_change_password"] is True
    assert c.patch(f"/api/users/{uid}", json={"active": False}).json()["active"] is False
    assert TestClient(app).post("/api/auth/login", json={"username": "bob", "password": temp}).status_code == 401
    assert c.delete(f"/api/users/{uid}").status_code == 204
    audit = c.get("/api/system/audit", params={"category": "admin"}).json()
    assert audit["chain_ok"] and {e["action"] for e in audit["entries"]} >= {"user_create", "user_delete"}


def test_overview_reports_real_metrics(app, db):
    make_user(db, "boss")
    o = login(app, "boss").get("/api/system/overview").json()
    assert o["metrics"]["mem_total"] > 0 and o["metrics"]["cpu_count"] >= 1
    assert o["vpn"] == {"instances": 0, "running": 0, "stopped": 0, "clients": 0, "connected": 0, "rx_bytes": 0, "tx_bytes": 0}
