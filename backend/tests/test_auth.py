import re

import pyotp
from fastapi.testclient import TestClient
from tunnelstead import audit
from tunnelstead.cli import main as cli
from tunnelstead.deps import auth_limiter
from tunnelstead.models import AuditEntry, Role, User

from tests.conftest import PW, login, make_user


def test_generic_error_for_unknown_wrong_and_locked(app, db):
    make_user(db, "alice")
    c = TestClient(app)
    msgs = set()
    for name, pw in (("nobody", "x" * 12), ("alice", "wrong-password-1")):
        r = c.post("/api/auth/login", json={"username": name, "password": pw})
        assert r.status_code == 401
        msgs.add(r.json()["detail"])
    for _ in range(5):
        c.post("/api/auth/login", json={"username": "alice", "password": "wrong-password-1"})
    auth_limiter.hits.clear()
    r = c.post("/api/auth/login", json={"username": "alice", "password": PW})  # right password, locked
    assert r.status_code == 401
    msgs.add(r.json()["detail"])
    assert msgs == {"Incorrect username or password"}


def test_ip_rate_limit(app):
    c = TestClient(app)
    codes = [c.post("/api/auth/login", json={"username": f"u{i}", "password": "x" * 12}).status_code for i in range(12)]
    assert 429 in codes


def test_cookie_flags_and_csrf(app, db):
    make_user(db, "alice")
    r = TestClient(app).post("/api/auth/login", json={"username": "alice", "password": PW})
    sc = r.headers["set-cookie"].lower()
    assert "httponly" in sc and "samesite=strict" in sc
    c = login(app, "alice")
    del c.headers["X-CSRF-Token"]
    assert c.post("/api/auth/logout").status_code == 403


def test_security_headers_and_no_docs(app):
    c = TestClient(app)
    h = c.get("/api/health").headers
    assert "frame-ancestors 'none'" in h["content-security-policy"] and h["x-frame-options"] == "DENY"
    assert c.get("/docs").status_code == 404  # interactive docs are not exposed


def test_forced_password_change_flow(app, db):
    make_user(db, "admin", must_change=True)
    c = login(app, "admin")
    assert c.get("/api/system/metrics").status_code == 403
    r = c.post("/api/auth/password", json={"current_password": PW, "new_password": "short"})
    assert r.status_code == 422
    r = c.post("/api/auth/password", json={"current_password": PW, "new_password": "admin-is-in-here-123"})
    assert r.status_code == 422  # contains the username
    r = c.post("/api/auth/password", json={"current_password": PW, "new_password": "a-new-strong-passphrase"})
    c.headers["X-CSRF-Token"] = r.json()["csrf_token"]
    assert c.get("/api/system/metrics").status_code == 200


def test_password_change_revokes_other_sessions(app, db):
    make_user(db, "alice")
    a, b = login(app, "alice"), login(app, "alice")
    r = a.post("/api/auth/password", json={"current_password": PW, "new_password": "another-good-passphrase"})
    assert r.status_code == 200 and b.get("/api/auth/me").status_code == 401


def test_session_list_and_revoke(app, db):
    make_user(db, "alice")
    a, b = login(app, "alice"), login(app, "alice")
    sessions = a.get("/api/auth/sessions").json()
    other = next(s for s in sessions if not s["current"])
    assert a.delete(f"/api/auth/sessions/{other['id']}").status_code == 204
    assert b.get("/api/auth/me").status_code == 401


def test_mfa_with_recovery_codes_and_lockout(app, db):
    make_user(db, "alice")
    c = login(app, "alice")
    secret = c.post("/api/auth/mfa/setup").json()["secret"]
    codes = c.post("/api/auth/mfa/enable", json={"code": pyotp.TOTP(secret).now()}).json()["recovery_codes"]
    assert len(codes) == 10

    def second_factor(code):
        c2 = TestClient(app)
        r = c2.post("/api/auth/login", json={"username": "alice", "password": PW})
        assert r.json()["mfa_required"] is True
        c2.headers["X-CSRF-Token"] = r.json()["csrf_token"]
        assert c2.get("/api/auth/me").status_code == 401  # half-signed-in session is useless
        return c2.post("/api/auth/mfa/verify", json={"code": code}).status_code

    assert second_factor(codes[0]) == 200
    assert second_factor(codes[0]) == 401  # single use
    assert second_factor(pyotp.TOTP(secret).now()) == 200
    for _ in range(5):  # distributed guessing: per-IP limiter reset each round, account lock still applies
        auth_limiter.hits.clear()
        c3 = TestClient(app)
        r = c3.post("/api/auth/login", json={"username": "alice", "password": PW})
        if r.status_code != 200:
            break
        c3.headers["X-CSRF-Token"] = r.json()["csrf_token"]
        c3.post("/api/auth/mfa/verify", json={"code": "000000"})
    auth_limiter.hits.clear()
    assert TestClient(app).post("/api/auth/login", json={"username": "alice", "password": PW}).status_code == 401


def test_audit_chain_detects_tampering(app, db):
    make_user(db, "alice")
    login(app, "alice")
    login(app, "alice")
    assert audit.verify(db) == (True, None)
    row = db.query(AuditEntry).first()
    row.success = False
    db.commit()
    assert audit.verify(db)[0] is False


def test_cli_init_admin_random_password_once(app, db, capsys):
    assert cli(["init-admin", "--username", "Root"]) == 0
    out = capsys.readouterr().out
    pw = re.search(r"TUNNELSTEAD_ADMIN_PASSWORD=(\S+)", out).group(1)
    assert len(pw) >= 20
    u = db.query(User).filter_by(username="root").one()
    assert u.role == Role.ADMIN and u.must_change_password
    assert cli(["init-admin"]) == 0 and "already exists" in capsys.readouterr().err  # never a second one
    c = login(app, "root", pw)
    assert c.get("/api/auth/me").json()["must_change_password"] is True


def test_csrf_token_survives_page_reload(app, db):
    from tests.conftest import login, make_user
    make_user(db, "reload")
    c = login(app, "reload")
    issued = c.headers["X-CSRF-Token"]
    del c.headers["X-CSRF-Token"]  # the reloaded tab has lost it
    assert c.post("/api/auth/logout").status_code == 403
    again = c.get("/api/auth/csrf").json()["csrf_token"]
    assert again == issued
    c.headers["X-CSRF-Token"] = again
    assert c.post("/api/auth/logout").status_code in (200, 204)
    assert c.get("/api/auth/csrf").status_code == 401
