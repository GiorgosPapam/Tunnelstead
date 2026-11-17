"""Security hardening: 2FA replay, bounded rate limiter, request size limits, pinned webhook connections."""
import socket
import time

import pyotp
import pytest
from fastapi.testclient import TestClient
from tunnelstead import notify
from tunnelstead.deps import RateLimiter, auth_limiter

from tests.conftest import PW, login, make_user


def _mfa_user(app, db, name="mallory-victim"):
    make_user(db, name)
    c = login(app, name)
    secret = c.post("/api/auth/mfa/setup").json()["secret"]
    assert c.post("/api/auth/mfa/enable", json={"code": pyotp.TOTP(secret).now()}).status_code == 200
    return secret


def _second_factor(app, name, code):
    c = TestClient(app)
    r = c.post("/api/auth/login", json={"username": name, "password": PW})
    c.headers["X-CSRF-Token"] = r.json()["csrf_token"]
    return c.post("/api/auth/mfa/verify", json={"code": code}).status_code


def test_totp_code_cannot_be_replayed(app, db):
    secret = _mfa_user(app, db)
    code = pyotp.TOTP(secret).at(time.time() + 30)
    assert _second_factor(app, "mallory-victim", code) == 200
    assert _second_factor(app, "mallory-victim", code) == 401           # same code again: refused
    old = pyotp.TOTP(secret).now()                                      # an older step than the one used
    assert _second_factor(app, "mallory-victim", old) == 401
    assert _second_factor(app, "mallory-victim", "12345") in (401, 422)  # malformed: rejected


def test_enabling_mfa_code_cannot_be_reused_to_sign_in(app, db):
    secret = _mfa_user(app, db, "bob-mfa")
    assert _second_factor(app, "bob-mfa", pyotp.TOTP(secret).now()) == 401


def test_wrong_codes_on_mfa_endpoints_count_toward_lockout(app, db):
    make_user(db, "carol-mfa")
    c = login(app, "carol-mfa")
    c.post("/api/auth/mfa/setup")
    for _ in range(5):
        auth_limiter.hits.clear()
        c.post("/api/auth/mfa/enable", json={"code": "000000"})
    auth_limiter.hits.clear()
    assert TestClient(app).post("/api/auth/login", json={"username": "carol-mfa", "password": PW}).status_code == 401


def test_rate_limiter_memory_is_bounded(monkeypatch):
    rl = RateLimiter(3, 60)
    monkeypatch.setattr(RateLimiter, "MAX_KEYS", 100)
    for i in range(5000):
        rl.check(f"10.{i // 65536}.{(i // 256) % 256}.{i % 256}")
    assert len(rl.hits) <= 100


def test_rate_limiter_groups_ipv6_by_64():
    rl = RateLimiter(3, 60)
    for host in ("2001:db8:1:2::1", "2001:db8:1:2::2", "2001:db8:1:2:ffff::9"):
        rl.check(host)
    with pytest.raises(Exception, match="429|Too many"):
        rl.check("2001:db8:1:2:aaaa::1")  # same /64: same budget
    rl.check("2001:db8:1:3::1")  # another /64 is separate


def test_oversized_bodies_are_refused_before_reading(app, db):
    c = TestClient(app)
    big = '{"username": "x", "password": "' + "a" * (2 * 1024 * 1024) + '"}'
    r = c.post("/api/auth/login", content=big, headers={"Content-Type": "application/json"})
    assert r.status_code == 413
    r = c.post("/api/auth/login", content=b"{}", headers={"Content-Type": "application/json", "Content-Length": "abc"})
    assert r.status_code in (400, 413)


def test_webhook_connection_is_pinned_to_checked_address(monkeypatch):
    """DNS rebinding: even if DNS changes after the check, the connection goes to the address that was checked."""
    answers = iter([[(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.215.14", 443))],
                    [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 443))]])
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: next(answers))
    seen = []

    def fake_connect(addr, timeout=None):
        seen.append(addr)
        raise OSError("stop here")
    monkeypatch.setattr(socket, "create_connection", fake_connect)
    with pytest.raises(OSError):
        notify._webhook("https://hooks.example.org/x", "t", "x")
    assert seen == [("93.184.215.14", 443)]
