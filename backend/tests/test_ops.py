"""Phase 5: monitoring history, service logs, encrypted backups/restore, notifications."""
from datetime import UTC, datetime

import pytest
from tunnelstead import backup, collector, notify
from tunnelstead.models import HostMetric, InstanceMetric, Role, Setting, VpnInstance

from tests.conftest import PW, WG1, login, make_user

PASS = "a long backup passphrase"


def _admin(app, db):
    make_user(db, "boss")
    return login(app, "boss")


# ---------------------------------------------------------------- backups

def test_backup_roundtrip_restores_deleted_server(app, db, helper):
    c = _admin(app, db)
    assert c.post("/api/instances", json=WG1).status_code == 201
    b = c.post("/api/backups", json={"passphrase": PASS}).json()
    assert b["kind"] == "manual" and b["size"] > 0
    raw = (backup.backup_dir() / b["name"]).read_bytes()
    assert raw.startswith(backup.MAGIC) and b"WG-Primary" not in raw and b"wg1" not in raw  # encrypted

    pv = c.post(f"/api/backups/{b['name']}/preview", json={"passphrase": PASS}).json()
    assert pv["integrity_ok"] and pv["same_secret_key"] and pv["compatible"] and pv["contents"]["vpn_servers"] == 1
    assert "secret_key" not in pv
    assert c.post(f"/api/backups/{b['name']}/preview", json={"passphrase": "wrong passphrase!!"}).status_code == 422

    iid = c.get("/api/instances").json()[0]["id"]
    c.delete(f"/api/instances/{iid}?confirm=WG-Primary")
    assert c.get("/api/instances").json() == []
    assert c.post(f"/api/backups/{b['name']}/restore", json={"passphrase": PASS}).status_code == 422  # no confirmation
    helper.calls.clear()
    r = c.post(f"/api/backups/{b['name']}/restore", json={"passphrase": PASS, "confirm": b["name"]})
    assert r.status_code == 200, r.text
    assert r.json()["safety_backup"].endswith("pre-restore.tsbk") and r.json()["warnings"] == []
    assert any(m == "wg.sync" and p["iface"] == "wg1" for m, p in helper.calls)  # server redeployed
    assert c.get("/api/auth/me").status_code == 401  # old sessions are not restored
    c2 = login(app, "boss")
    assert [i["name"] for i in c2.get("/api/instances").json()] == ["WG-Primary"]
    assert c2.get("/api/system/audit", params={"q": "backup_restored"}).json()["entries"]


def test_tampered_backup_is_rejected(app, db, helper):
    c = _admin(app, db)
    b = c.post("/api/backups", json={"passphrase": PASS}).json()
    p = backup.backup_dir() / b["name"]
    data = bytearray(p.read_bytes())
    data[-5] ^= 0xFF
    p.write_bytes(bytes(data))
    r = c.post(f"/api/backups/{b['name']}/preview", json={"passphrase": PASS})
    assert r.status_code == 422 and "damaged" in r.json()["detail"]


def test_upload_download_and_names(app, db, helper):
    c = _admin(app, db)
    b = c.post("/api/backups", json={"passphrase": PASS}).json()
    blob = c.get(f"/api/backups/{b['name']}/download").content
    up = c.post("/api/backups/upload", content=blob, headers={"Content-Type": "application/octet-stream"})
    assert up.status_code == 201 and up.json()["kind"] == "uploaded"
    assert c.post(f"/api/backups/{up.json()['name']}/preview", json={"passphrase": PASS}).status_code == 200
    assert c.post("/api/backups/upload", content=b"not a backup").status_code == 422
    for bad in ("../tunnelstead.db", "tunnelstead-backup-x.tsbk", "..%2Ftunnelstead.db"):
        assert c.get(f"/api/backups/{bad}/download").status_code in (404, 422)
    assert c.delete(f"/api/backups/{up.json()['name']}").status_code == 204
    assert len(c.get("/api/backups").json()["backups"]) == 1


def test_backup_from_another_server_needs_cli(app, db, helper, monkeypatch):
    c = _admin(app, db)
    b = c.post("/api/backups", json={"passphrase": PASS}).json()
    monkeypatch.setattr(backup.get_settings(), "secret_key", "A" * 43)
    r = c.post(f"/api/backups/{b['name']}/restore", json={"passphrase": PASS, "confirm": b["name"]})
    assert r.status_code == 409 and "restore.sh" in r.json()["detail"]


def test_scheduled_backups_and_retention(app, db, helper):
    c = _admin(app, db)
    assert c.put("/api/backups/schedule", json={"enabled": True, "hour": 3, "keep": 2}).status_code == 422  # passphrase
    hour = datetime.now(UTC).hour
    assert c.put("/api/backups/schedule", json={"enabled": True, "hour": hour, "keep": 2, "passphrase": PASS}).status_code == 200
    names = []
    for _ in range(3):
        db.expire_all()
        st = db.get(Setting, "backup_schedule")
        st.value = {**st.value, "last_day": None}
        db.commit()
        names.append(collector.scheduled_backup(db))
    assert all(names)
    assert collector.scheduled_backup(db) is None  # once per day
    kept = [b["name"] for b in c.get("/api/backups").json()["backups"] if b["kind"] == "scheduled"]
    assert len(kept) == 2 and names[0] not in kept


def test_backups_admin_only(app, db, helper):
    make_user(db, "op", role=Role.OPERATOR)
    c = login(app, "op")
    assert c.get("/api/backups").status_code == 403
    assert c.post("/api/backups", json={"passphrase": PASS}).status_code == 403
    assert c.get("/api/notifications").status_code == 403


def test_short_passphrase_rejected(app, db, helper):
    c = _admin(app, db)
    assert c.post("/api/backups", json={"passphrase": "short"}).status_code == 422


# ---------------------------------------------------------------- monitoring

def test_metrics_history_and_instance_health(app, db, helper, monkeypatch):
    c = _admin(app, db)
    c.post("/api/instances", json=WG1)
    sent = []
    monkeypatch.setattr(notify, "deliver", lambda cfg, t, x: sent.append((t, x)) or [])
    c.put("/api/notifications", json={"webhook_url": "https://hooks.example.org/x", "events": ["instance_down", "instance_recovered"]})
    collector.collect(db, helper)
    collector.host_sample(db)
    collector.collect(db, helper)
    assert db.query(HostMetric).count() == 1 and db.query(InstanceMetric).count() >= 1
    m = c.get("/api/monitoring", params={"range": "1h"}).json()
    assert m["host"] and m["host"][0]["cpu"] >= 0 and m["instances"][0]["availability"] == 100.0
    assert c.get("/api/monitoring", params={"range": "1y"}).status_code == 422

    helper.services["wg1"] = False  # the service died
    collector.collect(db, helper)
    collector.collect(db, helper)  # still down: alerted only once
    import time
    time.sleep(0.2)
    assert [t for t, _ in sent] == ["A VPN server stopped running"]
    assert c.get("/api/monitoring", params={"range": "1h"}).json()["health"]["down"] == ["WG-Primary"]
    helper.services["wg1"] = True
    collector.collect(db, helper)
    time.sleep(0.2)
    assert sent[-1][0] == "A VPN server is running again"
    assert c.get("/api/monitoring").json()["health"]["down"] == []


def test_service_logs(app, db, helper):
    c = _admin(app, db)
    c.post("/api/instances", json=WG1)
    r = c.get("/api/logs/services", params={"priority": "error", "q": "fail"}).json()
    assert "wg-quick@wg1" in r["units"] and [e["message"] for e in r["entries"]] == ["Failed to start"]
    assert helper.journal_args["priority"] == "error" and "tunnelstead-api" in helper.journal_args["units"]
    assert c.get("/api/logs/services", params={"unit": "sshd"}).status_code == 422
    make_user(db, "viewer", role=Role.VIEWER)
    assert login(app, "viewer").get("/api/logs/services").status_code == 403


# ---------------------------------------------------------------- notifications

def test_notification_config(app, db, helper, monkeypatch):
    c = _admin(app, db)
    assert c.put("/api/notifications", json={"webhook_url": "http://insecure.example"}).status_code == 422
    assert c.put("/api/notifications", json={"email": {"host": "smtp.example.org"}}).status_code == 422  # no recipients
    r = c.put("/api/notifications", json={"webhook_url": "https://hooks.example.org/x", "events": ["login_locked", "bogus"],
                                          "email": {"host": "smtp.example.org", "sender": "vpn@example.org",
                                                    "recipients": ["ops@example.org"], "password": "smtp-secret"}})
    cfg = r.json()
    assert cfg["events"] == ["login_locked"] and cfg["email"]["has_password"] and "password_enc" not in cfg["email"]
    stored = db.get(Setting, "notifications").value
    assert "smtp-secret" not in str(stored)
    c.put("/api/notifications", json={**{k: cfg[k] for k in ("webhook_url", "events")}, "email": {**cfg["email"]}})
    assert c.get("/api/notifications").json()["email"]["has_password"]  # kept when not sent

    calls = []
    monkeypatch.setattr(notify, "_webhook", lambda url, t, x: calls.append(url))
    monkeypatch.setattr(notify, "_email", lambda cfg, t, x: (_ for _ in ()).throw(OSError("connection refused")))
    t = c.post("/api/notifications/test").json()
    assert calls == ["https://hooks.example.org/x"] and t["ok"] is False and "connection refused" in t["errors"][0]


def test_lockout_sends_one_alert(app, db, helper, monkeypatch):
    c = _admin(app, db)
    c.put("/api/notifications", json={"webhook_url": "https://hooks.example.org/x", "events": ["login_locked"]})
    sent = []
    monkeypatch.setattr(notify, "deliver", lambda cfg, t, x: sent.append(x) or [])
    make_user(db, "alice")
    from fastapi.testclient import TestClient
    anon = TestClient(app)
    for _ in range(12):
        anon.post("/api/auth/login", json={"username": "alice", "password": "wrong-" + PW})
    import time
    time.sleep(0.2)
    assert len(sent) == 1 and "alice" in sent[0]


@pytest.mark.parametrize("bad", [["sshd"], ["wg-quick@eth0"], "tunnelstead-api", [], ["caddy; rm -rf /"]])
def test_helper_journal_rejects_bad_units(bad):
    from tests.test_helper import helper as H
    with pytest.raises(H.Invalid):
        H.sys_journal(bad)


def test_helper_journal_bounds():
    from tests.test_helper import helper as H
    for kw in ({"lines": 0}, {"lines": 5000}, {"priority": "debug"}, {"since_hours": 0}, {"lines": True}):
        with pytest.raises(H.Invalid):
            H.sys_journal(["caddy"], **kw)


def test_instance_model_unchanged_by_metrics(db, app):
    assert db.query(VpnInstance).count() == 0


def test_openapi_hidden_in_production(app):
    from fastapi.testclient import TestClient
    assert TestClient(app).get("/api/openapi.json").status_code == 404


@pytest.mark.parametrize("url", ["https://127.0.0.1/x", "https://localhost/x", "https://169.254.169.254/latest", "https://[::1]/x"])
def test_webhook_refuses_local_targets(url):
    with pytest.raises(ValueError, match="not allowed"):
        notify.check_target(url)


def test_webhook_errors_are_reported_not_raised(monkeypatch):
    errs = notify.deliver({"webhook_url": "https://127.0.0.1/hook", "email": {}}, "t", "x")
    assert errs and "not allowed" in errs[0]


def test_restores_backups_made_under_the_old_name(app, db, helper):
    """Backups made as VPNix (header VPNIXBK1, vpnix.db inside, .vbk name) must still restore after the rename."""
    import io
    import json
    import os
    import tarfile

    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    c = _admin(app, db)
    b = c.post("/api/backups", json={"passphrase": PASS}).json()
    p = backup.backup_dir() / b["name"]
    manifest, raw = backup.open_backup(p, PASS)
    manifest["app"] = "vpnix-create"
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for name, data in (("manifest.json", json.dumps(manifest).encode()), ("vpnix.db", raw)):
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    salt, nonce = os.urandom(16), os.urandom(12)
    old = b"VPNIXBK1"
    legacy = backup.backup_dir() / b["name"].replace("tunnelstead-", "vpnix-").replace(".tsbk", ".vbk")
    legacy.write_bytes(old + salt + nonce + AESGCM(backup._key(PASS, salt)).encrypt(nonce, buf.getvalue(), old))
    p.unlink()
    assert legacy.name in [x["name"] for x in c.get("/api/backups").json()["backups"]]
    r = c.post(f"/api/backups/{legacy.name}/preview", json={"passphrase": PASS})
    assert r.status_code == 200 and r.json()["integrity_ok"], r.text
    up = c.post("/api/backups/upload", content=legacy.read_bytes(), headers={"Content-Type": "application/octet-stream"})
    assert up.status_code == 201
