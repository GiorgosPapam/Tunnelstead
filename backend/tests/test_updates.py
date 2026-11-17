"""Phase 6: signed updates. The release tool, API checks and the root updater's verification logic."""
import base64
import importlib.util
import io
import json
import os
import pathlib
import tarfile

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from tunnelstead import __version__, updates
from tunnelstead.models import Role

from tests.conftest import login, make_user

ROOT = pathlib.Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("updater", ROOT / "updater" / "updater.py")
U = importlib.util.module_from_spec(spec)
spec.loader.exec_module(U)


def bump(v, n=1):
    a, b, c = (int(x) for x in v.split("."))
    return f"{a}.{b}.{c + n}"


def make_bundle(d: pathlib.Path, key, version, content_version=None, extra=None):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as t:
        for name, data in {"VERSION": (content_version or version) + "\n", "installer/install.sh": "exit 0\n", **(extra or {})}.items():
            info = tarfile.TarInfo(f"tunnelstead-{version}/{name}")
            info.size = len(data.encode())
            t.addfile(info, io.BytesIO(data.encode()))
    blob = buf.getvalue()
    p = d / f"tunnelstead-{version}.tar.gz"
    p.write_bytes(blob)
    import hashlib
    sig = key.sign(f"tunnelstead-release:{version}:{hashlib.sha256(blob).hexdigest()}".encode())
    pathlib.Path(str(p) + ".sig").write_text(base64.b64encode(sig).decode())
    return p


@pytest.fixture
def key(tmp_path, monkeypatch):
    k = Ed25519PrivateKey.generate()
    pub = tmp_path / "release-key.pub"
    pub.write_text(base64.b64encode(k.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).decode())
    monkeypatch.setattr(updates, "public_key", lambda: k.public_key())
    return k, pub


@pytest.fixture
def feed(tmp_path, monkeypatch):
    d = tmp_path / "feed"
    d.mkdir()
    monkeypatch.setenv("TUNNELSTEAD_UPDATE_FEED_DIR", str(d))
    monkeypatch.setenv("TUNNELSTEAD_UPDATE_DIR", str(tmp_path / "dl"))
    return d


def test_check_download_install_flow(app, db, helper, key, feed):
    k, _ = key
    new = bump(__version__)
    make_bundle(feed, k, new)
    make_bundle(feed, k, __version__)  # same version: never offered
    (feed / f"{new}.md").write_text("Fixes and improvements")
    make_user(db, "boss")
    c = login(app, "boss")
    o = c.post("/api/updates/check").json()
    assert o["check"]["latest"]["version"] == new and [v["version"] for v in o["check"]["newer"]] == [new]
    assert o["check"]["newer"][0]["notes"] == "Fixes and improvements"
    assert c.post(f"/api/updates/{new}/install").status_code == 422  # not downloaded yet
    r = c.post(f"/api/updates/{new}/download").json()
    assert r["verified"] and len(r["sha256"]) == 64
    assert c.get("/api/updates").json()["downloaded"] == [new]
    assert c.post(f"/api/updates/{new}/install").status_code == 202
    assert ("sys.update", {"action": "install", "version": new}) in helper.calls
    assert c.get("/api/system/audit", params={"q": "update_started"}).json()["entries"]


def test_downgrade_and_bad_signature_refused(app, db, helper, key, feed):
    k, _ = key
    make_user(db, "boss")
    c = login(app, "boss")
    assert c.post(f"/api/updates/{__version__}/download").status_code == 422
    other = Ed25519PrivateKey.generate()
    new = bump(__version__)
    make_bundle(feed, other, new)  # signed by someone else
    r = c.post(f"/api/updates/{new}/download")
    assert r.status_code == 422 and "Signature" in r.json()["detail"]
    assert not list((pathlib.Path(updates.downloads())).glob("*.tar.gz"))  # rejected file removed


def test_relabelled_old_bundle_refused(app, db, helper, key, feed):
    """A genuinely signed old bundle renamed to a newer version must fail: the signature covers the version."""
    k, _ = key
    old = make_bundle(feed, k, __version__)
    new = bump(__version__, 5)
    target = feed / f"tunnelstead-{new}.tar.gz"
    old.rename(target)
    pathlib.Path(str(old) + ".sig").rename(str(target) + ".sig")
    make_user(db, "boss")
    c = login(app, "boss")
    assert c.post(f"/api/updates/{new}/download").status_code == 422


def test_settings_and_permissions(app, db, helper):
    make_user(db, "boss")
    c = login(app, "boss")
    assert c.put("/api/updates/settings", json={"repo": "bad repo", "mode": "auto"}).status_code == 422
    r = c.put("/api/updates/settings", json={"repo": "example/tunnelstead", "mode": "auto", "day": "sun", "hour": 3}).json()
    assert r["settings"] == {"repo": "example/tunnelstead", "mode": "auto", "day": "sun", "hour": 3}
    make_user(db, "op", role=Role.OPERATOR)
    assert login(app, "op").get("/api/updates").status_code == 403
    assert c.post("/api/updates/rollback").status_code == 422  # nothing to roll back


def test_auto_update_window(app, db, helper, key, feed):
    from datetime import UTC, datetime
    k, _ = key
    new = bump(__version__)
    make_bundle(feed, k, new)
    updates.save_settings(db, mode="auto", day="any", hour=3)
    db.commit()
    assert updates.scheduled(db, helper, now=datetime(2026, 1, 5, 9, tzinfo=UTC)) is None  # outside the window
    assert not any(m == "sys.update" for m, _ in helper.calls)
    assert updates.scheduled(db, helper, now=datetime(2026, 1, 5, 3, tzinfo=UTC)) == new
    assert ("sys.update", {"action": "install", "version": new}) in helper.calls
    helper.calls.clear()
    updates.scheduled(db, helper, now=datetime(2026, 1, 5, 3, tzinfo=UTC))  # tried once per version only
    assert not any(m == "sys.update" for m, _ in helper.calls)


# ---------------------------------------------------------------- root updater (logic only; real run on the VPS)

def test_updater_verifies_signature_and_version_binding(tmp_path, key):
    k, pub = key
    b = make_bundle(tmp_path, k, "9.0.0")
    assert len(U.verify(b, pathlib.Path(str(b) + ".sig"), "9.0.0", pub)) == 64
    with pytest.raises(U.UpdateError):
        U.verify(b, pathlib.Path(str(b) + ".sig"), "9.0.1", pub)  # same file claimed as another version
    data = bytearray(b.read_bytes())
    data[-3] ^= 1
    b.write_bytes(bytes(data))
    with pytest.raises(U.UpdateError):
        U.verify(b, pathlib.Path(str(b) + ".sig"), "9.0.0", pub)


@pytest.mark.parametrize("bad", ["../evil", "/etc/passwd", "other-dir/x"])
def test_updater_rejects_unsafe_paths(tmp_path, key, bad):
    k, _ = key
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as t:
        for name in ("tunnelstead-9.0.0/VERSION", bad if bad.startswith(("/", "other")) else f"tunnelstead-9.0.0/{bad}"):
            info = tarfile.TarInfo(name)
            info.size = 6
            t.addfile(info, io.BytesIO(b"9.0.0\n"))
    p = tmp_path / "b.tar.gz"
    p.write_bytes(buf.getvalue())
    with pytest.raises(U.UpdateError):
        U.safe_extract(p, tmp_path / "x", "9.0.0")


def test_updater_rejects_links_and_version_mismatch(tmp_path, key):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as t:
        link = tarfile.TarInfo("tunnelstead-9.0.0/x")
        link.type, link.linkname = tarfile.SYMTYPE, "/etc/shadow"
        t.addfile(link)
    p = tmp_path / "l.tar.gz"
    p.write_bytes(buf.getvalue())
    with pytest.raises(U.UpdateError, match="links"):
        U.safe_extract(p, tmp_path / "x", "9.0.0")
    k, _ = key
    b = make_bundle(tmp_path, k, "9.0.0", content_version="1.0.0")
    with pytest.raises(U.UpdateError, match="VERSION"):
        U.safe_extract(b, tmp_path / "y", "9.0.0")


def test_updater_refuses_downgrade(monkeypatch):
    monkeypatch.setattr(U, "installed_version", lambda: "2.0.0")
    for v in ("2.0.0", "1.9.9"):
        with pytest.raises(U.UpdateError, match="not newer"):
            U.install(v)
    assert U.vtuple("2.10.0") > U.vtuple("2.9.9")
    with pytest.raises(U.UpdateError):
        U.vtuple("2.0")


def test_helper_update_validation():
    from tests.test_helper import helper as H
    for bad in [("install", None), ("install", "1.0"), ("install", "1.0.0; reboot"), ("rollback", "1.0.0"), ("purge", None)]:
        with pytest.raises(H.Invalid):
            H.sys_update(*bad)


def test_release_tool_signature_matches_updater(tmp_path):
    spec2 = importlib.util.spec_from_file_location("release", ROOT / "tools" / "release.py")
    R = importlib.util.module_from_spec(spec2)
    spec2.loader.exec_module(R)
    assert R.message("1.2.3", "ab") == U.message("1.2.3", "ab") == b"tunnelstead-release:1.2.3:ab"
    assert json.loads(json.dumps({"ok": 1}))  # sanity


def test_refused_attempt_keeps_rollback(tmp_path, monkeypatch):
    """Regression: a refused downgrade after a good update must not hide the rollback (found on the real VPS)."""
    monkeypatch.setattr(U, "PREV", tmp_path / "prev")
    monkeypatch.setattr(U, "SAFE", tmp_path / "safe")
    monkeypatch.setattr(U, "DOWNLOADS", tmp_path / "dl")
    monkeypatch.setattr(U, "STATUS", tmp_path / "dl" / "status.json")
    (tmp_path / "prev").mkdir()
    (tmp_path / "safe").mkdir()
    (tmp_path / "safe" / "snapshot.json").write_text(json.dumps({"version": "0.1.0", "replaced_by": "0.1.1"}))
    U.status("failed", error="0.1.0 is not newer than the installed 0.1.1")
    assert json.loads((tmp_path / "dl" / "status.json").read_text())["rollback_to"] == "0.1.0"
    U.drop_snapshot()
    U.status("rolled_back", manual=True)
    assert json.loads((tmp_path / "dl" / "status.json").read_text())["rollback_to"] is None


def test_api_rollback_follows_snapshot(app, db, helper, monkeypatch, tmp_path):
    monkeypatch.setenv("TUNNELSTEAD_UPDATE_DIR", str(tmp_path))
    make_user(db, "boss")
    c = login(app, "boss")
    (tmp_path / "status.json").write_text(json.dumps({"state": "failed", "rollback_to": "0.1.0"}))
    assert c.get("/api/updates").json()["rollback_to"] == "0.1.0"
    assert c.post("/api/updates/rollback").status_code == 202
    assert ("sys.update", {"action": "rollback"}) in helper.calls
    (tmp_path / "status.json").write_text(json.dumps({"state": "running", "rollback_to": "0.1.0"}))
    assert c.post("/api/updates/rollback").status_code == 422


def test_rollback_restore_keeps_open_connections_consistent(tmp_path):
    """Regression (found on the VPS): restoring by deleting -wal/-shm and copying the file made writes from an
    already-open connection vanish. The SQLite backup API keeps every connection on the real database."""
    import sqlite3
    db, snap = tmp_path / "live.db", tmp_path / "snap.db"
    setup = sqlite3.connect(db)
    setup.execute("PRAGMA journal_mode=WAL")
    setup.execute("create table users (name text)")
    setup.executemany("insert into users values (?)", [("admin",), ("temp",)])
    setup.commit()
    setup.close()
    U._sqlite_copy(db, snap)                       # snapshot before the "update"
    held = sqlite3.connect(db)                     # e.g. a tool or test that keeps its connection open
    held.execute("PRAGMA journal_mode=WAL")
    held.execute("insert into users values ('made-after-snapshot')")
    held.commit()
    U._sqlite_copy(snap, db)                       # rollback restores the snapshot
    held.execute("delete from users where name = 'temp'")
    held.commit()
    fresh = sqlite3.connect(db)
    assert sorted(r[0] for r in fresh.execute("select name from users")) == ["admin"]


def test_snapshot_copy_is_private_and_dropped(tmp_path, monkeypatch):
    import sqlite3
    import stat
    monkeypatch.setattr(U, "SAFE", tmp_path / "safe")
    monkeypatch.setattr(U, "PREV", tmp_path / "prev")
    monkeypatch.setattr(U, "DB", tmp_path / "live.db")
    monkeypatch.setattr(U, "APP", tmp_path / "app")
    (tmp_path / "app").mkdir()
    sqlite3.connect(tmp_path / "live.db").execute("create table t (x)").connection.commit()
    monkeypatch.setattr(U, "sh", lambda *a, **k: (tmp_path / "prev").mkdir(exist_ok=True))
    U.snapshot("1.0.0", "1.0.1")
    copy = tmp_path / "safe" / "pre-update.db"
    if os.name == "posix":
        assert stat.S_IMODE(copy.stat().st_mode) == 0o600
    assert copy.exists()
    U.drop_snapshot()
    assert not copy.exists() and not (tmp_path / "safe" / "snapshot.json").exists()
