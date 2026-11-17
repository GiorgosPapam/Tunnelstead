"""Update checks and downloads (unprivileged). Installing is done by the root updater, which verifies again.

Releases come from GitHub (`owner/repo`, set in the Updates page or TUNNELSTEAD_UPDATE_REPO). A release is used only if it
has `tunnelstead-X.Y.Z.tar.gz` and `tunnelstead-X.Y.Z.tar.gz.sig` assets. For offline installs and tests a local
directory with the same files can be used instead (TUNNELSTEAD_UPDATE_FEED_DIR).
"""
import base64
import hashlib
import json
import os
import re
import time
import urllib.request
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from sqlalchemy.orm import Session as DB

from . import __version__
from .models import Setting

VERSION_RE = re.compile(r"^\d{1,4}\.\d{1,4}\.\d{1,4}$")
REPO_RE = re.compile(r"^[A-Za-z0-9_.-]{1,39}/[A-Za-z0-9_.-]{1,100}$")
MAX_BUNDLE = 300 * 1024 * 1024
CHECK_EVERY = 6 * 3600


class UpdateError(ValueError):
    pass


def vtuple(v: str) -> tuple[int, ...]:
    return tuple(int(x) for x in v.split("."))


def app_dir() -> Path:
    return Path(__file__).resolve().parents[2]


def downloads() -> Path:
    from .backup import db_path
    d = Path(os.environ.get("TUNNELSTEAD_UPDATE_DIR") or Path(db_path()).parent / "updates")
    d.mkdir(mode=0o750, parents=True, exist_ok=True)
    return d


def public_key() -> Ed25519PublicKey:
    from . import testing
    if testing.enabled() and os.environ.get("TUNNELSTEAD_TEST_RELEASE_PUBKEY"):  # browser tests only (SQLite + test helper)
        return Ed25519PublicKey.from_public_bytes(base64.b64decode(os.environ["TUNNELSTEAD_TEST_RELEASE_PUBKEY"]))
    for p in (app_dir() / "release-key.pub", app_dir() / "installer" / "release-key.pub"):
        if p.exists():
            return Ed25519PublicKey.from_public_bytes(base64.b64decode(p.read_text().strip()))
    raise UpdateError("release-key.pub is missing")


def verify(bundle: Path, sig: Path, version: str) -> str:
    digest = hashlib.sha256(bundle.read_bytes()).hexdigest()
    try:
        public_key().verify(base64.b64decode(sig.read_text().strip()), f"tunnelstead-release:{version}:{digest}".encode())
    except (InvalidSignature, ValueError):
        raise UpdateError("Signature check failed: this release was not signed by the Tunnelstead release key") from None
    return digest


def settings(db: DB) -> dict:
    s = db.get(Setting, "update_settings")
    v = dict(s.value) if s else {}
    v.setdefault("repo", os.environ.get("TUNNELSTEAD_UPDATE_REPO", ""))
    v.setdefault("mode", "notify")      # off | notify | auto
    v.setdefault("day", "any")          # any | mon..sun
    v.setdefault("hour", 4)             # UTC
    return v


def save_settings(db: DB, **kw) -> dict:
    v = {**settings(db), **kw}
    s = db.get(Setting, "update_settings")
    if s:
        s.value = v
    else:
        db.add(Setting(key="update_settings", value=v))
    return v


def _get(url: str, limit: int = 2 * 1024 * 1024, accept: str = "application/vnd.github+json") -> bytes:
    if not url.startswith("https://"):
        raise UpdateError("Only https downloads are allowed")
    req = urllib.request.Request(url, headers={"Accept": accept, "User-Agent": "Tunnelstead-Updater"})  # noqa: S310
    with urllib.request.urlopen(req, timeout=30) as r:  # noqa: S310 - https only
        data = r.read(limit + 1)
    if len(data) > limit:
        raise UpdateError("Download is larger than allowed")
    return data


def _releases(repo: str) -> list[dict]:
    feed = os.environ.get("TUNNELSTEAD_UPDATE_FEED_DIR")
    out = []
    if feed:
        for p in Path(feed).glob("tunnelstead-*.tar.gz"):
            v = p.name.removeprefix("tunnelstead-").removesuffix(".tar.gz")
            notes = Path(feed, f"{v}.md")
            if VERSION_RE.match(v) and Path(str(p) + ".sig").exists():
                out.append({"version": v, "notes": notes.read_text() if notes.exists() else "", "published_at": None,
                            "url": f"file://{p}", "bundle": str(p), "sig": str(p) + ".sig", "page": None})
        return out
    if not REPO_RE.match(repo or ""):
        raise UpdateError("Set the GitHub repository (owner/name) to check for updates")
    try:
        rels = json.loads(_get(f"https://api.github.com/repos/{repo}/releases?per_page=20"))
    except UpdateError:
        raise
    except Exception as e:  # noqa: BLE001 - network problems are shown to the admin
        raise UpdateError(f"Could not reach GitHub: {e}") from None
    for r in rels:
        v = str(r.get("tag_name", "")).lstrip("v")
        if r.get("draft") or r.get("prerelease") or not VERSION_RE.match(v):
            continue
        assets = {a["name"]: a["browser_download_url"] for a in r.get("assets", [])}
        b = f"tunnelstead-{v}.tar.gz"
        if b in assets and b + ".sig" in assets:
            out.append({"version": v, "notes": (r.get("body") or "")[:20000], "published_at": r.get("published_at"),
                        "bundle": assets[b], "sig": assets[b + ".sig"], "page": r.get("html_url")})
    return out


def check(db: DB, force: bool = False) -> dict:
    cache = db.get(Setting, "update_check")
    if cache and not force and time.time() - cache.value.get("checked_at", 0) < CHECK_EVERY:
        return cache.value
    cfg = settings(db)
    rels = sorted(_releases(cfg["repo"]), key=lambda r: vtuple(r["version"]), reverse=True)
    newer = [r for r in rels if vtuple(r["version"]) > vtuple(__version__)]
    value = {"checked_at": time.time(), "current": __version__, "latest": newer[0] if newer else None,
             "newer": [{"version": r["version"], "notes": r["notes"], "published_at": r["published_at"]} for r in newer[:10]]}
    if cache:
        cache.value = value
    else:
        db.add(Setting(key="update_check", value=value))
    db.commit()
    return value


def download(db: DB, version: str) -> dict:
    """Fetch the bundle and signature for `version` and verify them (the root updater verifies again)."""
    if not VERSION_RE.match(version):
        raise UpdateError("Invalid version")
    if vtuple(version) <= vtuple(__version__):
        raise UpdateError(f"{version} is not newer than the installed {__version__}")
    rel = next((r for r in _releases(settings(db)["repo"]) if r["version"] == version), None)
    if not rel:
        raise UpdateError(f"Release {version} was not found")
    d, name = downloads(), f"tunnelstead-{version}.tar.gz"
    for src, dst in ((rel["bundle"], name), (rel["sig"], name + ".sig")):
        data = Path(src).read_bytes() if not src.startswith("https://") else _get(src, MAX_BUNDLE, "application/octet-stream")
        tmp = d / (dst + ".part")
        tmp.write_bytes(data)
        os.replace(tmp, d / dst)
    try:
        digest = verify(d / name, d / (name + ".sig"), version)
    except UpdateError:
        (d / name).unlink(missing_ok=True)
        (d / (name + ".sig")).unlink(missing_ok=True)
        raise
    return {"version": version, "sha256": digest, "size": (d / name).stat().st_size, "verified": True}


def downloaded(version: str) -> bool:
    d, name = downloads(), f"tunnelstead-{version}.tar.gz"
    if not ((d / name).exists() and (d / (name + ".sig")).exists()):
        return False
    try:
        verify(d / name, d / (name + ".sig"), version)
        return True
    except UpdateError:
        return False


def status() -> dict:
    try:
        return json.loads((downloads() / "status.json").read_text())
    except (OSError, ValueError):
        return {"state": "idle"}


def start(helper, action: str, version: str | None = None) -> dict:
    if action == "install":
        if not downloaded(version):
            raise UpdateError("Download and verify the update first")
        if vtuple(version) <= vtuple(__version__):
            raise UpdateError("Downgrades are refused; use rollback")
    st = status()
    if st.get("state") == "running" and time.time() - os.path.getmtime(downloads() / "status.json") < 1800:
        raise UpdateError("An update is already running")
    return helper.call("sys.update", action=action, **({"version": version} if action == "install" else {}))


DAYS = ["mon", "tue", "wed", "thu", "fri", "sat", "sun"]


def scheduled(db: DB, helper, now=None) -> str | None:
    """Collector hook: periodic check, 'update available' alert, and automatic install in the chosen window."""
    from datetime import UTC, datetime

    from . import audit, notify
    cfg = settings(db)
    if cfg["mode"] == "off" or not (cfg["repo"] or os.environ.get("TUNNELSTEAD_UPDATE_FEED_DIR")):
        return None
    try:
        info = check(db)
    except UpdateError:
        return None
    latest = info.get("latest")
    if not latest:
        return None
    notify.notify(db, "update_available", f"Tunnelstead {latest['version']} is available (installed: {__version__}).",
                  key=latest["version"])
    now = now or datetime.now(UTC)
    in_window = now.hour == int(cfg["hour"]) and cfg["day"] in ("any", DAYS[now.weekday()])
    if cfg["mode"] != "auto" or not in_window or cfg.get("auto_tried") == latest["version"]:
        return None
    save_settings(db, auto_tried=latest["version"])
    db.commit()
    try:
        download(db, latest["version"])
        start(helper, "install", latest["version"])
        audit.record(db, "system", "update_started", target=latest["version"], automatic=True)
    except Exception as e:  # noqa: BLE001 - alert, retry next version only
        audit.record(db, "system", "update_failed", success=False, target=latest["version"], error=str(e)[:200])
        notify.notify(db, "update_failed", f"Automatic update to {latest['version']} could not start: {e}", key=latest["version"])
    db.commit()
    return latest["version"]
