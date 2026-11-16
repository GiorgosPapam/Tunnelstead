"""Notifications: a webhook (Slack/Discord/Teams-compatible JSON) and/or e-mail over SMTP.

Sending happens in a background thread with short timeouts, so a slow endpoint never blocks the API or collector.
Repeated alerts with the same key are suppressed for REPEAT_AFTER (a server that stays down alerts once, not every 30 s).
"""
import json
import logging
import smtplib
import socket
import ssl
import threading
import time
import urllib.request
from email.message import EmailMessage

from sqlalchemy.orm import Session as DB

from .models import Setting
from .security import decrypt, encrypt

log = logging.getLogger("vpnix.notify")
REPEAT_AFTER = 6 * 3600
EVENTS = {
    "instance_down": "A VPN server stopped running",
    "instance_recovered": "A VPN server is running again",
    "client_blocked": "A client was blocked (expired or over its data limit)",
    "cert_expiring": "A certificate expires within 30 days",
    "disk_full": "Disk usage is above 90 %",
    "login_locked": "An account was locked after failed sign-ins",
    "firewall_rolled_back": "A firewall change was not kept and was undone",
    "update_available": "A new VPNix Create version is available",
    "update_done": "VPNix Create was updated",
    "update_failed": "An update failed (the previous version keeps running)",
    "backup_ok": "A scheduled backup was created",
    "backup_failed": "A scheduled backup failed",
}
DEFAULT_EVENTS = [e for e in EVENTS if e not in ("backup_ok", "update_done")]


def get_config(db: DB) -> dict:
    s = db.get(Setting, "notifications")
    v = dict(s.value) if s else {}
    v.setdefault("webhook_url", "")
    v.setdefault("email", {})
    v.setdefault("events", DEFAULT_EVENTS)
    return v


def public_config(db: DB) -> dict:
    v = get_config(db)
    email = {k: x for k, x in v["email"].items() if k != "password_enc"}
    email["has_password"] = bool(v["email"].get("password_enc"))
    return {"webhook_url": v["webhook_url"], "email": email, "events": v["events"],
            "available_events": EVENTS}


def save_config(db: DB, webhook_url: str, email: dict, events: list[str], password: str | None) -> None:
    old = get_config(db)
    email = {k: email.get(k) for k in ("host", "port", "username", "sender", "recipients", "starttls")}
    if password:
        email["password_enc"] = encrypt(password, "smtp-password")
    elif password is None and old["email"].get("password_enc"):
        email["password_enc"] = old["email"]["password_enc"]  # unchanged
    value = {"webhook_url": webhook_url, "email": email, "events": [e for e in events if e in EVENTS]}
    s = db.get(Setting, "notifications")
    if s:
        s.value = value
    else:
        db.add(Setting(key="notifications", value=value))


def _webhook(url: str, title: str, text: str) -> None:
    body = json.dumps({"text": f"*{title}*\n{text}", "content": f"**{title}**\n{text}", "title": title,
                       "message": text, "host": socket.gethostname(), "ts": int(time.time())}).encode()
    if not url.startswith("https://"):
        raise ValueError("webhook URL must use https")
    headers = {"Content-Type": "application/json", "User-Agent": "VPNix-Create"}
    req = urllib.request.Request(url, data=body, method="POST", headers=headers)  # noqa: S310 - https checked above
    with urllib.request.urlopen(req, timeout=8) as r:  # noqa: S310 - https checked above
        r.read(1024)


def _email(cfg: dict, title: str, text: str) -> None:
    msg = EmailMessage()
    msg["Subject"], msg["From"], msg["To"] = f"[VPNix Create] {title}", cfg["sender"], ", ".join(cfg["recipients"])
    msg.set_content(f"{text}\n\nServer: {socket.gethostname()}\n")
    port = int(cfg.get("port") or 587)
    ctx = ssl.create_default_context()
    if port == 465:
        smtp = smtplib.SMTP_SSL(cfg["host"], port, timeout=10, context=ctx)
    else:
        smtp = smtplib.SMTP(cfg["host"], port, timeout=10)
        if cfg.get("starttls", True):
            smtp.starttls(context=ctx)
    with smtp:
        if cfg.get("username") and cfg.get("password_enc"):
            smtp.login(cfg["username"], decrypt(cfg["password_enc"], "smtp-password"))
        smtp.send_message(msg)


def deliver(cfg: dict, title: str, text: str) -> list[str]:
    """Send now, synchronously. Returns the list of channel errors (empty = all delivered)."""
    errors = []
    if cfg.get("webhook_url"):
        try:
            _webhook(cfg["webhook_url"], title, text)
        except Exception as e:  # noqa: BLE001 - reported to the admin, never raised
            errors.append(f"Webhook: {e}")
    if cfg.get("email", {}).get("host") and cfg["email"].get("recipients"):
        try:
            _email(cfg["email"], title, text)
        except Exception as e:  # noqa: BLE001
            errors.append(f"E-mail: {e}")
    return errors


def notify(db: DB, event: str, text: str, key: str | None = None) -> bool:
    """Queue an alert if that event is enabled and was not sent recently. Returns True when queued."""
    cfg = get_config(db)
    if event not in cfg["events"] or not (cfg["webhook_url"] or cfg["email"].get("host")):
        return False
    key = f"{event}:{key or ''}"
    st = db.get(Setting, "notify_sent")
    sent = dict(st.value) if st else {}
    now = time.time()
    if now - sent.get(key, 0) < REPEAT_AFTER:
        return False
    sent = {k: t for k, t in sent.items() if now - t < REPEAT_AFTER}
    sent[key] = now
    if st:
        st.value = sent
    else:
        db.add(Setting(key="notify_sent", value=sent))
    db.commit()
    threading.Thread(target=lambda: [log.warning("notification failed: %s", e) for e in deliver(cfg, EVENTS[event], text)],
                     daemon=True).start()
    return True


def clear(db: DB, event: str, key: str | None = None) -> None:
    """Forget a suppressed alert (e.g. the server recovered), so a later failure alerts again."""
    st = db.get(Setting, "notify_sent")
    if st and f"{event}:{key or ''}" in st.value:
        st.value = {k: t for k, t in st.value.items() if k != f"{event}:{key or ''}"}
        db.commit()
