"""Request dependencies: client IP, rate limiting, session + CSRF validation, permission checks."""
import ipaddress
import time
from collections import deque
from datetime import UTC, timedelta

from fastapi import Depends, HTTPException, Request
from sqlalchemy.orm import Session as DB

from .config import get_settings
from .db import get_db
from .models import User, UserSession, utcnow
from .permissions import has
from .security import consteq, sha256

COOKIE = "tunnelstead_session"
CSRF_HEADER = "X-CSRF-Token"
SAFE = {"GET", "HEAD", "OPTIONS"}
PASSWORD_CHANGE_ALLOWED = {"/api/auth/me", "/api/auth/password", "/api/auth/logout"}


class RateLimiter:
    """Sliding window per client network (one API worker; documented limitation for multi-worker setups).

    Memory stays bounded: expired entries are dropped, and at most MAX_KEYS networks are tracked (when full, the
    stalest ones are evicted). IPv6 clients are grouped by /64, since one user controls a whole /64.
    """
    MAX_KEYS = 50_000

    def __init__(self, limit: int, window: float):
        self.limit, self.window = limit, window
        self.hits: dict[str, deque[float]] = {}

    @staticmethod
    def key(ip: str) -> str:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return ip[:64]
        if isinstance(addr, ipaddress.IPv6Address):
            if addr.ipv4_mapped:
                return str(addr.ipv4_mapped)
            return str(ipaddress.ip_network(f"{addr}/64", strict=False))
        return str(addr)

    def _sweep(self, now: float) -> None:
        for k in [k for k, q in self.hits.items() if not q or now - q[-1] > self.window]:
            del self.hits[k]
        if len(self.hits) >= self.MAX_KEYS:  # still full of active keys: evict the stalest
            for k in sorted(self.hits, key=lambda k: self.hits[k][-1])[: len(self.hits) - self.MAX_KEYS + 1]:
                del self.hits[k]

    def check(self, ip: str) -> None:
        now, key = time.monotonic(), self.key(ip)
        if key not in self.hits and len(self.hits) >= self.MAX_KEYS:
            self._sweep(now)
        q = self.hits.setdefault(key, deque())
        while q and now - q[0] > self.window:
            q.popleft()
        if len(q) >= self.limit:
            raise HTTPException(429, "Too many attempts. Wait a minute and try again.")
        q.append(now)


auth_limiter = RateLimiter(get_settings().auth_rate_per_minute, 60)


def client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def _aware(dt):
    return dt if dt is None or dt.tzinfo else dt.replace(tzinfo=UTC)


def current_session(request: Request, db: DB = Depends(get_db)) -> UserSession:
    token = request.cookies.get(COOKIE)
    s = db.query(UserSession).filter_by(token_hash=sha256(token)).first() if token else None
    now = utcnow()
    st = get_settings()
    if not s or _aware(s.expires_at) < now or now - _aware(s.last_seen_at) > timedelta(minutes=st.session_idle_minutes):
        if s:
            db.delete(s)
            db.commit()
        raise HTTPException(401, "Not signed in")
    if request.method not in SAFE:
        sent = request.headers.get(CSRF_HEADER, "")
        if not sent or not consteq(sha256(sent), s.csrf_hash):
            raise HTTPException(403, "Security token missing or invalid. Reload the page.")
    if now - _aware(s.last_seen_at) > timedelta(minutes=1):  # sliding idle timeout, cheap
        s.last_seen_at = now
        db.commit()
    return s


def current_user(request: Request, s: UserSession = Depends(current_session), db: DB = Depends(get_db)) -> User:
    if s.mfa_pending:
        raise HTTPException(401, "Two-factor verification required")
    u = db.get(User, s.user_id)
    if not u or not u.active:
        raise HTTPException(401, "Account unavailable")
    if u.must_change_password and request.url.path not in PASSWORD_CHANGE_ALLOWED:
        raise HTTPException(403, "Password change required")
    return u


def require(perm: str):
    def dep(user: User = Depends(current_user)) -> User:
        if not has(user.role, perm):
            raise HTTPException(403, "You do not have permission for this action")
        return user
    return dep
