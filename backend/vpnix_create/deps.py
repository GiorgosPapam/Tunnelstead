"""Request dependencies: client IP, rate limiting, session + CSRF validation, permission checks."""
import time
from collections import defaultdict, deque
from datetime import UTC, timedelta

from fastapi import Depends, HTTPException, Request
from sqlalchemy.orm import Session as DB

from .config import get_settings
from .db import get_db
from .models import User, UserSession, utcnow
from .permissions import has
from .security import consteq, sha256

COOKIE = "vpnix_session"
CSRF_HEADER = "X-CSRF-Token"
SAFE = {"GET", "HEAD", "OPTIONS"}
PASSWORD_CHANGE_ALLOWED = {"/api/auth/me", "/api/auth/password", "/api/auth/logout"}


class RateLimiter:
    """Sliding window per key (one API worker; documented limitation for multi-worker setups)."""
    def __init__(self, limit: int, window: float):
        self.limit, self.window, self.hits = limit, window, defaultdict(deque)

    def check(self, key: str) -> None:
        now, q = time.monotonic(), self.hits[key]
        while q and now - q[0] > self.window:
            q.popleft()
        if len(q) >= self.limit:
            raise HTTPException(429, "Too many attempts. Wait a minute and try again.")
        q.append(now)


auth_limiter = RateLimiter(10, 60)


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
