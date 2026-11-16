"""Sign-in, two-factor, password and session management."""
from datetime import timedelta

import pyotp
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from sqlalchemy import delete, select
from sqlalchemy.orm import Session as DB

from .. import audit
from ..config import get_settings
from ..db import get_db
from ..deps import COOKIE, _aware, auth_limiter, client_ip, current_session, current_user
from ..models import User, UserSession, utcnow
from ..schemas import CodeIn, LoginIn, PasswordChangeIn, UserOut
from ..security import (
    decrypt,
    encrypt,
    hash_password,
    new_token,
    new_totp_secret,
    password_problem,
    recovery_codes,
    sha256,
    verify_password,
    verify_totp,
)

router = APIRouter(prefix="/api/auth", tags=["auth"])
GENERIC = "Incorrect username or password"


def _locked(u: User | None) -> bool:
    return bool(u and u.locked_until and _aware(u.locked_until) > utcnow())


def _fail(db: DB, u: User) -> None:
    """One counter for password, 2FA and password-change failures; reaching the limit locks the account."""
    st = get_settings()
    u.failed_logins += 1
    if u.failed_logins >= st.login_max_failures:
        u.locked_until = utcnow() + timedelta(seconds=st.login_lockout_seconds)
        u.failed_logins = 0
        db.execute(delete(UserSession).where(UserSession.user_id == u.id, UserSession.mfa_pending.is_(True)))


def _issue(db: DB, resp: Response, request: Request, u: User, mfa_pending: bool) -> str:
    st = get_settings()
    token, csrf = new_token(), new_token()
    db.add(UserSession(token_hash=sha256(token), user_id=u.id, csrf_hash=sha256(csrf), mfa_pending=mfa_pending,
                       expires_at=utcnow() + timedelta(minutes=st.session_ttl_minutes), ip=client_ip(request),
                       user_agent=(request.headers.get("user-agent") or "")[:200]))
    resp.set_cookie(COOKIE, token, httponly=True, secure=st.cookie_secure, samesite="strict", path="/",
                    max_age=st.session_ttl_minutes * 60)
    return csrf


@router.post("/login")
def login(body: LoginIn, request: Request, response: Response, db: DB = Depends(get_db)):
    ip = client_ip(request)
    auth_limiter.check(ip)
    u = db.scalar(select(User).where(User.username == body.username.strip().lower()))
    ok = verify_password(body.password, u.password_hash if u else None)  # always full work
    if not ok or not u.active or _locked(u):
        if u:
            if not _locked(u):
                _fail(db, u)
            audit.record(db, "auth", "login", user=u, ip=ip, success=False, locked=_locked(u))
            db.commit()
        raise HTTPException(401, GENERIC)  # identical for unknown, disabled, locked and wrong password
    if not u.mfa_enabled:
        u.failed_logins = 0
        u.last_login_at, u.last_login_ip = utcnow(), ip
    csrf = _issue(db, response, request, u, mfa_pending=u.mfa_enabled)
    audit.record(db, "auth", "login" if not u.mfa_enabled else "login.password_ok", user=u, ip=ip)
    db.commit()
    return {"csrf_token": csrf, "mfa_required": u.mfa_enabled, "must_change_password": u.must_change_password}


@router.post("/mfa/verify")
def mfa_verify(body: CodeIn, request: Request, response: Response, s: UserSession = Depends(current_session),
               db: DB = Depends(get_db)):
    ip = client_ip(request)
    auth_limiter.check(ip)
    u = db.get(User, s.user_id)
    if not s.mfa_pending or not u.mfa_secret_enc:
        raise HTTPException(400, "No two-factor check is pending")
    if _locked(u):
        raise HTTPException(401, "Invalid code")
    if "-" in body.code:
        h = sha256(body.code)
        ok = h in (u.recovery_hashes or [])
        if ok:
            u.recovery_hashes = [x for x in u.recovery_hashes if x != h]
    else:
        ok = verify_totp(decrypt(u.mfa_secret_enc, f"mfa:{u.id}"), body.code)
    if not ok:
        _fail(db, u)
        audit.record(db, "auth", "mfa", user=u, ip=ip, success=False)
        db.commit()
        raise HTTPException(401, "Invalid code")
    u.failed_logins = 0
    u.last_login_at, u.last_login_ip = utcnow(), ip
    db.delete(s)  # rotate the session on privilege change
    csrf = _issue(db, response, request, u, mfa_pending=False)
    audit.record(db, "auth", "login", user=u, ip=ip, mfa=True, recovery_code="-" in body.code)
    db.commit()
    return {"csrf_token": csrf}


@router.post("/logout")
def logout(response: Response, request: Request, s: UserSession = Depends(current_session), db: DB = Depends(get_db)):
    u = db.get(User, s.user_id)
    db.delete(s)
    audit.record(db, "auth", "logout", user=u, ip=client_ip(request))
    db.commit()
    response.delete_cookie(COOKIE, path="/")
    return {"ok": True}


@router.get("/me", response_model=UserOut)
def me(u: User = Depends(current_user)):
    return u


@router.post("/password")
def change_password(body: PasswordChangeIn, request: Request, response: Response, u: User = Depends(current_user),
                    db: DB = Depends(get_db)):
    ip = client_ip(request)
    auth_limiter.check(ip)
    if not verify_password(body.current_password, u.password_hash):
        _fail(db, u)
        audit.record(db, "auth", "password_change", user=u, ip=ip, success=False)
        db.commit()
        raise HTTPException(400, "Current password is incorrect")
    if body.new_password == body.current_password:
        raise HTTPException(422, "Choose a password different from the current one")
    if problem := password_problem(body.new_password, u.username):
        raise HTTPException(422, problem)
    u.password_hash = hash_password(body.new_password)
    u.must_change_password = False
    db.execute(delete(UserSession).where(UserSession.user_id == u.id))  # sign out everywhere
    csrf = _issue(db, response, request, u, mfa_pending=False)
    audit.record(db, "auth", "password_change", user=u, ip=ip)
    db.commit()
    return {"csrf_token": csrf}


@router.get("/sessions")
def my_sessions(s: UserSession = Depends(current_session), u: User = Depends(current_user), db: DB = Depends(get_db)):
    rows = db.scalars(select(UserSession).where(UserSession.user_id == u.id).order_by(UserSession.created_at.desc()))
    return [{"id": r.id, "created_at": r.created_at, "last_seen_at": r.last_seen_at, "ip": r.ip,
             "user_agent": r.user_agent, "current": r.id == s.id} for r in rows]


@router.delete("/sessions/{sid}", status_code=204)
def revoke_session(sid: int, request: Request, u: User = Depends(current_user), db: DB = Depends(get_db)):
    r = db.scalar(select(UserSession).where(UserSession.id == sid, UserSession.user_id == u.id))
    if not r:
        raise HTTPException(404, "Session not found")
    db.delete(r)
    audit.record(db, "auth", "session_revoke", user=u, ip=client_ip(request), target=sid)
    db.commit()


@router.post("/mfa/setup")
def mfa_setup(u: User = Depends(current_user), db: DB = Depends(get_db)):
    if u.mfa_enabled:
        raise HTTPException(409, "Two-factor authentication is already on")
    secret = new_totp_secret()
    u.mfa_secret_enc = encrypt(secret, f"mfa:{u.id}")
    db.commit()
    return {"secret": secret, "otpauth_uri": pyotp.TOTP(secret).provisioning_uri(name=u.username,
                                                                                 issuer_name="VPNix Create")}


@router.post("/mfa/enable")
def mfa_enable(body: CodeIn, request: Request, u: User = Depends(current_user), db: DB = Depends(get_db)):
    if not u.mfa_secret_enc or not verify_totp(decrypt(u.mfa_secret_enc, f"mfa:{u.id}"), body.code):
        raise HTTPException(400, "That code is not valid. Check your device clock and try again.")
    codes = recovery_codes()
    u.mfa_enabled, u.recovery_hashes = True, [sha256(c) for c in codes]
    audit.record(db, "auth", "mfa_enable", user=u, ip=client_ip(request))
    db.commit()
    return {"recovery_codes": codes}


@router.post("/mfa/disable")
def mfa_disable(body: PasswordChangeIn, request: Request, u: User = Depends(current_user), db: DB = Depends(get_db)):
    """Requires the account password (sent as current_password; new_password is ignored)."""
    if not verify_password(body.current_password, u.password_hash):
        _fail(db, u)
        db.commit()
        raise HTTPException(400, "Password is incorrect")
    u.mfa_enabled, u.mfa_secret_enc, u.recovery_hashes = False, None, []
    audit.record(db, "auth", "mfa_disable", user=u, ip=client_ip(request))
    db.commit()
    return {"ok": True}


@router.post("/mfa/recovery-codes")
def regenerate_codes(body: CodeIn, request: Request, u: User = Depends(current_user), db: DB = Depends(get_db)):
    if not u.mfa_enabled or not verify_totp(decrypt(u.mfa_secret_enc, f"mfa:{u.id}"), body.code):
        raise HTTPException(400, "Enter a current code from your authenticator app")
    codes = recovery_codes()
    u.recovery_hashes = [sha256(c) for c in codes]
    audit.record(db, "auth", "recovery_codes_regenerate", user=u, ip=client_ip(request))
    db.commit()
    return {"recovery_codes": codes}
