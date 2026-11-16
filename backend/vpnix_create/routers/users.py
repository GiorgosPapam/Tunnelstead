"""User administration (admins only). Every change is audited."""
from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session as DB

from .. import audit
from ..db import get_db
from ..deps import client_ip, require
from ..models import Role, User, UserSession
from ..schemas import UserCreate, UserOut, UserUpdate
from ..security import generate_password, hash_password, password_problem

router = APIRouter(prefix="/api/users", tags=["users"])
admin_only = require("users.manage")


def _get(db: DB, uid: int) -> User:
    u = db.get(User, uid)
    if not u:
        raise HTTPException(404, "User not found")
    return u


def _admins_left(db: DB, excluding: int) -> int:
    return db.scalar(select(func.count()).select_from(User).where(User.role == Role.ADMIN, User.active.is_(True),
                                                                  User.id != excluding))


@router.get("", response_model=list[UserOut])
def list_users(_: User = Depends(admin_only), db: DB = Depends(get_db)):
    return list(db.scalars(select(User).order_by(User.username)))


@router.post("", response_model=UserOut, status_code=201)
def create_user(body: UserCreate, request: Request, admin: User = Depends(admin_only), db: DB = Depends(get_db)):
    name = body.username.lower()
    if db.scalar(select(User).where(User.username == name)):
        raise HTTPException(409, "That username is taken")
    if problem := password_problem(body.password, name):
        raise HTTPException(422, problem)
    u = User(username=name, email=body.email, role=Role(body.role), password_hash=hash_password(body.password),
             must_change_password=True)
    db.add(u)
    db.flush()
    audit.record(db, "admin", "user_create", user=admin, ip=client_ip(request), target=name, role=body.role)
    db.commit()
    return u


@router.patch("/{uid}", response_model=UserOut)
def update_user(uid: int, body: UserUpdate, request: Request, admin: User = Depends(admin_only),
                db: DB = Depends(get_db)):
    u = _get(db, uid)
    demoting = (body.role and body.role != "admin") or body.active is False
    if u.role == Role.ADMIN and demoting and _admins_left(db, u.id) == 0:
        raise HTTPException(409, "At least one active administrator must remain")
    if body.role:
        u.role = Role(body.role)
    if body.active is not None:
        u.active = body.active
        if not body.active:
            db.execute(delete(UserSession).where(UserSession.user_id == u.id))
    if body.email is not None:
        u.email = body.email or None
    audit.record(db, "admin", "user_update", user=admin, ip=client_ip(request), target=u.username,
                 **body.model_dump(exclude_none=True))
    db.commit()
    return u


@router.post("/{uid}/reset-password")
def reset_password(uid: int, request: Request, admin: User = Depends(admin_only), db: DB = Depends(get_db)):
    u = _get(db, uid)
    temp = generate_password()
    u.password_hash, u.must_change_password = hash_password(temp), True
    u.failed_logins, u.locked_until = 0, None
    db.execute(delete(UserSession).where(UserSession.user_id == u.id))
    audit.record(db, "admin", "user_password_reset", user=admin, ip=client_ip(request), target=u.username)
    db.commit()
    return {"temporary_password": temp}  # shown once to the admin; must be changed at next sign-in


@router.delete("/{uid}", status_code=204)
def delete_user(uid: int, request: Request, admin: User = Depends(admin_only), db: DB = Depends(get_db)):
    u = _get(db, uid)
    if u.id == admin.id:
        raise HTTPException(409, "You cannot delete your own account")
    if u.role == Role.ADMIN and _admins_left(db, u.id) == 0:
        raise HTTPException(409, "At least one active administrator must remain")
    audit.record(db, "admin", "user_delete", user=admin, ip=client_ip(request), target=u.username)
    db.delete(u)
    db.commit()
