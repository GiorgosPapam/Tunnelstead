"""Updates page API: check GitHub, download + verify, install, roll back, schedule."""
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session as DB

from .. import __version__, audit, updates
from ..db import get_db
from ..deps import client_ip, require
from ..helper_client import HelperError, get_helper
from ..models import Setting, User

router = APIRouter(prefix="/api/updates", tags=["updates"])
admin = require("system.manage")


class SettingsIn(BaseModel):
    repo: str = Field("", max_length=140, pattern=r"^([A-Za-z0-9_.-]{1,39}/[A-Za-z0-9_.-]{1,100})?$")
    mode: str = Field("notify", pattern="^(off|notify|auto)$")
    day: str = Field("any", pattern="^(any|mon|tue|wed|thu|fri|sat|sun)$")
    hour: int = Field(4, ge=0, le=23)


def _err(fn):
    try:
        return fn()
    except updates.UpdateError as e:
        raise HTTPException(422, str(e)) from None
    except HelperError as e:
        raise HTTPException(502, f"Could not start the updater: {e}") from None


@router.get("")
def overview(_: User = Depends(admin), db: DB = Depends(get_db)):
    cfg = updates.settings(db)
    cache = db.get(Setting, "update_check")
    st = updates.status()
    return {"current": __version__, "settings": {k: cfg[k] for k in ("repo", "mode", "day", "hour")},
            "check": cache.value if cache else None, "status": st,
            "rollback_to": st.get("rollback_to") if st.get("state") != "running" else None,
            "downloaded": [v["version"] for v in (cache.value.get("newer", []) if cache else []) if updates.downloaded(v["version"])]}


@router.put("/settings")
def put_settings(body: SettingsIn, request: Request, user: User = Depends(admin), db: DB = Depends(get_db)):
    updates.save_settings(db, **body.model_dump())
    audit.record(db, "system", "update_settings", user=user, ip=client_ip(request), **body.model_dump())
    db.commit()
    return overview(user, db)


@router.post("/check")
def check_now(user: User = Depends(admin), db: DB = Depends(get_db)):
    _err(lambda: updates.check(db, force=True))
    return overview(user, db)


@router.post("/{version}/download")
def download(version: str, request: Request, user: User = Depends(admin), db: DB = Depends(get_db)):
    r = _err(lambda: updates.download(db, version))
    audit.record(db, "system", "update_downloaded", user=user, ip=client_ip(request), target=version, sha256=r["sha256"])
    db.commit()
    return r


@router.post("/{version}/install", status_code=202)
def install(version: str, request: Request, user: User = Depends(admin), db: DB = Depends(get_db), helper=Depends(get_helper)):
    _err(lambda: updates.start(helper, "install", version))
    audit.record(db, "system", "update_started", user=user, ip=client_ip(request), target=version, previous=__version__)
    db.commit()
    return {"started": True, "message": "The update is running. The dashboard restarts and reconnects by itself."}


@router.post("/rollback", status_code=202)
def rollback(request: Request, user: User = Depends(admin), db: DB = Depends(get_db), helper=Depends(get_helper)):
    st = updates.status()
    if st.get("state") == "running" or not st.get("rollback_to"):
        raise HTTPException(422, "There is no update to roll back")
    _err(lambda: updates.start(helper, "rollback"))
    audit.record(db, "system", "update_rollback", user=user, ip=client_ip(request), target=st.get("rollback_to"), from_version=__version__)
    db.commit()
    return {"started": True}
