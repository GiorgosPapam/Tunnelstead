import base64
import os

os.environ.setdefault("VPNIX_SECRET_KEY", base64.urlsafe_b64encode(os.urandom(32)).decode())
os.environ.setdefault("VPNIX_COOKIE_SECURE", "false")
os.environ.setdefault("VPNIX_BACKGROUND_JOBS", "false")

import pytest
from fastapi.testclient import TestClient
from vpnix_create import db as dbmod
from vpnix_create.cli import migrate
from vpnix_create.config import get_settings
from vpnix_create.deps import auth_limiter
from vpnix_create.main import create_app
from vpnix_create.models import Role, User
from vpnix_create.security import hash_password

PW = "correct-horse-battery-9"


@pytest.fixture
def app(tmp_path):
    url = f"sqlite:///{tmp_path}/t.db"
    get_settings().database_url = url  # so code that opens its own engine (CLI) uses the test DB
    migrate(dbmod.init_engine(url))  # real migrations, not create_all
    auth_limiter.hits.clear()
    return create_app()


@pytest.fixture
def db(app):
    s = dbmod._Session()
    yield s
    s.close()


def make_user(db, name, role=Role.ADMIN, must_change=False):
    u = User(username=name, role=role, password_hash=hash_password(PW), must_change_password=must_change)
    db.add(u)
    db.commit()
    return u


def login(app, name, pw=PW):
    c = TestClient(app)
    r = c.post("/api/auth/login", json={"username": name, "password": pw})
    assert r.status_code == 200, r.text
    c.headers["X-CSRF-Token"] = r.json()["csrf_token"]
    return c
