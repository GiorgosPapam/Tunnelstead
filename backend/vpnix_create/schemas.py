from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

USERNAME = r"^[a-zA-Z0-9][a-zA-Z0-9._-]{2,63}$"


class LoginIn(BaseModel):
    username: str = Field(max_length=64)
    password: str = Field(max_length=256)


class CodeIn(BaseModel):
    code: str = Field(pattern=r"^(\d{6}|[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4})$")


class PasswordChangeIn(BaseModel):
    current_password: str = Field(max_length=256)
    new_password: str = Field(max_length=256)


class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    username: str
    email: str | None
    role: str
    active: bool
    mfa_enabled: bool
    must_change_password: bool
    created_at: datetime
    last_login_at: datetime | None


class UserCreate(BaseModel):
    username: str = Field(pattern=USERNAME)
    email: str | None = Field(None, max_length=254)
    role: str = Field("viewer", pattern=r"^(admin|operator|viewer)$")
    password: str = Field(max_length=256)


class UserUpdate(BaseModel):
    role: str | None = Field(None, pattern=r"^(admin|operator|viewer)$")
    active: bool | None = None
    email: str | None = Field(None, max_length=254)
