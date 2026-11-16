"""Runtime settings, read from the environment (VPNIX_*) or the root-owned env file. No secrets in code."""
from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="VPNIX_", extra="ignore",
                                      env_file=(Path(__file__).resolve().parents[1] / ".env", ".env"))

    database_url: str = "sqlite:////var/lib/vpnix-create/vpnix.db"
    secret_key: str  # 32 bytes, base64url; AES-256-GCM key for secrets at rest (required)
    cookie_secure: bool = True
    session_ttl_minutes: int = 12 * 60
    session_idle_minutes: int = 60
    login_max_failures: int = 5
    login_lockout_seconds: int = 900
    helper_socket: str = "/run/vpnix-create/helper.sock"
    background_jobs: bool = True


@lru_cache
def get_settings() -> Settings:
    return Settings()  # type: ignore[call-arg]
