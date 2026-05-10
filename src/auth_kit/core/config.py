from __future__ import annotations

from functools import lru_cache
from importlib.metadata import PackageNotFoundError, version
from typing import Literal

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

SameSiteMode = Literal["lax", "strict", "none"]


def _default_version() -> str:
    try:
        return version("auth-kit")
    except PackageNotFoundError:
        return "2.0.0"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_prefix="AUTHKIT_",
        extra="ignore",
    )

    app_name: str = "auth-kit"
    app_version: str = Field(default_factory=_default_version)

    database_url: str = Field(
        ...,
        description="Database DSN, e.g. postgresql+psycopg://user:pass@host:5432/db",
    )

    session_cookie_name: str = "authkit_sid"
    session_cookie_secure: bool = False
    session_cookie_samesite: SameSiteMode = "lax"
    session_cookie_path: str = "/"
    session_cookie_domain: str | None = None
    session_ttl_days: int = 30
    upload_dir: str = "./data/uploads"
    avatar_max_mb: int = 5

    password_min_length: int = 12

    bootstrap_owner_enabled: bool = False
    bootstrap_owner_email: str | None = None
    bootstrap_owner_username: str | None = None
    bootstrap_owner_password: str | None = None
    bootstrap_owner_display_name: str | None = None

    @field_validator("session_cookie_samesite")
    @classmethod
    def validate_samesite(cls, value: str) -> SameSiteMode:
        normalized = value.strip().lower()
        if normalized not in {"lax", "strict", "none"}:
            raise ValueError("session_cookie_samesite must be one of: lax, strict, none")
        return normalized  # type: ignore[return-value]

    @field_validator("session_ttl_days")
    @classmethod
    def validate_ttl(cls, value: int) -> int:
        if value < 1:
            raise ValueError("session_ttl_days must be >= 1")
        return value

    @field_validator("avatar_max_mb")
    @classmethod
    def validate_avatar_max_mb(cls, value: int) -> int:
        if value < 1:
            raise ValueError("avatar_max_mb must be >= 1")
        return value


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()  # type: ignore[call-arg]
