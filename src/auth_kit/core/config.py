from __future__ import annotations

from functools import lru_cache
from importlib.metadata import PackageNotFoundError, version
from typing import Any, Literal

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

SameSiteMode = Literal["lax", "strict", "none"]
EmailDeliveryMode = Literal["log", "smtp"]


def _default_version() -> str:
    try:
        return version("auth-kit")
    except PackageNotFoundError:
        return "1.0.0"


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
    csrf_cookie_name: str = "authkit_csrf"
    csrf_header_name: str = "X-CSRF-Token"
    cors_allow_origins: list[str] = Field(default_factory=list)
    upload_dir: str = "./data/uploads"
    avatar_max_mb: int = 5
    security_hsts_max_age: int = 31536000

    password_min_length: int = 12
    password_reset_ttl_minutes: int = 30
    password_reset_delivery_mode: EmailDeliveryMode = "log"
    password_reset_url_base: str | None = None
    smtp_host: str | None = None
    smtp_port: int = 587
    smtp_username: str | None = None
    smtp_password: str | None = None
    smtp_from_email: str | None = None
    smtp_from_name: str | None = None
    smtp_use_starttls: bool = True
    smtp_use_ssl: bool = False
    rate_limit_window_seconds: int = 60
    rate_limit_login: int = 5
    rate_limit_register: int = 5
    rate_limit_forgot_password: int = 5
    rate_limit_reset_password: int = 5

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

    @field_validator("cors_allow_origins", mode="before")
    @classmethod
    def parse_cors_allow_origins(cls, value: Any) -> list[str]:
        if value is None or value == "":
            return []
        if isinstance(value, str):
            return [item.strip() for item in value.split(",") if item.strip()]
        if isinstance(value, list):
            return [str(item).strip() for item in value if str(item).strip()]
        raise ValueError("cors_allow_origins must be a comma-separated string or list")

    @field_validator("password_reset_delivery_mode")
    @classmethod
    def validate_email_delivery_mode(cls, value: str) -> EmailDeliveryMode:
        normalized = value.strip().lower()
        if normalized not in {"log", "smtp"}:
            raise ValueError("password_reset_delivery_mode must be one of: log, smtp")
        return normalized  # type: ignore[return-value]

    @field_validator("session_ttl_days")
    @classmethod
    def validate_ttl(cls, value: int) -> int:
        if value < 1:
            raise ValueError("session_ttl_days must be >= 1")
        return value

    @field_validator("password_reset_ttl_minutes")
    @classmethod
    def validate_password_reset_ttl(cls, value: int) -> int:
        if value < 1:
            raise ValueError("password_reset_ttl_minutes must be >= 1")
        return value

    @field_validator("avatar_max_mb")
    @classmethod
    def validate_avatar_max_mb(cls, value: int) -> int:
        if value < 1:
            raise ValueError("avatar_max_mb must be >= 1")
        return value

    @field_validator(
        "security_hsts_max_age",
        "smtp_port",
        "rate_limit_window_seconds",
        "rate_limit_login",
        "rate_limit_register",
        "rate_limit_forgot_password",
        "rate_limit_reset_password",
    )
    @classmethod
    def validate_positive_numbers(cls, value: int) -> int:
        if value < 1:
            raise ValueError("numeric security settings must be >= 1")
        return value


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()  # type: ignore[call-arg]
