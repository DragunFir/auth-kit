from __future__ import annotations

from functools import lru_cache
from importlib.metadata import PackageNotFoundError, version
from typing import Any, Literal

from pydantic import AliasChoices, Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

SameSiteMode = Literal["lax", "strict", "none"]
MailMode = Literal["dev", "log", "smtp"]


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
    mail_mode: MailMode = Field(
        default="dev",
        validation_alias=AliasChoices(
            "AUTHKIT_MAIL_MODE",
            "AUTHKIT_PASSWORD_RESET_DELIVERY_MODE",
            "mail_mode",
            "password_reset_delivery_mode",
        ),
    )
    password_reset_url_base: str | None = None
    dev_mail_outbox_enabled: bool = True
    dev_mail_outbox_path: str = "./data/dev-mail/outbox.jsonl"
    smtp_host: str | None = None
    smtp_port: int | None = None
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

    @field_validator(
        "session_cookie_domain",
        "password_reset_url_base",
        "smtp_host",
        "smtp_username",
        "smtp_password",
        "smtp_from_email",
        "smtp_from_name",
        mode="before",
    )
    @classmethod
    def normalize_optional_strings(cls, value: Any) -> Any:
        if value is None:
            return None
        if isinstance(value, str):
            normalized = value.strip()
            return normalized or None
        return value

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

    @field_validator("mail_mode")
    @classmethod
    def validate_mail_mode(cls, value: str) -> MailMode:
        normalized = value.strip().lower()
        if normalized not in {"dev", "log", "smtp"}:
            raise ValueError("mail_mode must be one of: dev, log, smtp")
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

    @field_validator("smtp_port")
    @classmethod
    def validate_smtp_port(cls, value: int | None) -> int | None:
        if value is not None and value < 1:
            raise ValueError("smtp_port must be >= 1")
        return value

    @field_validator(
        "security_hsts_max_age",
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

    @model_validator(mode="after")
    def validate_smtp_settings_for_mode(self) -> Settings:
        if self.session_cookie_samesite == "none" and not self.session_cookie_secure:
            raise ValueError("AUTHKIT_SESSION_COOKIE_SAMESITE=none requires AUTHKIT_SESSION_COOKIE_SECURE=true")

        if self.mail_mode != "smtp":
            return self

        missing: list[str] = []
        if not self.smtp_host:
            missing.append("AUTHKIT_SMTP_HOST")
        if self.smtp_port is None:
            missing.append("AUTHKIT_SMTP_PORT")
        if not self.smtp_username:
            missing.append("AUTHKIT_SMTP_USERNAME")
        if not self.smtp_password:
            missing.append("AUTHKIT_SMTP_PASSWORD")
        if not self.smtp_from_email:
            missing.append("AUTHKIT_SMTP_FROM_EMAIL")

        if missing:
            joined = ", ".join(missing)
            raise ValueError(f"AUTHKIT_MAIL_MODE=smtp requires the following settings: {joined}")

        return self


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()  # type: ignore[call-arg]
