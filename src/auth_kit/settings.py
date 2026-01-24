from __future__ import annotations

from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="AUTH_", env_file=".env", extra="ignore")

    # Database
    database_url: str = Field(..., description="PostgreSQL DSN, e.g. postgresql+psycopg://user:pass@host:5432/db")

    # Cookie session
    session_cookie_name: str = "sid"
    session_ttl_days: int = 30
    cookie_secure: bool = True
    cookie_samesite: str = "lax"  # "lax" | "strict" | "none"
    cookie_domain: str | None = None

    # Local auth
    allow_local_login: bool = True

    # OIDC (optional)
    oidc_enabled: bool = False
    oidc_issuer: str | None = None
    oidc_client_id: str | None = None
    oidc_client_secret: str | None = None
    oidc_redirect_url: str | None = None  # e.g. https://nexus.example.com/api/auth/oidc/callback
    oidc_scopes: str = "openid profile email"
    oidc_claim_email: str = "email"
    oidc_claim_name: str = "name"
    oidc_claim_groups: str = "groups"  # or "roles"

    # Role mapping
    default_roles: str = "user"  # comma-separated
    owner_email: str | None = None  # optional bootstrap owner by email

    # Security
    password_bcrypt_rounds: int = 12


def get_settings() -> Settings:
    return Settings()
