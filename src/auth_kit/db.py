from __future__ import annotations

from sqlalchemy import create_engine
from sqlalchemy.engine import Engine
from sqlalchemy import text

from .settings import Settings


def create_db_engine(settings: Settings) -> Engine:
    engine = create_engine(settings.database_url, pool_pre_ping=True, future=True)
    return engine


def ensure_schema(engine: Engine) -> None:
    """
    Minimal schema, Postgres-oriented.
    If you already have your own schema, you can swap this out.
    """
    ddl = """
    CREATE EXTENSION IF NOT EXISTS citext;

    CREATE TABLE IF NOT EXISTS auth_user (
      id            BIGSERIAL PRIMARY KEY,
      email         CITEXT UNIQUE NOT NULL,
      password_hash TEXT,
      display_name  TEXT,
      roles         TEXT[] NOT NULL DEFAULT ARRAY['user']::TEXT[],
      is_active     BOOLEAN NOT NULL DEFAULT TRUE,
      created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
      updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
    );

    CREATE TABLE IF NOT EXISTS user_session (
      id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      user_id    BIGINT NOT NULL REFERENCES auth_user(id) ON DELETE CASCADE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      expires_at TIMESTAMPTZ NOT NULL
    );

    CREATE INDEX IF NOT EXISTS idx_user_session_user_id ON user_session(user_id);
    CREATE INDEX IF NOT EXISTS idx_user_session_expires_at ON user_session(expires_at);
    """
    with engine.begin() as conn:
        conn.execute(text(ddl))
