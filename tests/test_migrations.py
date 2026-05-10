from __future__ import annotations

from alembic.config import Config
from sqlalchemy import create_engine, inspect

from alembic import command


def test_alembic_upgrade_creates_v2_schema(tmp_path) -> None:
    database_path = tmp_path / "migrated.db"
    database_url = f"sqlite+pysqlite:///{database_path}"

    config = Config("alembic.ini")
    config.set_main_option("sqlalchemy.url", database_url)

    command.upgrade(config, "head")

    engine = create_engine(database_url)
    inspector = inspect(engine)
    tables = set(inspector.get_table_names())
    assert {
        "auth_user",
        "auth_session",
        "auth_audit_log",
        "auth_user_profile",
        "auth_user_address",
        "auth_user_contact",
        "auth_user_preferences",
        "auth_user_security",
    } <= tables

    profile_columns = {column["name"] for column in inspector.get_columns("auth_user_profile")}
    assert {"user_id", "avatar_url", "avatar_storage_key", "created_at", "updated_at"} <= profile_columns

    session_columns = {column["name"] for column in inspector.get_columns("auth_session")}
    assert "updated_at" in session_columns
    engine.dispose()
