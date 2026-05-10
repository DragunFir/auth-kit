from __future__ import annotations

from collections.abc import Callable

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from auth_kit.app import create_app
from auth_kit.core.config import Settings
from auth_kit.db import Base


@pytest.fixture
def settings_factory(tmp_path) -> Callable[..., Settings]:
    counter = 0

    def build(**overrides: object) -> Settings:
        nonlocal counter
        counter += 1
        base_values: dict[str, object] = {
            "database_url": f"sqlite+pysqlite:///{tmp_path / f'auth-kit-{counter}.db'}",
            "session_cookie_secure": False,
            "bootstrap_owner_enabled": True,
            "bootstrap_owner_email": "owner@example.com",
            "bootstrap_owner_username": "owner",
            "bootstrap_owner_password": "PrimaryPass!123",
            "bootstrap_owner_display_name": "Bootstrap Owner",
            "upload_dir": str(tmp_path / "uploads"),
            "avatar_max_mb": 1,
        }
        base_values.update(overrides)
        return Settings(**base_values)

    return build


@pytest.fixture
def settings(settings_factory: Callable[..., Settings]) -> Settings:
    return settings_factory()


@pytest.fixture
def engine(settings: Settings):
    engine = create_engine(settings.database_url, connect_args={"check_same_thread": False})
    Base.metadata.create_all(engine)
    yield engine
    engine.dispose()


@pytest.fixture
def app(settings: Settings, engine):
    return create_app(settings)


@pytest.fixture
def client(app):
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture
def db_session(settings: Settings) -> Session:
    engine = create_engine(settings.database_url, connect_args={"check_same_thread": False})
    session = Session(engine)
    try:
        yield session
    finally:
        session.close()
        engine.dispose()
