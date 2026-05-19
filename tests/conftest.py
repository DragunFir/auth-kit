from __future__ import annotations

from collections.abc import Callable

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from auth_kit.app import create_app
from auth_kit.core.config import Settings
from auth_kit.db import Base

BOOTSTRAP_OWNER_PASSWORD = "HarborKey!2026Z"


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
            "bootstrap_owner_password": BOOTSTRAP_OWNER_PASSWORD,
            "bootstrap_owner_display_name": "Bootstrap Owner",
            "upload_dir": str(tmp_path / "uploads"),
            "avatar_max_mb": 1,
            "password_reset_delivery_mode": "log",
            "password_reset_url_base": "http://127.0.0.1:5173/reset-password",
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
def api_request(settings: Settings):
    def request(client: TestClient, method: str, path: str, **kwargs):
        headers = dict(kwargs.pop("headers", {}))
        if method.upper() not in {"GET", "HEAD", "OPTIONS"}:
            csrf = client.get("/api/auth/csrf")
            assert csrf.status_code == 200
            headers.setdefault(settings.csrf_header_name, csrf.json()["csrf_token"])
        return client.request(method, path, headers=headers, **kwargs)

    return request


@pytest.fixture
def db_session(settings: Settings) -> Session:
    engine = create_engine(settings.database_url, connect_args={"check_same_thread": False})
    session = Session(engine)
    try:
        yield session
    finally:
        session.close()
        engine.dispose()
