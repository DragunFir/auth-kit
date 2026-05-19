from __future__ import annotations

from collections.abc import Callable

from fastapi.testclient import TestClient
from sqlalchemy import create_engine

from auth_kit.app import create_app
from auth_kit.core.config import Settings
from auth_kit.db import Base


def _api_request(client: TestClient, method: str, path: str, settings: Settings, **kwargs):
    headers = dict(kwargs.pop("headers", {}))
    if method.upper() not in {"GET", "HEAD", "OPTIONS"}:
        csrf = client.get("/api/auth/csrf")
        assert csrf.status_code == 200
        headers.setdefault(settings.csrf_header_name, csrf.json()["csrf_token"])
    return client.request(method, path, headers=headers, **kwargs)


def test_setup_status_and_initial_owner_creation(settings_factory: Callable[..., Settings]) -> None:
    settings = settings_factory(
        bootstrap_owner_enabled=False,
        bootstrap_owner_email=None,
        bootstrap_owner_username=None,
        bootstrap_owner_password=None,
        bootstrap_owner_display_name=None,
    )
    engine = create_engine(settings.database_url, connect_args={"check_same_thread": False})
    Base.metadata.create_all(engine)
    app = create_app(settings)

    with TestClient(app) as client:
        status_before = client.get("/api/setup/status")
        assert status_before.status_code == 200
        assert status_before.json() == {"needs_setup": True, "has_owner": False}

        created = _api_request(
            client,
            "POST",
            "/api/setup/owner",
            settings,
            json={
                "email": "first-owner@example.com",
                "username": "firstowner",
                "display_name": "First Owner",
                "password": "StrongPassword!123",
            },
        )
        assert created.status_code == 201
        assert created.json()["roles"] == ["user", "admin", "owner"]
        assert "authkit_sid" in client.cookies

        me = client.get("/api/auth/me")
        assert me.status_code == 200
        assert me.json()["username"] == "firstowner"
        assert "owner" in me.json()["roles"]

        status_after = client.get("/api/setup/status")
        assert status_after.status_code == 200
        assert status_after.json() == {"needs_setup": False, "has_owner": True}
    engine.dispose()


def test_setup_owner_creation_is_blocked_after_owner_exists(settings_factory: Callable[..., Settings]) -> None:
    settings = settings_factory(
        bootstrap_owner_enabled=False,
        bootstrap_owner_email=None,
        bootstrap_owner_username=None,
        bootstrap_owner_password=None,
        bootstrap_owner_display_name=None,
    )
    engine = create_engine(settings.database_url, connect_args={"check_same_thread": False})
    Base.metadata.create_all(engine)
    app = create_app(settings)

    with TestClient(app) as client:
        first = _api_request(
            client,
            "POST",
            "/api/setup/owner",
            settings,
            json={
                "email": "first-owner@example.com",
                "username": "firstowner",
                "display_name": "First Owner",
                "password": "StrongPassword!123",
            },
        )
        assert first.status_code == 201

        second = _api_request(
            client,
            "POST",
            "/api/setup/owner",
            settings,
            json={
                "email": "second-owner@example.com",
                "username": "secondowner",
                "display_name": "Second Owner",
                "password": "StrongPassword!123",
            },
        )
        assert second.status_code == 409
        assert second.json()["error_code"] == "setup_already_completed"
    engine.dispose()
