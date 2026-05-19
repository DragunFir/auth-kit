from __future__ import annotations

import json
import logging
import re
from urllib.parse import parse_qs, urlsplit

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine

from auth_kit.app import create_app
from auth_kit.core.config import Settings
from auth_kit.db import Base
from auth_kit.models import AuthAuditLog, AuthPasswordResetToken, AuthUser

OWNER_PASSWORD = "HarborKey!2026Z"


def _register_payload(**overrides: str) -> dict[str, str]:
    payload = {
        "email": "alice@example.com",
        "username": "alice",
        "display_name": "Alice",
        "password": "StrongPassword!123",
    }
    payload.update(overrides)
    return payload


def _custom_api_request(client: TestClient, settings: Settings, method: str, path: str, **kwargs):
    headers = dict(kwargs.pop("headers", {}))
    if method.upper() not in {"GET", "HEAD", "OPTIONS"}:
        csrf = client.get("/api/auth/csrf")
        assert csrf.status_code == 200
        headers.setdefault(settings.csrf_header_name, csrf.json()["csrf_token"])
    return client.request(method, path, headers=headers, **kwargs)


def test_bootstrap_owner_created_on_startup(client, db_session) -> None:
    owner = db_session.query(AuthUser).filter(AuthUser.username == "owner").one()
    assert "owner" in owner.roles
    assert owner.is_active is True
    assert owner.is_verified is True
    assert owner.profile is not None
    assert owner.contact is not None
    assert owner.preferences is not None
    assert owner.security is not None

    audit = db_session.query(AuthAuditLog).filter(AuthAuditLog.event_type == "system.bootstrap_owner_created").one()
    assert audit.target_user_id == owner.id


def test_csrf_required_for_mutating_requests(client: TestClient) -> None:
    response = client.post("/api/auth/register", json=_register_payload())
    assert response.status_code == 403
    assert response.json()["error_code"] == "csrf_invalid"


def test_register_profile_preferences_contact_security_and_me(client: TestClient, api_request) -> None:
    assert api_request(client, "PATCH", "/api/auth/profile", json={"bio": "blocked"}).status_code == 401

    response = api_request(client, "POST", "/api/auth/register", json=_register_payload())
    assert response.status_code == 201
    assert response.json()["email"] == "alice@example.com"
    assert "authkit_sid" in client.cookies

    me = client.get("/api/auth/me")
    assert me.status_code == 200
    assert me.json()["username"] == "alice"
    assert me.json()["profile"]["avatar_url"] is None
    assert me.json()["preferences"]["notification_settings"] == {}

    profile = api_request(
        client,
        "PATCH",
        "/api/auth/profile",
        json={
            "bio": "Builder of auth-kit",
            "locale": "de-DE",
            "timezone": "Europe/Berlin",
        },
    )
    assert profile.status_code == 200
    assert profile.json()["timezone"] == "Europe/Berlin"

    contact = api_request(
        client,
        "PATCH",
        "/api/auth/contact",
        json={
            "phone": "+49 30 123456",
            "website": "https://alice.example.com",
            "social_links": {"github": "alice-dev"},
        },
    )
    assert contact.status_code == 200
    assert contact.json()["social_links"] == {"github": "alice-dev"}

    preferences = api_request(
        client,
        "PATCH",
        "/api/auth/preferences",
        json={
            "theme": "sunrise",
            "language": "de",
            "notification_settings": {"email": True, "product": False},
        },
    )
    assert preferences.status_code == 200
    assert preferences.json()["theme"] == "sunrise"

    security = api_request(
        client,
        "PATCH",
        "/api/auth/security",
        json={"two_factor_enabled": True, "trusted_devices_enabled": True},
    )
    assert security.status_code == 200
    assert security.json()["two_factor_enabled"] is True
    assert security.json()["trusted_devices_enabled"] is True

    me_after = client.get("/api/auth/me")
    assert me_after.status_code == 200
    assert me_after.json()["profile"]["bio"] == "Builder of auth-kit"
    assert me_after.json()["preferences"]["theme"] == "sunrise"

    sessions = client.get("/api/auth/sessions")
    assert sessions.status_code == 200
    assert len(sessions.json()) == 1
    assert sessions.json()[0]["is_current"] is True
    assert sessions.json()[0]["updated_at"] is not None

    changed = api_request(
        client,
        "POST",
        "/api/auth/change-password",
        json={
            "current_password": "StrongPassword!123",
            "new_password": "EvenStronger!456",
        },
    )
    assert changed.status_code == 200

    logout = api_request(client, "POST", "/api/auth/logout")
    assert logout.status_code == 200

    assert client.get("/api/auth/me").status_code == 401
    assert api_request(client, "POST", "/api/auth/login", json={"identifier": "alice", "password": "StrongPassword!123"}).status_code == 401

    relogin = api_request(
        client,
        "POST",
        "/api/auth/login",
        json={"identifier": "alice@example.com", "password": "EvenStronger!456"},
    )
    assert relogin.status_code == 200
    assert relogin.json()["username"] == "alice"


def test_login_rotates_existing_session(client: TestClient, api_request, db_session) -> None:
    registered = api_request(
        client,
        "POST",
        "/api/auth/register",
        json=_register_payload(email="rotate@example.com", username="rotate"),
    )
    assert registered.status_code == 201

    first_sessions = client.get("/api/auth/sessions").json()
    assert len(first_sessions) == 1
    first_session_id = first_sessions[0]["id"]

    relogin = api_request(
        client,
        "POST",
        "/api/auth/login",
        json={"identifier": "rotate@example.com", "password": "StrongPassword!123"},
    )
    assert relogin.status_code == 200

    second_sessions = client.get("/api/auth/sessions").json()
    assert len(second_sessions) == 1
    assert second_sessions[0]["id"] != first_session_id

    user = db_session.query(AuthUser).filter(AuthUser.username == "rotate").one()
    revoked_sessions = [session for session in user.sessions if session.revoked_at is not None]
    active_sessions = [session for session in user.sessions if session.revoked_at is None]
    assert len(revoked_sessions) == 1
    assert len(active_sessions) == 1


@pytest.mark.parametrize(
    ("password", "error_code"),
    [
        ("Short1!", "password_too_short"),
        ("STRONGPASSWORD!123", "password_missing_lowercase"),
        ("strongpassword!123", "password_missing_uppercase"),
        ("StrongPassword!!!", "password_missing_digit"),
        ("StrongPassword123", "password_missing_special"),
        ("alice@example.comA1!", "password_contains_email"),
        ("AliceUserA1!", "password_contains_username"),
    ],
)
def test_register_invalid_password_returns_structured_error(
    client: TestClient,
    api_request,
    password: str,
    error_code: str,
) -> None:
    response = api_request(
        client,
        "POST",
        "/api/auth/register",
        json=_register_payload(username="aliceuser", password=password),
    )

    assert response.status_code == 400
    assert response.json()["error_code"] == error_code
    assert response.json()["message"]


def test_register_rejects_cross_field_identifier_collisions(client: TestClient, api_request) -> None:
    first = api_request(
        client,
        "POST",
        "/api/auth/register",
        json=_register_payload(email="first@one.example", username="first@example.com"),
    )
    assert first.status_code == 201

    same_email_as_username = api_request(
        client,
        "POST",
        "/api/auth/register",
        json=_register_payload(email="second@example.com", username="first@one.example"),
    )
    assert same_email_as_username.status_code == 409

    same_username_as_email = api_request(
        client,
        "POST",
        "/api/auth/register",
        json=_register_payload(email="first@example.com", username="seconduser"),
    )
    assert same_username_as_email.status_code == 409


@pytest.mark.parametrize(
    ("filename", "content_type"),
    [
        ("avatar.png", "image/png"),
        ("avatar.jpg", "image/jpeg"),
        ("avatar.webp", "image/webp"),
    ],
)
def test_avatar_upload_accepts_supported_types(
    client: TestClient,
    db_session,
    api_request,
    filename: str,
    content_type: str,
) -> None:
    register = api_request(
        client,
        "POST",
        "/api/auth/register",
        json=_register_payload(email="avatar@example.com", username="avataruser", display_name="Avatar User"),
    )
    assert register.status_code == 201

    response = api_request(
        client,
        "POST",
        "/api/auth/profile/avatar",
        files={"avatar": (filename, b"fake-image-bytes", content_type)},
    )

    assert response.status_code == 201
    avatar_url = response.json()["avatar_url"]
    assert avatar_url.startswith("/api/auth/avatars/")
    assert "/srv/" not in avatar_url
    assert "avataruser" not in avatar_url
    assert "avatar@example.com" not in avatar_url
    assert filename not in avatar_url

    fetched = client.get(avatar_url)
    assert fetched.status_code == 200
    assert fetched.content == b"fake-image-bytes"

    current_avatar = client.get("/api/auth/profile/avatar")
    assert current_avatar.status_code == 200
    assert current_avatar.content == b"fake-image-bytes"

    me = client.get("/api/auth/me")
    assert me.status_code == 200
    assert me.json()["profile"]["avatar_url"] == avatar_url

    user = db_session.query(AuthUser).filter(AuthUser.username == "avataruser").one()
    assert user.profile is not None
    assert user.profile.avatar_storage_key is not None
    assert filename not in user.profile.avatar_storage_key
    assert str(user.id) not in user.profile.avatar_storage_key
    assert user.username not in user.profile.avatar_storage_key
    assert user.email not in user.profile.avatar_storage_key
    assert "/srv/" not in user.profile.avatar_storage_key
    assert user.profile.avatar_storage_key.startswith("avatars/")
    assert user.profile.avatar_storage_key.count("/") >= 3


def test_avatar_endpoint_rejects_unknown_identifier(client: TestClient) -> None:
    response = client.get("/api/auth/avatars/not-a-real-avatar")
    assert response.status_code == 404
    assert response.json()["error_code"] == "avatar_not_found"


def test_avatar_upload_rejects_invalid_type(client: TestClient, api_request) -> None:
    register = api_request(
        client,
        "POST",
        "/api/auth/register",
        json=_register_payload(email="avatarbad@example.com", username="avatarbad", display_name="Avatar Bad"),
    )
    assert register.status_code == 201

    response = api_request(
        client,
        "POST",
        "/api/auth/profile/avatar",
        files={"avatar": ("avatar.txt", b"plain-text", "text/plain")},
    )

    assert response.status_code == 400
    assert response.json()["error_code"] == "avatar_invalid_content_type"


def test_avatar_upload_rejects_oversized_file(client: TestClient, api_request) -> None:
    register = api_request(
        client,
        "POST",
        "/api/auth/register",
        json=_register_payload(email="avatarlimit@example.com", username="avatarlimit", display_name="Avatar Limit"),
    )
    assert register.status_code == 201

    response = api_request(
        client,
        "POST",
        "/api/auth/profile/avatar",
        files={"avatar": ("avatar.png", b"x" * (1024 * 1024 + 1), "image/png")},
    )

    assert response.status_code == 413
    assert response.json()["error_code"] == "avatar_too_large"


def test_address_lifecycle_multiple_and_cross_user_protection(app, client: TestClient, api_request) -> None:
    register = {
        "email": "bob@example.com",
        "username": "bob",
        "display_name": "Bob",
        "password": "StrongPassword!123",
    }
    assert api_request(client, "POST", "/api/auth/register", json=register).status_code == 201

    first = api_request(
        client,
        "POST",
        "/api/auth/addresses",
        json={
            "type": "billing",
            "name": "Bob Billing",
            "street_line_1": "Main Street 1",
            "postal_code": "12345",
            "city": "Berlin",
            "country": "DE",
            "is_default": True,
        },
    )
    assert first.status_code == 201
    first_address_id = first.json()["id"]
    assert first.json()["is_default"] is True

    second = api_request(
        client,
        "POST",
        "/api/auth/addresses",
        json={
            "type": "shipping",
            "name": "Bob Shipping",
            "street_line_1": "Side Street 2",
            "street_line_2": "Floor 3",
            "postal_code": "54321",
            "city": "Hamburg",
            "state": "HH",
            "country": "DE",
            "is_default": False,
        },
    )
    assert second.status_code == 201
    second_address_id = second.json()["id"]

    addresses = client.get("/api/auth/addresses")
    assert addresses.status_code == 200
    assert len(addresses.json()) == 2

    updated = api_request(
        client,
        "PATCH",
        f"/api/auth/addresses/{second_address_id}",
        json={"city": "Munich", "is_default": True},
    )
    assert updated.status_code == 200
    assert updated.json()["city"] == "Munich"
    assert updated.json()["is_default"] is True

    addresses_after_patch = client.get("/api/auth/addresses").json()
    first_after = next(item for item in addresses_after_patch if item["id"] == first_address_id)
    second_after = next(item for item in addresses_after_patch if item["id"] == second_address_id)
    assert first_after["is_default"] is False
    assert second_after["is_default"] is True

    with TestClient(app) as second_client:
        second_register = api_request(
            second_client,
            "POST",
            "/api/auth/register",
            json={
                "email": "eve@example.com",
                "username": "eve",
                "display_name": "Eve",
                "password": "StrongPassword!123",
            },
        )
        assert second_register.status_code == 201
        assert api_request(second_client, "PATCH", f"/api/auth/addresses/{first_address_id}", json={"city": "Paris"}).status_code == 404
        assert api_request(second_client, "DELETE", f"/api/auth/addresses/{second_address_id}").status_code == 404

    deleted = api_request(client, "DELETE", f"/api/auth/addresses/{first_address_id}")
    assert deleted.status_code == 204
    remaining = client.get("/api/auth/addresses")
    assert remaining.status_code == 200
    assert [address["id"] for address in remaining.json()] == [second_address_id]


def test_session_revocation_invalidates_other_client(app, client: TestClient, api_request) -> None:
    register = {
        "email": "zoe@example.com",
        "username": "zoe",
        "display_name": "Zoe",
        "password": "StrongPassword!123",
    }
    assert api_request(client, "POST", "/api/auth/register", json=register).status_code == 201

    with TestClient(app) as second_client:
        login = api_request(
            second_client,
            "POST",
            "/api/auth/login",
            json={"identifier": "zoe", "password": "StrongPassword!123"},
        )
        assert login.status_code == 200

        sessions = client.get("/api/auth/sessions").json()
        assert len(sessions) == 2
        other_session = next(item for item in sessions if item["is_current"] is False)

        revoke = api_request(client, "DELETE", f"/api/auth/sessions/{other_session['id']}")
        assert revoke.status_code == 204
        assert second_client.get("/api/auth/me").status_code == 401


def test_forgot_password_and_reset_flow(app, client: TestClient, db_session, api_request, caplog) -> None:
    registered = api_request(
        client,
        "POST",
        "/api/auth/register",
        json=_register_payload(email="reset@example.com", username="resetuser", display_name="Reset User"),
    )
    assert registered.status_code == 201

    with TestClient(app) as second_client:
        second_login = api_request(
            second_client,
            "POST",
            "/api/auth/login",
            json={"identifier": "reset@example.com", "password": "StrongPassword!123"},
        )
        assert second_login.status_code == 200

        with caplog.at_level(logging.INFO):
            forgot = api_request(
                client,
                "POST",
                "/api/auth/forgot-password",
                json={"email": "reset@example.com"},
            )
        assert forgot.status_code == 200
        assert forgot.json()["message"] == "If an account exists for that email, reset instructions will be sent."

        match = re.search(r"\[auth-kit\] password reset link for reset@example\.com: (\S+)", caplog.text)
        assert match is not None
        reset_url = match.group(1)
        raw_token = parse_qs(urlsplit(reset_url).query)["token"][0]

        db_session.expire_all()
        reset_token = db_session.query(AuthPasswordResetToken).one()
        assert reset_token.token_hash != raw_token
        assert len(reset_token.token_hash) == 64
        assert reset_token.consumed_at is None

        outbox_path = app.state.settings.dev_mail_outbox_path
        with open(outbox_path, encoding="utf-8") as handle:
            outbox_lines = handle.readlines()
        assert len(outbox_lines) == 1
        outbox_entry = json.loads(outbox_lines[0])
        assert outbox_entry["email"] == "reset@example.com"
        assert outbox_entry["reset_url"] == reset_url
        assert outbox_entry["token"] == raw_token
        assert outbox_entry["mail_mode"] == "dev"

        reset = api_request(
            client,
            "POST",
            "/api/auth/reset-password",
            json={"token": raw_token, "new_password": "EvenStronger!456"},
        )
        assert reset.status_code == 200
        assert reset.json()["message"] == "Password has been reset. You can now sign in."

        db_session.expire_all()
        refreshed_token = db_session.query(AuthPasswordResetToken).one()
        assert refreshed_token.consumed_at is not None

        assert client.get("/api/auth/me").status_code == 401
        assert second_client.get("/api/auth/me").status_code == 401

    assert (
        api_request(
            client,
            "POST",
            "/api/auth/login",
            json={"identifier": "reset@example.com", "password": "StrongPassword!123"},
        ).status_code
        == 401
    )
    assert (
        api_request(
            client,
            "POST",
            "/api/auth/login",
            json={"identifier": "reset@example.com", "password": "EvenStronger!456"},
        ).status_code
        == 200
    )


def test_forgot_password_does_not_enumerate(client: TestClient, api_request) -> None:
    assert (
        api_request(
            client,
            "POST",
            "/api/auth/register",
            json=_register_payload(email="known@example.com", username="known"),
        ).status_code
        == 201
    )

    existing = api_request(client, "POST", "/api/auth/forgot-password", json={"email": "known@example.com"})
    missing = api_request(client, "POST", "/api/auth/forgot-password", json={"email": "missing@example.com"})

    assert existing.status_code == 200
    assert missing.status_code == 200
    assert existing.json() == missing.json()


def test_rate_limit_blocks_repeated_login_requests(settings_factory) -> None:
    settings = settings_factory(rate_limit_login=1)
    engine = create_engine(settings.database_url, connect_args={"check_same_thread": False})
    Base.metadata.create_all(engine)
    app = create_app(settings)

    with TestClient(app) as client:
        first = _custom_api_request(
            client,
            settings,
            "POST",
            "/api/auth/login",
            json={"identifier": "owner@example.com", "password": OWNER_PASSWORD},
        )
        assert first.status_code == 200

        second = _custom_api_request(
            client,
            settings,
            "POST",
            "/api/auth/login",
            json={"identifier": "owner@example.com", "password": OWNER_PASSWORD},
        )
        assert second.status_code == 429
        assert second.json()["error_code"] == "rate_limit_exceeded"
    engine.dispose()


def test_security_headers_present(client: TestClient) -> None:
    response = client.get("/api/health")
    assert response.status_code == 200
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert response.headers["permissions-policy"] == "camera=(), microphone=(), geolocation=()"
    assert "default-src 'none'" in response.headers["content-security-policy"]
