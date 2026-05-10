from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from auth_kit.models import AuthAuditLog, AuthUser


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


def test_register_profile_preferences_contact_security_and_me(client: TestClient) -> None:
    assert client.patch("/api/auth/profile", json={"bio": "blocked"}).status_code == 401

    response = client.post(
        "/api/auth/register",
        json={
            "email": "alice@example.com",
            "username": "alice",
            "display_name": "Alice",
            "password": "StrongPassword!123",
        },
    )
    assert response.status_code == 201
    assert response.json()["email"] == "alice@example.com"
    assert "authkit_sid" in client.cookies

    me = client.get("/api/auth/me")
    assert me.status_code == 200
    assert me.json()["username"] == "alice"
    assert me.json()["profile"]["avatar_url"] is None
    assert me.json()["preferences"]["notification_settings"] == {}

    profile = client.patch(
        "/api/auth/profile",
        json={
            "bio": "Builder of auth-kit",
            "locale": "de-DE",
            "timezone": "Europe/Berlin",
        },
    )
    assert profile.status_code == 200
    assert profile.json()["timezone"] == "Europe/Berlin"

    contact = client.patch(
        "/api/auth/contact",
        json={
            "phone": "+49 30 123456",
            "website": "https://alice.example.com",
            "social_links": {"github": "alice-dev"},
        },
    )
    assert contact.status_code == 200
    assert contact.json()["social_links"] == {"github": "alice-dev"}

    preferences = client.patch(
        "/api/auth/preferences",
        json={
            "theme": "sunrise",
            "language": "de",
            "notification_settings": {"email": True, "product": False},
        },
    )
    assert preferences.status_code == 200
    assert preferences.json()["theme"] == "sunrise"

    security = client.patch(
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

    changed = client.post(
        "/api/auth/change-password",
        json={
            "current_password": "StrongPassword!123",
            "new_password": "EvenStronger!456",
        },
    )
    assert changed.status_code == 200

    logout = client.post("/api/auth/logout")
    assert logout.status_code == 200

    assert client.get("/api/auth/me").status_code == 401
    assert client.post("/api/auth/login", json={"identifier": "alice", "password": "StrongPassword!123"}).status_code == 401

    relogin = client.post(
        "/api/auth/login",
        json={"identifier": "alice@example.com", "password": "EvenStronger!456"},
    )
    assert relogin.status_code == 200
    assert relogin.json()["username"] == "alice"


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
    password: str,
    error_code: str,
) -> None:
    response = client.post(
        "/api/auth/register",
        json={
            "email": "alice@example.com",
            "username": "aliceuser",
            "display_name": "Alice",
            "password": password,
        },
    )

    assert response.status_code == 400
    assert response.json()["error_code"] == error_code
    assert response.json()["message"]


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
    filename: str,
    content_type: str,
) -> None:
    register = client.post(
        "/api/auth/register",
        json={
            "email": "avatar@example.com",
            "username": "avataruser",
            "display_name": "Avatar User",
            "password": "StrongPassword!123",
        },
    )
    assert register.status_code == 201

    response = client.post(
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


def test_avatar_upload_rejects_invalid_type(client: TestClient) -> None:
    register = client.post(
        "/api/auth/register",
        json={
            "email": "avatarbad@example.com",
            "username": "avatarbad",
            "display_name": "Avatar Bad",
            "password": "StrongPassword!123",
        },
    )
    assert register.status_code == 201

    response = client.post(
        "/api/auth/profile/avatar",
        files={"avatar": ("avatar.txt", b"plain-text", "text/plain")},
    )

    assert response.status_code == 400
    assert response.json()["error_code"] == "avatar_invalid_content_type"


def test_avatar_upload_rejects_oversized_file(client: TestClient) -> None:
    register = client.post(
        "/api/auth/register",
        json={
            "email": "avatarlimit@example.com",
            "username": "avatarlimit",
            "display_name": "Avatar Limit",
            "password": "StrongPassword!123",
        },
    )
    assert register.status_code == 201

    response = client.post(
        "/api/auth/profile/avatar",
        files={"avatar": ("avatar.png", b"x" * (1024 * 1024 + 1), "image/png")},
    )

    assert response.status_code == 413
    assert response.json()["error_code"] == "avatar_too_large"


def test_address_lifecycle_multiple_and_cross_user_protection(app, client: TestClient) -> None:
    register = {
        "email": "bob@example.com",
        "username": "bob",
        "display_name": "Bob",
        "password": "StrongPassword!123",
    }
    assert client.post("/api/auth/register", json=register).status_code == 201

    first = client.post(
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

    second = client.post(
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

    updated = client.patch(
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
        second_register = second_client.post(
            "/api/auth/register",
            json={
                "email": "eve@example.com",
                "username": "eve",
                "display_name": "Eve",
                "password": "StrongPassword!123",
            },
        )
        assert second_register.status_code == 201
        assert second_client.patch(f"/api/auth/addresses/{first_address_id}", json={"city": "Paris"}).status_code == 404
        assert second_client.delete(f"/api/auth/addresses/{second_address_id}").status_code == 404

    deleted = client.delete(f"/api/auth/addresses/{first_address_id}")
    assert deleted.status_code == 204
    remaining = client.get("/api/auth/addresses")
    assert remaining.status_code == 200
    assert [address["id"] for address in remaining.json()] == [second_address_id]


def test_session_revocation_invalidates_other_client(app, client: TestClient) -> None:
    register = {
        "email": "zoe@example.com",
        "username": "zoe",
        "display_name": "Zoe",
        "password": "StrongPassword!123",
    }
    assert client.post("/api/auth/register", json=register).status_code == 201

    with TestClient(app) as second_client:
        login = second_client.post(
            "/api/auth/login",
            json={"identifier": "zoe", "password": "StrongPassword!123"},
        )
        assert login.status_code == 200

        sessions = client.get("/api/auth/sessions").json()
        assert len(sessions) == 2
        other_session = next(item for item in sessions if item["is_current"] is False)

        revoke = client.delete(f"/api/auth/sessions/{other_session['id']}")
        assert revoke.status_code == 204
        assert second_client.get("/api/auth/me").status_code == 401
