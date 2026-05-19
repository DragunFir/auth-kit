from __future__ import annotations

from fastapi.testclient import TestClient

OWNER_PASSWORD = "HarborKey!2026Z"


def _login_owner(client: TestClient, api_request) -> None:
    response = api_request(
        client,
        "POST",
        "/api/auth/login",
        json={"identifier": "owner@example.com", "password": OWNER_PASSWORD},
    )
    assert response.status_code == 200


def test_admin_user_flow_and_owner_safeguard(client: TestClient, api_request) -> None:
    _login_owner(client, api_request)

    created = api_request(
        client,
        "POST",
        "/api/admin/users",
        json={
            "email": "charlie@example.com",
            "username": "charlie",
            "display_name": "Charlie",
            "password": "StrongPassword!123",
            "roles": ["user"],
            "is_active": True,
            "is_verified": True,
        },
    )
    assert created.status_code == 201
    user_id = created.json()["id"]

    listed = client.get("/api/admin/users")
    assert listed.status_code == 200
    assert any(user["id"] == user_id for user in listed.json())

    detail = client.get(f"/api/admin/users/{user_id}")
    assert detail.status_code == 200
    assert detail.json()["profile"]["avatar_url"] is None
    assert detail.json()["preferences"]["notification_settings"] == {}
    assert detail.json()["security"]["two_factor_enabled"] is False
    assert detail.json()["addresses"] == []

    patched = api_request(
        client,
        "PATCH",
        f"/api/admin/users/{user_id}",
        json={
            "roles": ["user", "admin"],
            "is_verified": False,
            "profile": {"bio": "Admin managed profile"},
            "contact": {"phone": "+1-555-0100"},
            "preferences": {"theme": "ocean"},
        },
    )
    assert patched.status_code == 200
    assert patched.json()["roles"] == ["user", "admin"]
    assert patched.json()["is_verified"] is False
    assert patched.json()["profile"]["bio"] == "Admin managed profile"
    assert patched.json()["contact"]["phone"] == "+1-555-0100"
    assert patched.json()["preferences"]["theme"] == "ocean"

    unsafe_security = api_request(
        client,
        "PATCH",
        f"/api/admin/users/{user_id}",
        json={"security": {"two_factor_enabled": True}},
    )
    assert unsafe_security.status_code == 422

    unsafe_password = api_request(
        client,
        "PATCH",
        f"/api/admin/users/{user_id}",
        json={"password_hash": "not-allowed"},
    )
    assert unsafe_password.status_code == 422

    reset = api_request(
        client,
        "POST",
        f"/api/admin/users/{user_id}/reset-password",
        json={"new_password": "ResetPassword!456"},
    )
    assert reset.status_code == 200

    disabled = api_request(client, "POST", f"/api/admin/users/{user_id}/disable")
    assert disabled.status_code == 200
    assert disabled.json()["is_active"] is False

    blocked_login = api_request(
        client,
        "POST",
        "/api/auth/login",
        json={"identifier": "charlie", "password": "ResetPassword!456"},
    )
    assert blocked_login.status_code == 403

    enabled = api_request(client, "POST", f"/api/admin/users/{user_id}/enable")
    assert enabled.status_code == 200
    assert enabled.json()["is_active"] is True

    allowed_login = api_request(
        client,
        "POST",
        "/api/auth/login",
        json={"identifier": "charlie@example.com", "password": "ResetPassword!456"},
    )
    assert allowed_login.status_code == 200

    _login_owner(client, api_request)
    last_owner = api_request(client, "POST", "/api/admin/users/1/disable")
    assert last_owner.status_code == 400
