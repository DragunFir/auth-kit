from __future__ import annotations

from fastapi.testclient import TestClient


def _login_owner(client: TestClient) -> None:
    response = client.post(
        "/api/auth/login",
        json={"identifier": "owner@example.com", "password": "PrimaryPass!123"},
    )
    assert response.status_code == 200


def test_admin_user_flow_and_owner_safeguard(client: TestClient) -> None:
    _login_owner(client)

    created = client.post(
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

    patched = client.patch(
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

    unsafe_security = client.patch(
        f"/api/admin/users/{user_id}",
        json={"security": {"two_factor_enabled": True}},
    )
    assert unsafe_security.status_code == 422

    unsafe_password = client.patch(
        f"/api/admin/users/{user_id}",
        json={"password_hash": "not-allowed"},
    )
    assert unsafe_password.status_code == 422

    reset = client.post(
        f"/api/admin/users/{user_id}/reset-password",
        json={"new_password": "ResetPassword!456"},
    )
    assert reset.status_code == 200

    disabled = client.post(f"/api/admin/users/{user_id}/disable")
    assert disabled.status_code == 200
    assert disabled.json()["is_active"] is False

    blocked_login = client.post(
        "/api/auth/login",
        json={"identifier": "charlie", "password": "ResetPassword!456"},
    )
    assert blocked_login.status_code == 403

    enabled = client.post(f"/api/admin/users/{user_id}/enable")
    assert enabled.status_code == 200
    assert enabled.json()["is_active"] is True

    allowed_login = client.post(
        "/api/auth/login",
        json={"identifier": "charlie@example.com", "password": "ResetPassword!456"},
    )
    assert allowed_login.status_code == 200

    _login_owner(client)
    last_owner = client.post("/api/admin/users/1/disable")
    assert last_owner.status_code == 400
