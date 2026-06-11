from __future__ import annotations

from pathlib import Path


def test_avatar_url_is_not_rendered_as_text_input() -> None:
    app_source = Path("web/src/App.tsx").read_text()

    assert 'label="Avatar URL"' not in app_source
    assert "value={profile.avatar_url" not in app_source
    assert "value={adminForm.profile.avatar_url" not in app_source
    assert "src={profile.avatar_url || undefined}" in app_source


def test_forgot_password_uses_neutral_confirmation_message() -> None:
    app_source = Path("web/src/App.tsx").read_text()

    assert "Wenn ein Konto existiert, wurde eine Reset-Anleitung verschickt." in app_source
    assert "development mail log" not in app_source
    assert "data/dev-mail/outbox.jsonl" not in app_source


def test_reset_password_prefills_token_from_url() -> None:
    app_source = Path("web/src/App.tsx").read_text()

    assert 'new URLSearchParams(location.search).get("token") ?? ""' in app_source
    assert "Paste the reset token from the development mail log" not in app_source


def test_account_surface_includes_session_controls() -> None:
    app_source = Path("web/src/App.tsx").read_text()

    assert 'title="Sessions and Devices"' in app_source
    assert 'session.is_current ? "Logout current" : "End session"' in app_source


def test_security_preferences_are_marked_as_planned_not_active() -> None:
    app_source = Path("web/src/App.tsx").read_text()

    assert 'title="Security preferences"' in app_source
    assert 'subheader="Prepared security options"' in app_source
    assert "These options are prepared for future releases and are not active security features yet." in app_source
    assert 'label="Two-factor authentication planned"' in app_source
    assert 'label="Passkeys planned"' in app_source
    assert 'label="Recovery codes planned"' in app_source
    assert 'label="Trusted devices planned"' in app_source
    assert 'label="Two-factor enabled"' not in app_source
    assert 'label="Passkeys enabled"' not in app_source
    assert 'label="Recovery codes enabled"' not in app_source
    assert 'label="Trusted devices enabled"' not in app_source
    assert "Save security" not in app_source


def test_admin_surface_exposes_safe_role_and_status_controls_only() -> None:
    app_source = Path("web/src/App.tsx").read_text()

    assert 'selectedUser.is_active ? "Disable" : "Enable"' in app_source
    assert "toggleRole(adminForm.roles, role)" in app_source
    assert 'label="New password"' in app_source
    assert "Direct security internals stay server-side." in app_source
    assert 'label="Password Hash"' not in app_source
