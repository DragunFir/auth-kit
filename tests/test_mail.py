from __future__ import annotations

import pytest

from auth_kit.services import send_test_mail


def test_send_test_mail_requires_smtp_mode(settings_factory) -> None:
    settings = settings_factory(mail_mode="dev")

    with pytest.raises(RuntimeError, match="AUTHKIT_MAIL_MODE must be set to smtp"):
        send_test_mail(to_email="ops@example.com", settings=settings)


def test_send_test_mail_uses_current_smtp_configuration(settings_factory, monkeypatch) -> None:
    settings = settings_factory(
        mail_mode="smtp",
        smtp_host="smtp.example.com",
        smtp_port=587,
        smtp_username="mailer",
        smtp_password="secret",
        smtp_from_email="no-reply@example.com",
    )
    sent: dict[str, object] = {}

    def fake_send_smtp_email(*, to_email: str, subject: str, body: str, settings) -> None:
        sent["to_email"] = to_email
        sent["subject"] = subject
        sent["body"] = body
        sent["mail_mode"] = settings.mail_mode

    monkeypatch.setattr("auth_kit.services.send_smtp_email", fake_send_smtp_email)

    send_test_mail(to_email="ops@example.com", settings=settings)

    assert sent["to_email"] == "ops@example.com"
    assert sent["subject"] == "auth-kit SMTP test mail"
    assert "Configured mail mode: smtp" in str(sent["body"])
    assert sent["mail_mode"] == "smtp"
