from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from auth_kit.core.config import Settings


def _write_env_file(path: Path, lines: list[str]) -> Path:
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def test_settings_mail_mode_defaults_to_dev(tmp_path) -> None:
    settings = Settings(
        database_url=f"sqlite+pysqlite:///{tmp_path / 'default.db'}",
        _env_file=None,
    )

    assert settings.mail_mode == "dev"


def test_settings_reads_prefixed_mail_mode_from_env_file(tmp_path) -> None:
    env_file = _write_env_file(
        tmp_path / "smtp.env",
        [
            "AUTHKIT_MAIL_MODE=smtp",
            "AUTHKIT_SMTP_HOST=smtp.example.com",
            "AUTHKIT_SMTP_PORT=587",
            "AUTHKIT_SMTP_USERNAME=mailer",
            "AUTHKIT_SMTP_PASSWORD=super-secret",
            "AUTHKIT_SMTP_FROM_EMAIL=no-reply@example.com",
        ],
    )

    settings = Settings(
        database_url=f"sqlite+pysqlite:///{tmp_path / 'smtp.db'}",
        _env_file=env_file,
    )

    assert settings.mail_mode == "smtp"


def test_settings_require_smtp_configuration_when_mail_mode_is_smtp(tmp_path) -> None:
    env_file = _write_env_file(
        tmp_path / "invalid-smtp.env",
        [
            "AUTHKIT_MAIL_MODE=smtp",
        ],
    )

    with pytest.raises(ValidationError, match="AUTHKIT_MAIL_MODE=smtp requires the following settings"):
        Settings(
            database_url=f"sqlite+pysqlite:///{tmp_path / 'invalid.db'}",
            _env_file=env_file,
        )


def test_settings_reads_legacy_prefixed_mail_mode_alias_from_env_file(tmp_path) -> None:
    env_file = _write_env_file(
        tmp_path / "legacy.env",
        [
            "AUTHKIT_PASSWORD_RESET_DELIVERY_MODE=log",
        ],
    )

    settings = Settings(
        database_url=f"sqlite+pysqlite:///{tmp_path / 'legacy.db'}",
        _env_file=env_file,
    )

    assert settings.mail_mode == "log"


def test_settings_require_secure_cookie_for_samesite_none(tmp_path) -> None:
    with pytest.raises(
        ValidationError,
        match="AUTHKIT_SESSION_COOKIE_SAMESITE=none requires AUTHKIT_SESSION_COOKIE_SECURE=true",
    ):
        Settings(
            database_url=f"sqlite+pysqlite:///{tmp_path / 'samesite-none.db'}",
            session_cookie_samesite="none",
            session_cookie_secure=False,
            _env_file=None,
        )


def test_settings_allow_samesite_none_with_secure_cookie(tmp_path) -> None:
    settings = Settings(
        database_url=f"sqlite+pysqlite:///{tmp_path / 'samesite-none-secure.db'}",
        session_cookie_samesite="none",
        session_cookie_secure=True,
        _env_file=None,
    )

    assert settings.session_cookie_samesite == "none"
    assert settings.session_cookie_secure is True
