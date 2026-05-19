from __future__ import annotations

from pathlib import Path

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
        ],
    )

    settings = Settings(
        database_url=f"sqlite+pysqlite:///{tmp_path / 'smtp.db'}",
        _env_file=env_file,
    )

    assert settings.mail_mode == "smtp"


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
