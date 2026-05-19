from __future__ import annotations

import hashlib
import re
import secrets

from argon2 import PasswordHasher, Type
from argon2.exceptions import InvalidHashError, VerifyMismatchError

from .core.config import Settings
from .errors import ApiError, PasswordValidationError
from .models import STANDARD_ROLES

_password_hasher = PasswordHasher(type=Type.ID)


def normalize_email(email: str) -> str:
    return email.strip().lower()


def normalize_username(username: str) -> str:
    return username.strip().lower()


def normalize_roles(roles: list[str] | tuple[str, ...] | set[str]) -> list[str]:
    cleaned: list[str] = []
    for raw in roles:
        role = raw.strip().lower()
        if not role:
            continue
        if role not in STANDARD_ROLES:
            raise ApiError(status_code=400, error_code="invalid_role", message=f"Unsupported role: {role}.")
        if role not in cleaned:
            cleaned.append(role)
    if not cleaned:
        raise ApiError(status_code=400, error_code="roles_required", message="At least one role is required.")
    return cleaned


def validate_password(password: str, *, email: str, username: str, settings: Settings) -> None:
    if len(password) < settings.password_min_length:
        raise PasswordValidationError(
            status_code=400,
            error_code="password_too_short",
            message=f"Password must be at least {settings.password_min_length} characters long.",
        )
    if not re.search(r"[a-z]", password):
        raise PasswordValidationError(
            status_code=400,
            error_code="password_missing_lowercase",
            message="Password must contain at least one lowercase letter.",
        )
    if not re.search(r"[A-Z]", password):
        raise PasswordValidationError(
            status_code=400,
            error_code="password_missing_uppercase",
            message="Password must contain at least one uppercase letter.",
        )
    if not re.search(r"[0-9]", password):
        raise PasswordValidationError(
            status_code=400,
            error_code="password_missing_digit",
            message="Password must contain at least one digit.",
        )
    if not re.search(r"[^A-Za-z0-9]", password):
        raise PasswordValidationError(
            status_code=400,
            error_code="password_missing_special",
            message="Password must contain at least one special character.",
        )

    lowered_password = password.lower()
    if normalize_email(email) in lowered_password:
        raise PasswordValidationError(
            status_code=400,
            error_code="password_contains_email",
            message="Password must not contain your email address.",
        )
    if normalize_username(username) in lowered_password:
        raise PasswordValidationError(
            status_code=400,
            error_code="password_contains_username",
            message="Password must not contain your username.",
        )


def hash_password(password: str) -> str:
    return _password_hasher.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return _password_hasher.verify(password_hash, password)
    except (InvalidHashError, VerifyMismatchError):
        return False


def generate_session_token() -> str:
    return secrets.token_urlsafe(32)


def generate_csrf_token() -> str:
    return secrets.token_urlsafe(32)


def generate_password_reset_token() -> str:
    return secrets.token_urlsafe(48)


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def hash_session_token(token: str) -> str:
    return hash_token(token)


def hash_password_reset_token(token: str) -> str:
    return hash_token(token)
