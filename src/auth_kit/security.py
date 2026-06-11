from __future__ import annotations

import base64
import hashlib
import hmac
import re
import secrets
import urllib.parse
from datetime import UTC, datetime

from argon2 import PasswordHasher, Type
from argon2.exceptions import InvalidHashError, VerifyMismatchError

from .core.config import Settings
from .errors import ApiError, PasswordValidationError
from .models import STANDARD_ROLES

_password_hasher = PasswordHasher(type=Type.ID)
RECOVERY_CODE_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
TOTP_PERIOD_SECONDS = 30
TOTP_DIGITS = 6


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


def generate_login_challenge_token() -> str:
    return secrets.token_urlsafe(48)


def generate_trusted_device_token() -> str:
    return secrets.token_urlsafe(48)


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def hash_session_token(token: str) -> str:
    return hash_token(token)


def hash_password_reset_token(token: str) -> str:
    return hash_token(token)


def hash_login_challenge_token(token: str) -> str:
    return hash_token(token)


def hash_trusted_device_token(token: str) -> str:
    return hash_token(token)


def generate_totp_secret() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode("ascii").rstrip("=")


def build_totp_otpauth_uri(*, secret: str, issuer: str, account_name: str) -> str:
    issuer_value = issuer.strip() or "auth-kit"
    label = urllib.parse.quote(f"{issuer_value}:{account_name}", safe="")
    params = urllib.parse.urlencode(
        {
            "secret": secret,
            "issuer": issuer_value,
            "algorithm": "SHA1",
            "digits": str(TOTP_DIGITS),
            "period": str(TOTP_PERIOD_SECONDS),
        }
    )
    return f"otpauth://totp/{label}?{params}"


def _base32_decode(value: str) -> bytes:
    normalized = value.strip().replace(" ", "").upper()
    padding = "=" * ((8 - len(normalized) % 8) % 8)
    return base64.b32decode(normalized + padding, casefold=True)


def generate_totp_code(secret: str, *, when: datetime | None = None) -> str:
    now = when or datetime.now(UTC)
    counter = int(now.timestamp()) // TOTP_PERIOD_SECONDS
    secret_bytes = _base32_decode(secret)
    counter_bytes = counter.to_bytes(8, "big")
    digest = hmac.new(secret_bytes, counter_bytes, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    truncated = int.from_bytes(digest[offset : offset + 4], "big") & 0x7FFFFFFF
    otp = truncated % (10**TOTP_DIGITS)
    return f"{otp:0{TOTP_DIGITS}d}"


def verify_totp_code(secret: str, code: str, *, when: datetime | None = None, window: int = 1) -> bool:
    normalized_code = "".join(character for character in code.strip() if character.isdigit())
    if len(normalized_code) != TOTP_DIGITS:
        return False

    now = when or datetime.now(UTC)
    for offset in range(-window, window + 1):
        candidate_time = datetime.fromtimestamp(now.timestamp() + (offset * TOTP_PERIOD_SECONDS), UTC)
        if hmac.compare_digest(generate_totp_code(secret, when=candidate_time), normalized_code):
            return True
    return False


def generate_recovery_codes(*, count: int) -> list[str]:
    codes: list[str] = []
    for _ in range(count):
        raw = "".join(secrets.choice(RECOVERY_CODE_ALPHABET) for _ in range(8))
        codes.append(f"{raw[:4]}-{raw[4:]}")
    return codes


def normalize_recovery_code(code: str) -> str:
    return "".join(character for character in code.strip().upper() if character.isalnum())


def hash_recovery_code(code: str) -> str:
    return hash_token(normalize_recovery_code(code))


def _expand_keystream(key: bytes, nonce: bytes, length: int) -> bytes:
    chunks: list[bytes] = []
    counter = 0
    while sum(len(chunk) for chunk in chunks) < length:
        counter_bytes = counter.to_bytes(4, "big")
        chunks.append(hmac.new(key, nonce + counter_bytes, hashlib.sha256).digest())
        counter += 1
    return b"".join(chunks)[:length]


def protect_sensitive_value(value: str, *, settings: Settings, purpose: str) -> str:
    secret_key = settings.security_secret_key.encode("utf-8")
    purpose_key = hmac.new(secret_key, purpose.encode("utf-8"), hashlib.sha256).digest()
    nonce = secrets.token_bytes(16)
    plaintext = value.encode("utf-8")
    keystream = _expand_keystream(purpose_key, nonce, len(plaintext))
    ciphertext = bytes(left ^ right for left, right in zip(plaintext, keystream, strict=True))
    tag = hmac.new(purpose_key, nonce + ciphertext, hashlib.sha256).digest()
    payload = base64.urlsafe_b64encode(nonce + tag + ciphertext).decode("ascii")
    return f"v1:{payload}"


def unprotect_sensitive_value(value: str, *, settings: Settings, purpose: str) -> str:
    if not value.startswith("v1:"):
        raise ApiError(status_code=500, error_code="protected_secret_invalid", message="Protected secret format is invalid.")

    payload = base64.urlsafe_b64decode(value[3:].encode("ascii"))
    nonce = payload[:16]
    tag = payload[16:48]
    ciphertext = payload[48:]
    secret_key = settings.security_secret_key.encode("utf-8")
    purpose_key = hmac.new(secret_key, purpose.encode("utf-8"), hashlib.sha256).digest()
    expected_tag = hmac.new(purpose_key, nonce + ciphertext, hashlib.sha256).digest()
    if not hmac.compare_digest(tag, expected_tag):
        raise ApiError(status_code=500, error_code="protected_secret_invalid", message="Protected secret verification failed.")

    keystream = _expand_keystream(purpose_key, nonce, len(ciphertext))
    plaintext = bytes(left ^ right for left, right in zip(ciphertext, keystream, strict=True))
    return plaintext.decode("utf-8")
