from __future__ import annotations

from passlib.context import CryptContext

from .settings import Settings

_pwd_ctx: CryptContext | None = None


def get_pwd_context(settings: Settings) -> CryptContext:
    global _pwd_ctx
    if _pwd_ctx is None:
        _pwd_ctx = CryptContext(
            schemes=["bcrypt"],
            deprecated="auto",
            bcrypt__rounds=settings.password_bcrypt_rounds,
        )
    return _pwd_ctx


def hash_password(settings: Settings, password: str) -> str:
    return get_pwd_context(settings).hash(password)


def verify_password(settings: Settings, password: str, password_hash: str) -> bool:
    return get_pwd_context(settings).verify(password, password_hash)
