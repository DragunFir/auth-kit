from __future__ import annotations

from collections.abc import Generator
from dataclasses import dataclass

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from .core.config import Settings
from .db import utcnow
from .models import AuthSession, AuthUser
from .security import hash_session_token


@dataclass(frozen=True)
class AuthContext:
    user: AuthUser
    session: AuthSession
    raw_token: str


def get_settings_dep(request: Request) -> Settings:
    return request.app.state.settings


def get_session_factory(request: Request) -> sessionmaker[Session]:
    return request.app.state.session_factory


def get_db(
    session_factory: sessionmaker[Session] = Depends(get_session_factory),
) -> Generator[Session, None, None]:
    db = session_factory()
    try:
        yield db
    finally:
        db.close()


def _resolve_auth_context(db: Session, settings: Settings, raw_token: str | None) -> AuthContext | None:
    if not raw_token:
        return None
    token_hash = hash_session_token(raw_token)
    stmt = (
        select(AuthSession, AuthUser)
        .join(AuthUser, AuthUser.id == AuthSession.user_id)
        .where(
            AuthSession.token_hash == token_hash,
            AuthSession.revoked_at.is_(None),
            AuthSession.expires_at > utcnow(),
        )
    )
    result = db.execute(stmt).first()
    if result is None:
        return None
    session_obj, user = result
    return AuthContext(user=user, session=session_obj, raw_token=raw_token)


def current_auth(
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings_dep),
) -> AuthContext:
    auth = _resolve_auth_context(db, settings, request.cookies.get(settings.session_cookie_name))
    if auth is None or not auth.user.is_active:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")
    return auth


def current_user(auth: AuthContext = Depends(current_auth)) -> AuthUser:
    return auth.user


def require_admin(auth: AuthContext = Depends(current_auth)) -> AuthContext:
    roles = {role.lower() for role in auth.user.roles}
    if "admin" not in roles and "owner" not in roles:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin role required")
    return auth


def require_owner(auth: AuthContext = Depends(current_auth)) -> AuthContext:
    roles = {role.lower() for role in auth.user.roles}
    if "owner" not in roles:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Owner role required")
    return auth
