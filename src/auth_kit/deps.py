from __future__ import annotations

from collections.abc import Generator
from dataclasses import dataclass

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from .core.config import Settings
from .db import utcnow
from .models import AuthSession, AuthUser
from .rate_limit import InMemoryRateLimiter
from .security import hash_session_token
from .services import get_client_ip, log_event


@dataclass(frozen=True)
class AuthContext:
    user: AuthUser
    session: AuthSession
    raw_token: str


def get_settings_dep(request: Request) -> Settings:
    return request.app.state.settings


def get_session_factory(request: Request) -> sessionmaker[Session]:
    return request.app.state.session_factory


def get_rate_limiter(request: Request) -> InMemoryRateLimiter:
    return request.app.state.rate_limiter


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


def require_csrf_protection(
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings_dep),
) -> None:
    if request.method in {"GET", "HEAD", "OPTIONS"}:
        return
    csrf_cookie = request.cookies.get(settings.csrf_cookie_name)
    csrf_header = request.headers.get(settings.csrf_header_name)
    if csrf_cookie and csrf_header and csrf_cookie == csrf_header:
        return
    log_event(
        db,
        event_type="security.csrf_rejected",
        request=request,
        metadata={"path": request.url.path},
    )
    db.commit()
    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail={"error_code": "csrf_invalid", "message": "CSRF validation failed."},
    )


def _enforce_rate_limit(
    *,
    action: str,
    limit: int,
    request: Request,
    db: Session,
    settings: Settings,
    rate_limiter: InMemoryRateLimiter,
) -> None:
    client_ip = get_client_ip(request) or "unknown"
    allowed = rate_limiter.allow(
        f"{action}:{client_ip}",
        limit=limit,
        window_seconds=settings.rate_limit_window_seconds,
    )
    if allowed:
        return
    log_event(
        db,
        event_type="security.rate_limit_exceeded",
        request=request,
        metadata={"action": action, "path": request.url.path, "ip_address": client_ip},
    )
    db.commit()
    raise HTTPException(
        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
        detail={"error_code": "rate_limit_exceeded", "message": "Too many requests. Please try again later."},
    )


def limit_login_requests(
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings_dep),
    rate_limiter: InMemoryRateLimiter = Depends(get_rate_limiter),
) -> None:
    _enforce_rate_limit(
        action="login",
        limit=settings.rate_limit_login,
        request=request,
        db=db,
        settings=settings,
        rate_limiter=rate_limiter,
    )


def limit_register_requests(
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings_dep),
    rate_limiter: InMemoryRateLimiter = Depends(get_rate_limiter),
) -> None:
    _enforce_rate_limit(
        action="register",
        limit=settings.rate_limit_register,
        request=request,
        db=db,
        settings=settings,
        rate_limiter=rate_limiter,
    )


def limit_forgot_password_requests(
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings_dep),
    rate_limiter: InMemoryRateLimiter = Depends(get_rate_limiter),
) -> None:
    _enforce_rate_limit(
        action="forgot_password",
        limit=settings.rate_limit_forgot_password,
        request=request,
        db=db,
        settings=settings,
        rate_limiter=rate_limiter,
    )


def limit_reset_password_requests(
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings_dep),
    rate_limiter: InMemoryRateLimiter = Depends(get_rate_limiter),
) -> None:
    _enforce_rate_limit(
        action="reset_password",
        limit=settings.rate_limit_reset_password,
        request=request,
        db=db,
        settings=settings,
        rate_limiter=rate_limiter,
    )


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
