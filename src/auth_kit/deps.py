from __future__ import annotations

from uuid import UUID

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy.engine import Engine

from .models import User
from .sessions import get_user_by_session
from .settings import Settings


def get_engine(request: Request) -> Engine:
    engine = request.app.state.db_engine
    return engine


def get_settings_dep(request: Request) -> Settings:
    return request.app.state.auth_settings


def current_user(
    request: Request,
    engine: Engine = Depends(get_engine),
    settings: Settings = Depends(get_settings_dep),
) -> User:
    raw = request.cookies.get(settings.session_cookie_name)
    if not raw:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")
    try:
        sid = UUID(raw)
    except Exception:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid session")
    user = get_user_by_session(engine, sid)
    if not user or not user.is_active:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")
    return user
