from __future__ import annotations

from fastapi import APIRouter, Depends, Request, Response, status
from sqlalchemy.orm import Session

from ..core.config import Settings
from ..deps import get_db, get_settings_dep, require_csrf_protection
from ..schemas import SetupOwnerRequest, SetupStatusResponse, UserPublic
from ..services import create_initial_owner, create_session_for_user, log_event, set_session_cookie, setup_status

router = APIRouter(prefix="/setup", tags=["setup"], dependencies=[Depends(require_csrf_protection)])


@router.get("/status", response_model=SetupStatusResponse)
def get_setup_status(db: Session = Depends(get_db)) -> SetupStatusResponse:
    needs_setup, has_owner = setup_status(db)
    return SetupStatusResponse(needs_setup=needs_setup, has_owner=has_owner)


@router.post("/owner", response_model=UserPublic, status_code=status.HTTP_201_CREATED)
def create_owner(
    payload: SetupOwnerRequest,
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings_dep),
) -> UserPublic:
    user = create_initial_owner(
        db,
        email=str(payload.email),
        username=payload.username,
        display_name=payload.display_name,
        password=payload.password,
        settings=settings,
    )
    _, raw_token = create_session_for_user(db, user=user, request=request, settings=settings)
    log_event(
        db,
        event_type="setup.owner_session_started",
        actor_user_id=user.id,
        target_user_id=user.id,
        request=request,
    )
    db.commit()
    set_session_cookie(response, settings, raw_token)
    return UserPublic.model_validate(user)
