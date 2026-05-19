from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..core.config import Settings
from ..deps import AuthContext, get_db, get_settings_dep, require_admin, require_csrf_protection
from ..models import AuthUser
from ..schemas import (
    AdminCreateUserRequest,
    AdminResetPasswordRequest,
    AdminUpdateUserRequest,
    AdminUserDetailPublic,
    StatusResponse,
    UserPublic,
)
from ..services import (
    UNSET,
    admin_reset_password,
    admin_set_user_enabled,
    create_admin_user,
    ensure_user_details,
    get_user_or_404,
    log_event,
    update_admin_user,
    update_user_contact,
    update_user_preferences,
    update_user_profile,
)

router = APIRouter(prefix="/admin", tags=["admin"], dependencies=[Depends(require_csrf_protection)])


@router.get("/users", response_model=list[UserPublic])
def list_users(
    db: Session = Depends(get_db),
    _: AuthContext = Depends(require_admin),
) -> list[UserPublic]:
    users = list(db.scalars(select(AuthUser).order_by(AuthUser.created_at.asc())))
    return [UserPublic.model_validate(user) for user in users]


@router.post("/users", response_model=UserPublic, status_code=status.HTTP_201_CREATED)
def create_user(
    payload: AdminCreateUserRequest,
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings_dep),
    auth: AuthContext = Depends(require_admin),
) -> UserPublic:
    actor_roles = {role.lower() for role in auth.user.roles}
    if "owner" in {role.lower() for role in payload.roles} and "owner" not in actor_roles:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Only an owner can assign the owner role")
    user = create_admin_user(
        db,
        email=str(payload.email),
        username=payload.username,
        display_name=payload.display_name,
        password=payload.password,
        roles=payload.roles,
        is_active=payload.is_active,
        is_verified=payload.is_verified,
        settings=settings,
    )
    log_event(
        db,
        event_type="admin.user_created",
        actor_user_id=auth.user.id,
        target_user_id=user.id,
        request=request,
        metadata={"roles": user.roles},
    )
    db.commit()
    return UserPublic.model_validate(user)


@router.get("/users/{user_id}", response_model=AdminUserDetailPublic)
def get_user(
    user_id: int,
    db: Session = Depends(get_db),
    _: AuthContext = Depends(require_admin),
) -> AdminUserDetailPublic:
    user = get_user_or_404(db, user_id)
    if ensure_user_details(db, user):
        db.commit()
    return AdminUserDetailPublic.model_validate(user)


@router.patch("/users/{user_id}", response_model=AdminUserDetailPublic)
def patch_user(
    user_id: int,
    payload: AdminUpdateUserRequest,
    request: Request,
    db: Session = Depends(get_db),
    auth: AuthContext = Depends(require_admin),
) -> AdminUserDetailPublic:
    payload_data = payload.model_dump(exclude_unset=True)
    user = get_user_or_404(db, user_id)
    updated = update_admin_user(
        db,
        actor=auth.user,
        target=user,
        email=str(payload_data["email"]) if "email" in payload_data else None,
        username=payload_data.get("username"),
        display_name=payload_data["display_name"] if "display_name" in payload_data else UNSET,
        roles=payload_data.get("roles"),
        is_active=payload_data.get("is_active"),
        is_verified=payload_data.get("is_verified"),
    )

    if payload.profile is not None:
        profile_data = payload.profile.model_dump(exclude_unset=True)
        update_user_profile(
            db,
            user=updated,
            bio=profile_data["bio"] if "bio" in profile_data else UNSET,
            locale=profile_data["locale"] if "locale" in profile_data else UNSET,
            timezone=profile_data["timezone"] if "timezone" in profile_data else UNSET,
        )
    if payload.contact is not None:
        contact_data = payload.contact.model_dump(exclude_unset=True)
        update_user_contact(
            db,
            user=updated,
            phone=contact_data["phone"] if "phone" in contact_data else UNSET,
            website=contact_data["website"] if "website" in contact_data else UNSET,
            social_links=contact_data["social_links"] if "social_links" in contact_data else UNSET,
        )
    if payload.preferences is not None:
        preference_data = payload.preferences.model_dump(exclude_unset=True)
        update_user_preferences(
            db,
            user=updated,
            theme=preference_data["theme"] if "theme" in preference_data else UNSET,
            language=preference_data["language"] if "language" in preference_data else UNSET,
            notification_settings=preference_data["notification_settings"] if "notification_settings" in preference_data else UNSET,
        )

    log_event(
        db,
        event_type="admin.user_updated",
        actor_user_id=auth.user.id,
        target_user_id=updated.id,
        request=request,
    )
    db.commit()
    return AdminUserDetailPublic.model_validate(updated)


@router.post("/users/{user_id}/reset-password", response_model=StatusResponse)
def reset_password(
    user_id: int,
    payload: AdminResetPasswordRequest,
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings_dep),
    auth: AuthContext = Depends(require_admin),
) -> StatusResponse:
    user = get_user_or_404(db, user_id)
    admin_reset_password(
        db,
        actor=auth.user,
        target=user,
        new_password=payload.new_password,
        settings=settings,
    )
    log_event(
        db,
        event_type="admin.user_password_reset",
        actor_user_id=auth.user.id,
        target_user_id=user.id,
        request=request,
    )
    db.commit()
    return StatusResponse()


@router.post("/users/{user_id}/disable", response_model=UserPublic)
def disable_user(
    user_id: int,
    request: Request,
    db: Session = Depends(get_db),
    auth: AuthContext = Depends(require_admin),
) -> UserPublic:
    user = admin_set_user_enabled(
        db,
        actor=auth.user,
        target=get_user_or_404(db, user_id),
        enabled=False,
    )
    log_event(
        db,
        event_type="admin.user_disabled",
        actor_user_id=auth.user.id,
        target_user_id=user.id,
        request=request,
    )
    db.commit()
    return UserPublic.model_validate(user)


@router.post("/users/{user_id}/enable", response_model=UserPublic)
def enable_user(
    user_id: int,
    request: Request,
    db: Session = Depends(get_db),
    auth: AuthContext = Depends(require_admin),
) -> UserPublic:
    user = admin_set_user_enabled(
        db,
        actor=auth.user,
        target=get_user_or_404(db, user_id),
        enabled=True,
    )
    log_event(
        db,
        event_type="admin.user_enabled",
        actor_user_id=auth.user.id,
        target_user_id=user.id,
        request=request,
    )
    db.commit()
    return UserPublic.model_validate(user)
