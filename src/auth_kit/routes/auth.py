from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, File, Request, Response, UploadFile, status
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session

from ..core.config import Settings
from ..deps import AuthContext, current_auth, get_db, get_settings_dep
from ..errors import ApiError
from ..models import AuthSession
from ..schemas import (
    AuthMePublic,
    ChangePasswordRequest,
    LoginRequest,
    RegisterRequest,
    SessionPublic,
    StatusResponse,
    UserAddressCreateRequest,
    UserAddressPatchRequest,
    UserAddressPublic,
    UserContactPatchRequest,
    UserContactPublic,
    UserPreferencesPatchRequest,
    UserPreferencesPublic,
    UserProfilePatchRequest,
    UserProfilePublic,
    UserPublic,
    UserSecurityPatchRequest,
    UserSecurityPublic,
)
from ..services import (
    UNSET,
    authenticate_user,
    avatar_media_type,
    avatar_storage_path,
    change_user_password,
    clear_session_cookie,
    create_session_for_user,
    create_user_address,
    delete_user_address,
    ensure_user_details,
    get_avatar_profile_or_404,
    get_profile_avatar_or_404,
    get_user_address_or_404,
    list_active_sessions_for_user,
    list_user_addresses,
    log_event,
    register_user,
    revoke_session,
    set_session_cookie,
    store_user_avatar,
    update_user_address,
    update_user_contact,
    update_user_preferences,
    update_user_profile,
    update_user_security,
)

router = APIRouter(prefix="/auth", tags=["auth"])


def _session_to_public(session: AuthSession, *, current_session_id: UUID) -> SessionPublic:
    return SessionPublic(
        id=session.id,
        created_at=session.created_at,
        updated_at=session.updated_at,
        expires_at=session.expires_at,
        revoked_at=session.revoked_at,
        user_agent=session.user_agent,
        ip_address=session.ip_address,
        is_current=session.id == current_session_id,
    )


@router.post("/register", response_model=UserPublic, status_code=status.HTTP_201_CREATED)
def register(
    payload: RegisterRequest,
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings_dep),
) -> UserPublic:
    user = register_user(
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
        event_type="auth.register",
        actor_user_id=user.id,
        target_user_id=user.id,
        request=request,
        metadata={"username": user.username},
    )
    db.commit()
    set_session_cookie(response, settings, raw_token)
    return UserPublic.model_validate(user)


@router.post("/login", response_model=UserPublic)
def login(
    payload: LoginRequest,
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings_dep),
) -> UserPublic:
    user = authenticate_user(db, identifier=payload.identifier, password=payload.password)
    _, raw_token = create_session_for_user(db, user=user, request=request, settings=settings)
    log_event(
        db,
        event_type="auth.login",
        actor_user_id=user.id,
        target_user_id=user.id,
        request=request,
    )
    db.commit()
    set_session_cookie(response, settings, raw_token)
    return UserPublic.model_validate(user)


@router.post("/logout", response_model=StatusResponse)
def logout(
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings_dep),
) -> StatusResponse:
    raw_token = request.cookies.get(settings.session_cookie_name)
    if raw_token:
        from ..deps import _resolve_auth_context

        auth = _resolve_auth_context(db, settings, raw_token)
        if auth is not None:
            revoke_session(auth.session)
            log_event(
                db,
                event_type="auth.logout",
                actor_user_id=auth.user.id,
                target_user_id=auth.user.id,
                request=request,
            )
            db.commit()
    clear_session_cookie(response, settings)
    return StatusResponse()


@router.get("/me", response_model=AuthMePublic)
def me(auth: AuthContext = Depends(current_auth), db: Session = Depends(get_db)) -> AuthMePublic:
    if ensure_user_details(db, auth.user):
        db.commit()
    return AuthMePublic.model_validate(auth.user)


@router.post("/change-password", response_model=StatusResponse)
def change_password(
    payload: ChangePasswordRequest,
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings_dep),
    auth: AuthContext = Depends(current_auth),
) -> StatusResponse:
    change_user_password(
        db,
        user=auth.user,
        current_password=payload.current_password,
        new_password=payload.new_password,
        current_session_id=auth.session.id,
        settings=settings,
    )
    log_event(
        db,
        event_type="auth.password_changed",
        actor_user_id=auth.user.id,
        target_user_id=auth.user.id,
        request=request,
    )
    db.commit()
    return StatusResponse()


@router.get("/sessions", response_model=list[SessionPublic])
def sessions(auth: AuthContext = Depends(current_auth), db: Session = Depends(get_db)) -> list[SessionPublic]:
    active_sessions = list_active_sessions_for_user(db, auth.user.id)
    return [_session_to_public(session, current_session_id=auth.session.id) for session in active_sessions]


@router.get("/profile", response_model=UserProfilePublic)
def get_profile(auth: AuthContext = Depends(current_auth), db: Session = Depends(get_db)) -> UserProfilePublic:
    if ensure_user_details(db, auth.user):
        db.commit()
    assert auth.user.profile is not None
    return UserProfilePublic.model_validate(auth.user.profile)


@router.patch("/profile", response_model=UserProfilePublic)
def patch_profile(
    payload: UserProfilePatchRequest,
    request: Request,
    db: Session = Depends(get_db),
    auth: AuthContext = Depends(current_auth),
) -> UserProfilePublic:
    payload_data = payload.model_dump(exclude_unset=True)
    profile = update_user_profile(
        db,
        user=auth.user,
        bio=payload_data["bio"] if "bio" in payload_data else UNSET,
        locale=payload_data["locale"] if "locale" in payload_data else UNSET,
        timezone=payload_data["timezone"] if "timezone" in payload_data else UNSET,
    )
    log_event(
        db,
        event_type="auth.profile_updated",
        actor_user_id=auth.user.id,
        target_user_id=auth.user.id,
        request=request,
    )
    db.commit()
    return UserProfilePublic.model_validate(profile)


@router.get("/profile/avatar")
def get_current_avatar(
    auth: AuthContext = Depends(current_auth),
    settings: Settings = Depends(get_settings_dep),
) -> FileResponse:
    profile = get_profile_avatar_or_404(auth.user)
    storage_key = profile.avatar_storage_key
    assert storage_key is not None
    file_path = avatar_storage_path(settings, storage_key)
    if not file_path.is_file():
        raise ApiError(status_code=404, error_code="avatar_not_found", message="Avatar not found.")
    return FileResponse(file_path, media_type=avatar_media_type(storage_key))


@router.post("/profile/avatar", response_model=UserProfilePublic, status_code=status.HTTP_201_CREATED)
async def upload_avatar(
    request: Request,
    avatar: UploadFile = File(...),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings_dep),
    auth: AuthContext = Depends(current_auth),
) -> UserProfilePublic:
    contents = await avatar.read()
    profile = store_user_avatar(
        db,
        user=auth.user,
        content_type=avatar.content_type,
        contents=contents,
        settings=settings,
    )
    log_event(
        db,
        event_type="auth.avatar_uploaded",
        actor_user_id=auth.user.id,
        target_user_id=auth.user.id,
        request=request,
        metadata={"content_type": avatar.content_type or "unknown"},
    )
    db.commit()
    return UserProfilePublic.model_validate(profile)


@router.get("/avatars/{avatar_id}")
def get_avatar_by_id(
    avatar_id: str,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings_dep),
) -> FileResponse:
    profile = get_avatar_profile_or_404(db, avatar_id)
    storage_key = profile.avatar_storage_key
    assert storage_key is not None
    file_path = avatar_storage_path(settings, storage_key)
    if not file_path.is_file():
        raise ApiError(status_code=404, error_code="avatar_not_found", message="Avatar not found.")
    return FileResponse(file_path, media_type=avatar_media_type(storage_key))


@router.get("/addresses", response_model=list[UserAddressPublic])
def get_addresses(auth: AuthContext = Depends(current_auth), db: Session = Depends(get_db)) -> list[UserAddressPublic]:
    return [UserAddressPublic.model_validate(address) for address in list_user_addresses(db, auth.user.id)]


@router.post("/addresses", response_model=UserAddressPublic, status_code=status.HTTP_201_CREATED)
def post_address(
    payload: UserAddressCreateRequest,
    request: Request,
    db: Session = Depends(get_db),
    auth: AuthContext = Depends(current_auth),
) -> UserAddressPublic:
    address = create_user_address(
        db,
        user=auth.user,
        type=payload.type,
        name=payload.name,
        street_line_1=payload.street_line_1,
        street_line_2=payload.street_line_2,
        postal_code=payload.postal_code,
        city=payload.city,
        state=payload.state,
        country=payload.country,
        is_default=payload.is_default,
    )
    log_event(
        db,
        event_type="auth.address_created",
        actor_user_id=auth.user.id,
        target_user_id=auth.user.id,
        request=request,
        metadata={"address_id": address.id},
    )
    db.commit()
    return UserAddressPublic.model_validate(address)


@router.patch("/addresses/{address_id}", response_model=UserAddressPublic)
def patch_address(
    address_id: int,
    payload: UserAddressPatchRequest,
    request: Request,
    db: Session = Depends(get_db),
    auth: AuthContext = Depends(current_auth),
) -> UserAddressPublic:
    payload_data = payload.model_dump(exclude_unset=True)
    address = get_user_address_or_404(db, user_id=auth.user.id, address_id=address_id)
    updated = update_user_address(
        db,
        address=address,
        type=payload_data["type"] if "type" in payload_data else UNSET,
        name=payload_data["name"] if "name" in payload_data else UNSET,
        street_line_1=payload_data["street_line_1"] if "street_line_1" in payload_data else UNSET,
        street_line_2=payload_data["street_line_2"] if "street_line_2" in payload_data else UNSET,
        postal_code=payload_data["postal_code"] if "postal_code" in payload_data else UNSET,
        city=payload_data["city"] if "city" in payload_data else UNSET,
        state=payload_data["state"] if "state" in payload_data else UNSET,
        country=payload_data["country"] if "country" in payload_data else UNSET,
        is_default=payload_data["is_default"] if "is_default" in payload_data else UNSET,
    )
    log_event(
        db,
        event_type="auth.address_updated",
        actor_user_id=auth.user.id,
        target_user_id=auth.user.id,
        request=request,
        metadata={"address_id": updated.id},
    )
    db.commit()
    return UserAddressPublic.model_validate(updated)


@router.delete("/addresses/{address_id}", status_code=status.HTTP_204_NO_CONTENT)
def remove_address(
    address_id: int,
    request: Request,
    db: Session = Depends(get_db),
    auth: AuthContext = Depends(current_auth),
) -> Response:
    address = get_user_address_or_404(db, user_id=auth.user.id, address_id=address_id)
    delete_user_address(db, address=address)
    log_event(
        db,
        event_type="auth.address_deleted",
        actor_user_id=auth.user.id,
        target_user_id=auth.user.id,
        request=request,
        metadata={"address_id": address_id},
    )
    db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get("/contact", response_model=UserContactPublic)
def get_contact(auth: AuthContext = Depends(current_auth), db: Session = Depends(get_db)) -> UserContactPublic:
    if ensure_user_details(db, auth.user):
        db.commit()
    assert auth.user.contact is not None
    return UserContactPublic.model_validate(auth.user.contact)


@router.patch("/contact", response_model=UserContactPublic)
def patch_contact(
    payload: UserContactPatchRequest,
    request: Request,
    db: Session = Depends(get_db),
    auth: AuthContext = Depends(current_auth),
) -> UserContactPublic:
    payload_data = payload.model_dump(exclude_unset=True)
    contact = update_user_contact(
        db,
        user=auth.user,
        phone=payload_data["phone"] if "phone" in payload_data else UNSET,
        website=payload_data["website"] if "website" in payload_data else UNSET,
        social_links=payload_data["social_links"] if "social_links" in payload_data else UNSET,
    )
    log_event(
        db,
        event_type="auth.contact_updated",
        actor_user_id=auth.user.id,
        target_user_id=auth.user.id,
        request=request,
    )
    db.commit()
    return UserContactPublic.model_validate(contact)


@router.get("/preferences", response_model=UserPreferencesPublic)
def get_preferences(auth: AuthContext = Depends(current_auth), db: Session = Depends(get_db)) -> UserPreferencesPublic:
    if ensure_user_details(db, auth.user):
        db.commit()
    assert auth.user.preferences is not None
    return UserPreferencesPublic.model_validate(auth.user.preferences)


@router.patch("/preferences", response_model=UserPreferencesPublic)
def patch_preferences(
    payload: UserPreferencesPatchRequest,
    request: Request,
    db: Session = Depends(get_db),
    auth: AuthContext = Depends(current_auth),
) -> UserPreferencesPublic:
    payload_data = payload.model_dump(exclude_unset=True)
    preferences = update_user_preferences(
        db,
        user=auth.user,
        theme=payload_data["theme"] if "theme" in payload_data else UNSET,
        language=payload_data["language"] if "language" in payload_data else UNSET,
        notification_settings=payload_data["notification_settings"] if "notification_settings" in payload_data else UNSET,
    )
    log_event(
        db,
        event_type="auth.preferences_updated",
        actor_user_id=auth.user.id,
        target_user_id=auth.user.id,
        request=request,
    )
    db.commit()
    return UserPreferencesPublic.model_validate(preferences)


@router.get("/security", response_model=UserSecurityPublic)
def get_security(auth: AuthContext = Depends(current_auth), db: Session = Depends(get_db)) -> UserSecurityPublic:
    if ensure_user_details(db, auth.user):
        db.commit()
    assert auth.user.security is not None
    return UserSecurityPublic.model_validate(auth.user.security)


@router.patch("/security", response_model=UserSecurityPublic)
def patch_security(
    payload: UserSecurityPatchRequest,
    request: Request,
    db: Session = Depends(get_db),
    auth: AuthContext = Depends(current_auth),
) -> UserSecurityPublic:
    payload_data = payload.model_dump(exclude_unset=True)
    security = update_user_security(
        db,
        user=auth.user,
        two_factor_enabled=payload_data["two_factor_enabled"] if "two_factor_enabled" in payload_data else UNSET,
        passkeys_enabled=payload_data["passkeys_enabled"] if "passkeys_enabled" in payload_data else UNSET,
        recovery_codes_enabled=payload_data["recovery_codes_enabled"] if "recovery_codes_enabled" in payload_data else UNSET,
        trusted_devices_enabled=payload_data["trusted_devices_enabled"] if "trusted_devices_enabled" in payload_data else UNSET,
    )
    log_event(
        db,
        event_type="auth.security_updated",
        actor_user_id=auth.user.id,
        target_user_id=auth.user.id,
        request=request,
    )
    db.commit()
    return UserSecurityPublic.model_validate(security)


@router.delete("/sessions/{session_id}", status_code=status.HTTP_204_NO_CONTENT)
def revoke_named_session(
    session_id: UUID,
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings_dep),
    auth: AuthContext = Depends(current_auth),
) -> Response:
    session = db.get(AuthSession, session_id)
    if session is None or session.user_id != auth.user.id:
        return Response(status_code=status.HTTP_404_NOT_FOUND)
    revoke_session(session)
    log_event(
        db,
        event_type="auth.session_revoked",
        actor_user_id=auth.user.id,
        target_user_id=auth.user.id,
        request=request,
        metadata={"session_id": str(session.id)},
    )
    db.commit()
    if session.id == auth.session.id:
        clear_session_cookie(response, settings)
    response.status_code = status.HTTP_204_NO_CONTENT
    return response


@router.delete("/sessions/current", status_code=status.HTTP_204_NO_CONTENT)
def revoke_current_session(
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings_dep),
    auth: AuthContext = Depends(current_auth),
) -> Response:
    revoke_session(auth.session)
    log_event(
        db,
        event_type="auth.session_revoked",
        actor_user_id=auth.user.id,
        target_user_id=auth.user.id,
        request=request,
        metadata={"session_id": str(auth.session.id)},
    )
    db.commit()
    clear_session_cookie(response, settings)
    response.status_code = status.HTTP_204_NO_CONTENT
    return response
