from __future__ import annotations

import logging
from uuid import UUID

from fastapi import APIRouter, Depends, File, Request, Response, UploadFile, status
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session

from ..core.config import Settings
from ..deps import (
    AuthContext,
    current_auth,
    get_db,
    get_settings_dep,
    limit_forgot_password_requests,
    limit_login_requests,
    limit_register_requests,
    limit_reset_password_requests,
    require_csrf_protection,
)
from ..errors import ApiError
from ..models import AuthSession
from ..security import hash_trusted_device_token
from ..schemas import (
    AuthMePublic,
    ChangePasswordRequest,
    CsrfTokenResponse,
    DisableTwoFactorRequest,
    EnableTwoFactorRequest,
    ForgotPasswordRequest,
    LoginTwoFactorRequiredResponse,
    LoginRequest,
    RecoveryCodesResponse,
    RegisterRequest,
    RegenerateRecoveryCodesRequest,
    ResetPasswordRequest,
    SessionPublic,
    StatusMessageResponse,
    StatusResponse,
    TrustedDevicePublic,
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
    TwoFactorSetupResponse,
    VerifyTwoFactorLoginRequest,
)
from ..services import (
    LOGIN_CHALLENGE_COOKIE_NAME,
    UNSET,
    authenticate_user,
    avatar_media_type,
    avatar_storage_path,
    change_user_password,
    clear_csrf_cookie,
    clear_login_challenges,
    clear_login_challenge_cookie,
    clear_session_cookie,
    clear_trusted_device_cookie,
    create_password_reset_token,
    create_session_for_user,
    create_user_address,
    create_login_challenge,
    create_trusted_device,
    delete_user_address,
    deliver_password_reset_email,
    disable_two_factor,
    enable_two_factor,
    ensure_user_details,
    get_avatar_profile_or_404,
    get_profile_avatar_or_404,
    get_trusted_device_or_404,
    get_user_address_or_404,
    get_user_by_email,
    issue_csrf_token,
    list_active_sessions_for_user,
    list_active_trusted_devices_for_user,
    list_user_addresses,
    log_event,
    mark_user_logged_in,
    register_user,
    regenerate_recovery_codes,
    resolve_login_challenge,
    resolve_trusted_device,
    reset_password_with_token,
    revoke_session,
    revoke_trusted_device,
    set_session_cookie,
    set_login_challenge_cookie,
    set_trusted_device_cookie,
    start_two_factor_setup,
    store_user_avatar,
    sync_user_security_state,
    user_security_payload,
    update_user_address,
    update_user_contact,
    update_user_preferences,
    update_user_profile,
    update_user_security,
    verify_two_factor_code_for_user,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/auth", tags=["auth"], dependencies=[Depends(require_csrf_protection)])


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


def _security_to_public(auth: AuthContext) -> UserSecurityPublic:
    return UserSecurityPublic.model_validate(user_security_payload(auth.user))


def _trusted_device_to_public(
    device,
    *,
    current_trusted_device_hash: str | None,
) -> TrustedDevicePublic:
    return TrustedDevicePublic.model_validate(
        {
            "id": device.id,
            "device_label": device.device_label,
            "user_agent": device.user_agent,
            "ip_address": device.ip_address,
            "created_at": device.created_at,
            "updated_at": device.updated_at,
            "last_used_at": device.last_used_at,
            "expires_at": device.expires_at,
            "revoked_at": device.revoked_at,
            "is_current": current_trusted_device_hash == device.token_hash,
        }
    )


@router.get("/csrf", response_model=CsrfTokenResponse)
def get_csrf_token(response: Response, settings: Settings = Depends(get_settings_dep)) -> CsrfTokenResponse:
    return CsrfTokenResponse(csrf_token=issue_csrf_token(response, settings))


@router.post("/register", response_model=UserPublic, status_code=status.HTTP_201_CREATED, dependencies=[Depends(limit_register_requests)])
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
    mark_user_logged_in(user)
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


@router.post("/login", response_model=UserPublic | LoginTwoFactorRequiredResponse, dependencies=[Depends(limit_login_requests)])
def login(
    payload: LoginRequest,
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings_dep),
) -> UserPublic | LoginTwoFactorRequiredResponse:
    try:
        user = authenticate_user(db, identifier=payload.identifier, password=payload.password)
    except ApiError:
        log_event(
            db,
            event_type="auth.login_failed",
            request=request,
            metadata={"identifier": payload.identifier.strip().lower()},
        )
        db.commit()
        raise

    sync_user_security_state(db, user)
    trusted_device = None
    raw_trusted_device_cookie = request.cookies.get(settings.trusted_device_cookie_name)
    if user.security is not None and user.security.two_factor_enabled:
        trusted_device = resolve_trusted_device(
            db,
            user_id=user.id,
            raw_token=raw_trusted_device_cookie,
        )
        if trusted_device is None:
            challenge, raw_challenge = create_login_challenge(db, user=user, request=request, settings=settings)
            log_event(
                db,
                event_type="auth.login_two_factor_challenge_created",
                actor_user_id=user.id,
                target_user_id=user.id,
                request=request,
            )
            db.commit()
            if raw_trusted_device_cookie:
                clear_trusted_device_cookie(response, settings)
            set_login_challenge_cookie(response, settings, raw_challenge)
            response.status_code = status.HTTP_202_ACCEPTED
            return LoginTwoFactorRequiredResponse(
                message="Two-factor authentication is required to complete sign-in.",
                challenge_expires_at=challenge.expires_at,
            )

    raw_cookie = request.cookies.get(settings.session_cookie_name)
    if raw_cookie:
        from ..deps import _resolve_auth_context

        current_auth_context = _resolve_auth_context(db, settings, raw_cookie)
        if current_auth_context is not None:
            revoke_session(current_auth_context.session)

    mark_user_logged_in(user)
    _, raw_token = create_session_for_user(db, user=user, request=request, settings=settings)
    log_event(
        db,
        event_type="auth.login",
        actor_user_id=user.id,
        target_user_id=user.id,
        request=request,
        metadata={"second_factor_method": "trusted_device" if trusted_device is not None else "password_only"},
    )
    db.commit()
    clear_login_challenge_cookie(response, settings)
    set_session_cookie(response, settings, raw_token)
    return UserPublic.model_validate(user)


@router.post("/login/verify-2fa", response_model=UserPublic, dependencies=[Depends(limit_login_requests)])
def verify_login_two_factor(
    payload: VerifyTwoFactorLoginRequest,
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings_dep),
) -> UserPublic:
    challenge = resolve_login_challenge(db, raw_token=request.cookies.get(LOGIN_CHALLENGE_COOKIE_NAME))
    if challenge is None:
        raise ApiError(
            status_code=400,
            error_code="login_challenge_invalid",
            message="Login challenge is missing or expired.",
        )

    user = challenge.user
    if not user.is_active:
        raise ApiError(status_code=403, error_code="user_disabled", message="User is disabled.")

    try:
        second_factor_method = verify_two_factor_code_for_user(db, user=user, code=payload.code, settings=settings)
    except ApiError:
        log_event(
            db,
            event_type="auth.login_two_factor_failed",
            actor_user_id=user.id,
            target_user_id=user.id,
            request=request,
        )
        db.commit()
        raise

    raw_cookie = request.cookies.get(settings.session_cookie_name)
    if raw_cookie:
        from ..deps import _resolve_auth_context

        current_auth_context = _resolve_auth_context(db, settings, raw_cookie)
        if current_auth_context is not None:
            revoke_session(current_auth_context.session)

    mark_user_logged_in(user)
    _, raw_token = create_session_for_user(db, user=user, request=request, settings=settings)
    trusted_device_token: str | None = None
    if payload.trust_device:
        _, trusted_device_token = create_trusted_device(
            db,
            user=user,
            request=request,
            settings=settings,
            device_label=payload.device_label,
        )
    log_event(
        db,
        event_type="auth.login",
        actor_user_id=user.id,
        target_user_id=user.id,
        request=request,
        metadata={"second_factor_method": second_factor_method},
    )
    if trusted_device_token is not None:
        log_event(
            db,
            event_type="auth.trusted_device_registered",
            actor_user_id=user.id,
            target_user_id=user.id,
            request=request,
        )
    clear_login_challenges(db, user_id=user.id)
    sync_user_security_state(db, user)
    db.commit()
    clear_login_challenge_cookie(response, settings)
    set_session_cookie(response, settings, raw_token)
    if trusted_device_token is not None:
        set_trusted_device_cookie(response, settings, trusted_device_token)
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
    clear_csrf_cookie(response, settings)
    clear_login_challenge_cookie(response, settings)
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


@router.post(
    "/forgot-password",
    response_model=StatusMessageResponse,
    dependencies=[Depends(limit_forgot_password_requests)],
)
def forgot_password(
    payload: ForgotPasswordRequest,
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings_dep),
) -> StatusMessageResponse:
    response_message = "If an account exists for that email, reset instructions will be sent."
    user = get_user_by_email(db, str(payload.email))
    if user is None:
        log_event(
            db,
            event_type="auth.password_reset_requested_unknown_email",
            request=request,
            metadata={"email": str(payload.email).strip().lower()},
        )
        db.commit()
        return StatusMessageResponse(message=response_message)

    raw_token = create_password_reset_token(db, user=user, request=request, settings=settings)
    log_event(
        db,
        event_type="auth.password_reset_requested",
        actor_user_id=user.id,
        target_user_id=user.id,
        request=request,
    )
    try:
        deliver_password_reset_email(email=user.email, raw_token=raw_token, settings=settings)
    except Exception as exc:
        logger.exception(
            "[auth-kit] password reset delivery failed for %s using mail_mode=%s",
            user.email,
            settings.mail_mode,
        )
        log_event(
            db,
            event_type="auth.password_reset_delivery_failed",
            actor_user_id=user.id,
            target_user_id=user.id,
            request=request,
            metadata={"error": type(exc).__name__},
        )
        db.commit()
        return StatusMessageResponse(message=response_message)

    db.commit()
    return StatusMessageResponse(message=response_message)


@router.post(
    "/reset-password",
    response_model=StatusMessageResponse,
    dependencies=[Depends(limit_reset_password_requests)],
)
def reset_password(
    payload: ResetPasswordRequest,
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings_dep),
) -> StatusMessageResponse:
    try:
        user = reset_password_with_token(
            db,
            raw_token=payload.token,
            new_password=payload.new_password,
            settings=settings,
        )
    except ApiError:
        log_event(
            db,
            event_type="auth.password_reset_failed",
            request=request,
        )
        db.commit()
        raise

    log_event(
        db,
        event_type="auth.password_reset_completed",
        actor_user_id=user.id,
        target_user_id=user.id,
        request=request,
    )
    db.commit()
    return StatusMessageResponse(message="Password has been reset. You can now sign in.")


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
    sync_user_security_state(db, auth.user)
    db.commit()
    return _security_to_public(auth)


@router.patch("/security", response_model=UserSecurityPublic)
def patch_security(
    payload: UserSecurityPatchRequest,
    request: Request,
    db: Session = Depends(get_db),
    auth: AuthContext = Depends(current_auth),
) -> UserSecurityPublic:
    payload_data = payload.model_dump(exclude_unset=True)
    update_user_security(
        db,
        user=auth.user,
        two_factor_enabled=payload_data["two_factor_enabled"] if "two_factor_enabled" in payload_data else UNSET,
        passkeys_enabled=payload_data["passkeys_enabled"] if "passkeys_enabled" in payload_data else UNSET,
        recovery_codes_enabled=payload_data["recovery_codes_enabled"] if "recovery_codes_enabled" in payload_data else UNSET,
        trusted_devices_enabled=payload_data["trusted_devices_enabled"] if "trusted_devices_enabled" in payload_data else UNSET,
    )
    log_event(
        db,
        event_type="auth.security_update_rejected",
        actor_user_id=auth.user.id,
        target_user_id=auth.user.id,
        request=request,
    )
    db.commit()
    raise ApiError(
        status_code=400,
        error_code="security_preferences_read_only",
        message="Use the dedicated account protection endpoints for security changes.",
    )


@router.post("/security/two-factor/setup", response_model=TwoFactorSetupResponse)
def setup_two_factor(
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings_dep),
    auth: AuthContext = Depends(current_auth),
) -> TwoFactorSetupResponse:
    _, secret, otpauth_uri = start_two_factor_setup(db, user=auth.user, settings=settings)
    log_event(
        db,
        event_type="auth.two_factor_setup_started",
        actor_user_id=auth.user.id,
        target_user_id=auth.user.id,
        request=request,
    )
    db.commit()
    return TwoFactorSetupResponse(
        secret=secret,
        otpauth_uri=otpauth_uri,
        qr_data=otpauth_uri,
        security=_security_to_public(auth),
    )


@router.post("/security/two-factor/enable", response_model=RecoveryCodesResponse)
def enable_two_factor_authentication(
    payload: EnableTwoFactorRequest,
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings_dep),
    auth: AuthContext = Depends(current_auth),
) -> RecoveryCodesResponse:
    _, recovery_codes = enable_two_factor(db, user=auth.user, code=payload.code, settings=settings)
    log_event(
        db,
        event_type="auth.two_factor_enabled",
        actor_user_id=auth.user.id,
        target_user_id=auth.user.id,
        request=request,
    )
    db.commit()
    return RecoveryCodesResponse(
        message="Two-factor authentication has been enabled.",
        recovery_codes=recovery_codes,
        security=_security_to_public(auth),
    )


@router.post("/security/two-factor/disable", response_model=UserSecurityPublic)
def disable_two_factor_authentication(
    payload: DisableTwoFactorRequest,
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings_dep),
    auth: AuthContext = Depends(current_auth),
) -> UserSecurityPublic:
    disable_two_factor(db, user=auth.user, current_password=payload.current_password)
    log_event(
        db,
        event_type="auth.two_factor_disabled",
        actor_user_id=auth.user.id,
        target_user_id=auth.user.id,
        request=request,
    )
    db.commit()
    clear_trusted_device_cookie(response, settings)
    clear_login_challenge_cookie(response, settings)
    return _security_to_public(auth)


@router.post("/security/recovery-codes/regenerate", response_model=RecoveryCodesResponse)
def regenerate_user_recovery_codes(
    payload: RegenerateRecoveryCodesRequest,
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings_dep),
    auth: AuthContext = Depends(current_auth),
) -> RecoveryCodesResponse:
    _, recovery_codes = regenerate_recovery_codes(
        db,
        user=auth.user,
        current_password=payload.current_password,
        settings=settings,
    )
    log_event(
        db,
        event_type="auth.recovery_codes_regenerated",
        actor_user_id=auth.user.id,
        target_user_id=auth.user.id,
        request=request,
    )
    db.commit()
    return RecoveryCodesResponse(
        message="Recovery codes have been regenerated.",
        recovery_codes=recovery_codes,
        security=_security_to_public(auth),
    )


@router.get("/security/trusted-devices", response_model=list[TrustedDevicePublic])
def get_trusted_devices(
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings_dep),
    auth: AuthContext = Depends(current_auth),
) -> list[TrustedDevicePublic]:
    devices = list_active_trusted_devices_for_user(db, auth.user.id)
    current_trusted_device_hash = None
    raw_token = request.cookies.get(settings.trusted_device_cookie_name)
    if raw_token:
        current_trusted_device_hash = hash_trusted_device_token(raw_token)
    sync_user_security_state(db, auth.user)
    db.commit()
    return [
        _trusted_device_to_public(device, current_trusted_device_hash=current_trusted_device_hash)
        for device in devices
    ]


@router.delete("/security/trusted-devices/{device_id}", response_model=StatusMessageResponse)
def revoke_trusted_device_route(
    device_id: UUID,
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings_dep),
    auth: AuthContext = Depends(current_auth),
) -> StatusMessageResponse:
    device = get_trusted_device_or_404(db, user_id=auth.user.id, device_id=device_id)
    revoke_trusted_device(device)
    sync_user_security_state(db, auth.user)
    log_event(
        db,
        event_type="auth.trusted_device_revoked",
        actor_user_id=auth.user.id,
        target_user_id=auth.user.id,
        request=request,
        metadata={"trusted_device_id": str(device.id)},
    )
    db.commit()
    raw_token = request.cookies.get(settings.trusted_device_cookie_name)
    if raw_token and hash_trusted_device_token(raw_token) == device.token_hash:
        clear_trusted_device_cookie(response, settings)
    return StatusMessageResponse(message="Trusted device has been revoked.")


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
        clear_csrf_cookie(response, settings)
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
    clear_csrf_cookie(response, settings)
    response.status_code = status.HTTP_204_NO_CONTENT
    return response
