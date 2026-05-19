from __future__ import annotations

import json
import logging
import smtplib
from datetime import timedelta
from email.message import EmailMessage
from pathlib import Path
from secrets import choice
from string import ascii_lowercase
from typing import Any, TypeGuard
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
from uuid import UUID, uuid4

from fastapi import Request, Response
from sqlalchemy import or_, select
from sqlalchemy.orm import Session, sessionmaker

from .core.config import Settings
from .db import utcnow
from .errors import ApiError
from .models import (
    AuthAuditLog,
    AuthPasswordResetToken,
    AuthSession,
    AuthUser,
    AuthUserAddress,
    AuthUserContact,
    AuthUserPreferences,
    AuthUserProfile,
    AuthUserSecurity,
)
from .security import (
    generate_csrf_token,
    generate_password_reset_token,
    generate_session_token,
    hash_password,
    hash_password_reset_token,
    hash_session_token,
    normalize_email,
    normalize_roles,
    normalize_username,
    validate_password,
    verify_password,
)

logger = logging.getLogger(__name__)


class UnsetType:
    __slots__ = ()


UNSET = UnsetType()
AVATAR_CONTENT_TYPES = {
    "image/png": ".png",
    "image/jpeg": ".jpg",
    "image/webp": ".webp",
}
AVATAR_ROUTE_PREFIX = "/api/auth/avatars/"
LEGACY_AVATAR_ROUTE_PREFIX = "/uploads/avatars/"
AVATAR_CONTENT_TYPES_BY_SUFFIX = {suffix: content_type for content_type, suffix in AVATAR_CONTENT_TYPES.items()}


def is_set[T](value: T | UnsetType) -> TypeGuard[T]:
    return not isinstance(value, UnsetType)


def avatar_max_bytes(settings: Settings) -> int:
    return settings.avatar_max_mb * 1024 * 1024


def build_avatar_public_url(avatar_id: str) -> str:
    return f"{AVATAR_ROUTE_PREFIX}{avatar_id}"


def build_avatar_storage_key() -> tuple[str, str]:
    file_token = "".join(choice(ascii_lowercase) for _ in range(32))
    avatar_id = uuid4().hex
    relative_key = f"avatars/{file_token[:2]}/{file_token[2:4]}/{file_token}"
    return avatar_id, relative_key


def set_session_cookie(response: Response, settings: Settings, raw_token: str) -> None:
    if settings.session_cookie_domain:
        response.set_cookie(
            key=settings.session_cookie_name,
            value=raw_token,
            httponly=True,
            secure=settings.session_cookie_secure,
            samesite=settings.session_cookie_samesite,
            domain=settings.session_cookie_domain,
            max_age=settings.session_ttl_days * 24 * 3600,
            path=settings.session_cookie_path,
        )
        return

    response.set_cookie(
        key=settings.session_cookie_name,
        value=raw_token,
        httponly=True,
        secure=settings.session_cookie_secure,
        samesite=settings.session_cookie_samesite,
        max_age=settings.session_ttl_days * 24 * 3600,
        path=settings.session_cookie_path,
    )


def set_csrf_cookie(response: Response, settings: Settings, csrf_token: str) -> None:
    if settings.session_cookie_domain:
        response.set_cookie(
            key=settings.csrf_cookie_name,
            value=csrf_token,
            httponly=False,
            secure=settings.session_cookie_secure,
            samesite=settings.session_cookie_samesite,
            domain=settings.session_cookie_domain,
            max_age=settings.session_ttl_days * 24 * 3600,
            path=settings.session_cookie_path,
        )
        return

    response.set_cookie(
        key=settings.csrf_cookie_name,
        value=csrf_token,
        httponly=False,
        secure=settings.session_cookie_secure,
        samesite=settings.session_cookie_samesite,
        max_age=settings.session_ttl_days * 24 * 3600,
        path=settings.session_cookie_path,
    )


def issue_csrf_token(response: Response, settings: Settings) -> str:
    csrf_token = generate_csrf_token()
    set_csrf_cookie(response, settings, csrf_token)
    return csrf_token


def clear_session_cookie(response: Response, settings: Settings) -> None:
    if settings.session_cookie_domain:
        response.delete_cookie(
            key=settings.session_cookie_name,
            path=settings.session_cookie_path,
            domain=settings.session_cookie_domain,
        )
        return

    response.delete_cookie(
        key=settings.session_cookie_name,
        path=settings.session_cookie_path,
    )


def clear_csrf_cookie(response: Response, settings: Settings) -> None:
    if settings.session_cookie_domain:
        response.delete_cookie(
            key=settings.csrf_cookie_name,
            path=settings.session_cookie_path,
            domain=settings.session_cookie_domain,
        )
        return

    response.delete_cookie(
        key=settings.csrf_cookie_name,
        path=settings.session_cookie_path,
    )


def get_client_ip(request: Request | None) -> str | None:
    if request is None:
        return None
    forwarded_for = request.headers.get("x-forwarded-for")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    if request.client is not None:
        return request.client.host
    return None


def log_event(
    db: Session,
    *,
    event_type: str,
    actor_user_id: int | None = None,
    target_user_id: int | None = None,
    request: Request | None = None,
    metadata: dict[str, object] | None = None,
) -> None:
    db.add(
        AuthAuditLog(
            actor_user_id=actor_user_id,
            event_type=event_type,
            target_user_id=target_user_id,
            ip_address=get_client_ip(request),
            user_agent=request.headers.get("user-agent") if request else None,
            metadata_json=metadata or {},
        )
    )


def get_user_by_identifier(db: Session, identifier: str) -> AuthUser | None:
    normalized = identifier.strip().lower()
    user = db.scalar(select(AuthUser).where(AuthUser.email == normalized))
    if user is not None:
        return user
    return db.scalar(select(AuthUser).where(AuthUser.username == normalized))


def get_user_by_email(db: Session, email: str) -> AuthUser | None:
    return db.scalar(select(AuthUser).where(AuthUser.email == normalize_email(email)))


def get_user_or_404(db: Session, user_id: int) -> AuthUser:
    user = db.get(AuthUser, user_id)
    if user is None:
        raise ApiError(status_code=404, error_code="user_not_found", message="User not found.")
    return user


def get_user_address_or_404(db: Session, *, user_id: int, address_id: int) -> AuthUserAddress:
    address = db.get(AuthUserAddress, address_id)
    if address is None or address.user_id != user_id:
        raise ApiError(status_code=404, error_code="address_not_found", message="Address not found.")
    return address


def ensure_unique_identity(
    db: Session,
    *,
    email: str,
    username: str,
    exclude_user_id: int | None = None,
) -> None:
    stmt = select(AuthUser).where(
        or_(
            AuthUser.email == email,
            AuthUser.username == username,
            AuthUser.email == username,
            AuthUser.username == email,
        )
    )
    for user in db.scalars(stmt):
        if exclude_user_id is None or user.id != exclude_user_id:
            if user.email in {email, username}:
                raise ApiError(status_code=409, error_code="email_already_exists", message="Email already exists.")
            raise ApiError(status_code=409, error_code="username_already_exists", message="Username already exists.")


def _clean_optional_string(value: str | None) -> str | None:
    if value is None:
        return None
    cleaned = value.strip()
    return cleaned or None


def _clean_required_string(value: str | None, field_name: str) -> str:
    cleaned = _clean_optional_string(value)
    if cleaned is None:
        raise ApiError(status_code=400, error_code="field_required", message=f"{field_name} is required.")
    return cleaned


def initialize_user_details(user: AuthUser) -> None:
    if user.profile is None:
        user.profile = AuthUserProfile()
    if user.contact is None:
        user.contact = AuthUserContact(social_links={})
    if user.preferences is None:
        user.preferences = AuthUserPreferences(notification_settings={})
    if user.security is None:
        user.security = AuthUserSecurity()


def ensure_user_details(db: Session, user: AuthUser) -> bool:
    created = False
    if user.profile is None:
        user.profile = AuthUserProfile()
        created = True
    if user.contact is None:
        user.contact = AuthUserContact(social_links={})
        created = True
    if user.preferences is None:
        user.preferences = AuthUserPreferences(notification_settings={})
        created = True
    if user.security is None:
        user.security = AuthUserSecurity()
        created = True
    if created:
        db.flush()
    return created


def create_session_for_user(
    db: Session,
    *,
    user: AuthUser,
    request: Request | None,
    settings: Settings,
) -> tuple[AuthSession, str]:
    raw_token = generate_session_token()
    session = AuthSession(
        user=user,
        token_hash=hash_session_token(raw_token),
        user_agent=request.headers.get("user-agent") if request else None,
        ip_address=get_client_ip(request),
        expires_at=utcnow() + timedelta(days=settings.session_ttl_days),
    )
    db.add(session)
    db.flush()
    return session, raw_token


def build_password_reset_url(settings: Settings, raw_token: str) -> str:
    base_url = settings.password_reset_url_base or "http://127.0.0.1:5173/reset-password"
    parts = urlsplit(base_url)
    query_items = dict(parse_qsl(parts.query, keep_blank_values=True))
    query_items["token"] = raw_token
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(query_items), parts.fragment))


def ensure_smtp_configuration(settings: Settings) -> None:
    missing: list[str] = []
    if not settings.smtp_host:
        missing.append("AUTHKIT_SMTP_HOST")
    if settings.smtp_port is None:
        missing.append("AUTHKIT_SMTP_PORT")
    if not settings.smtp_username:
        missing.append("AUTHKIT_SMTP_USERNAME")
    if not settings.smtp_password:
        missing.append("AUTHKIT_SMTP_PASSWORD")
    if not settings.smtp_from_email:
        missing.append("AUTHKIT_SMTP_FROM_EMAIL")
    if missing:
        raise RuntimeError(f"SMTP delivery requires the following settings: {', '.join(missing)}")


def send_smtp_email(
    *,
    to_email: str,
    subject: str,
    body: str,
    settings: Settings,
) -> None:
    ensure_smtp_configuration(settings)
    assert settings.smtp_host is not None
    assert settings.smtp_port is not None
    assert settings.smtp_username is not None
    assert settings.smtp_password is not None
    assert settings.smtp_from_email is not None

    message = EmailMessage()
    message["Subject"] = subject
    message["From"] = f"{settings.smtp_from_name} <{settings.smtp_from_email}>" if settings.smtp_from_name else settings.smtp_from_email
    message["To"] = to_email
    message.set_content(body)

    smtp_cls = smtplib.SMTP_SSL if settings.smtp_use_ssl else smtplib.SMTP
    with smtp_cls(settings.smtp_host, settings.smtp_port, timeout=10) as server:
        if not settings.smtp_use_ssl and settings.smtp_use_starttls:
            server.starttls()
        server.login(settings.smtp_username, settings.smtp_password)
        server.send_message(message)


def append_dev_mail_outbox(*, email: str, raw_token: str, reset_url: str, settings: Settings) -> None:
    if not settings.dev_mail_outbox_enabled:
        return

    outbox_path = Path(settings.dev_mail_outbox_path)
    outbox_path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "kind": "password_reset",
        "email": email,
        "reset_url": reset_url,
        "token": raw_token,
        "expires_in_minutes": settings.password_reset_ttl_minutes,
        "created_at": utcnow().isoformat(),
        "mail_mode": settings.mail_mode,
    }
    with outbox_path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(payload, ensure_ascii=True))
        handle.write("\n")


def deliver_password_reset_email(*, email: str, raw_token: str, settings: Settings) -> None:
    reset_url = build_password_reset_url(settings, raw_token)
    subject = "auth-kit password reset"
    body = (
        "A password reset was requested for your auth-kit account.\n\n"
        f"Reset URL: {reset_url}\n"
        f"Reset token: {raw_token}\n"
        f"Token expires in {settings.password_reset_ttl_minutes} minutes.\n"
    )

    if settings.mail_mode in {"dev", "log"}:
        logger.info("[auth-kit] password reset link for %s: %s", email, reset_url)
        append_dev_mail_outbox(email=email, raw_token=raw_token, reset_url=reset_url, settings=settings)
        return

    send_smtp_email(
        to_email=email,
        subject=subject,
        body=body,
        settings=settings,
    )


def send_test_mail(*, to_email: str, settings: Settings) -> None:
    if settings.mail_mode != "smtp":
        raise RuntimeError("AUTHKIT_MAIL_MODE must be set to smtp to send a live test mail.")

    send_smtp_email(
        to_email=to_email,
        subject="auth-kit SMTP test mail",
        body=(
            "This is a live SMTP test mail from auth-kit.\n\n"
            f"Configured mail mode: {settings.mail_mode}\n"
            "If you received this message, the current SMTP configuration is working.\n"
        ),
        settings=settings,
    )


def revoke_session(session: AuthSession) -> None:
    now = utcnow()
    if session.revoked_at is None:
        session.revoked_at = now
    session.updated_at = now


def revoke_user_sessions(
    db: Session,
    *,
    user_id: int,
    except_session_id: UUID | None = None,
) -> int:
    stmt = select(AuthSession).where(
        AuthSession.user_id == user_id,
        AuthSession.revoked_at.is_(None),
        AuthSession.expires_at > utcnow(),
    )
    revoked = 0
    for session in db.scalars(stmt):
        if except_session_id is not None and session.id == except_session_id:
            continue
        revoke_session(session)
        revoked += 1
    return revoked


def list_active_sessions_for_user(db: Session, user_id: int) -> list[AuthSession]:
    stmt = (
        select(AuthSession)
        .where(
            AuthSession.user_id == user_id,
            AuthSession.revoked_at.is_(None),
            AuthSession.expires_at > utcnow(),
        )
        .order_by(AuthSession.created_at.desc())
    )
    return list(db.scalars(stmt))


def register_user(
    db: Session,
    *,
    email: str,
    username: str,
    display_name: str | None,
    password: str,
    settings: Settings,
) -> AuthUser:
    normalized_email = normalize_email(email)
    normalized_username = normalize_username(username)
    validate_password(password, email=normalized_email, username=normalized_username, settings=settings)
    ensure_unique_identity(db, email=normalized_email, username=normalized_username)
    user = AuthUser(
        email=normalized_email,
        username=normalized_username,
        display_name=display_name.strip() if display_name else None,
        password_hash=hash_password(password),
        roles=["user"],
        is_active=True,
        is_verified=False,
    )
    initialize_user_details(user)
    db.add(user)
    db.flush()
    return user


def authenticate_user(db: Session, *, identifier: str, password: str) -> AuthUser:
    user = get_user_by_identifier(db, identifier)
    if user is None or not verify_password(password, user.password_hash):
        raise ApiError(status_code=401, error_code="invalid_credentials", message="Invalid credentials.")
    if not user.is_active:
        raise ApiError(status_code=403, error_code="user_disabled", message="User is disabled.")
    user.last_login_at = utcnow()
    return user


def change_user_password(
    db: Session,
    *,
    user: AuthUser,
    current_password: str,
    new_password: str,
    current_session_id: UUID,
    settings: Settings,
) -> None:
    if not verify_password(current_password, user.password_hash):
        raise ApiError(
            status_code=400,
            error_code="current_password_invalid",
            message="Current password is invalid.",
        )
    validate_password(new_password, email=user.email, username=user.username, settings=settings)
    if verify_password(new_password, user.password_hash):
        raise ApiError(
            status_code=400,
            error_code="password_unchanged",
            message="New password must differ from the current password.",
        )
    user.password_hash = hash_password(new_password)
    user.updated_at = utcnow()
    invalidate_password_reset_tokens(db, user_id=user.id)
    revoke_user_sessions(db, user_id=user.id, except_session_id=current_session_id)


def invalidate_password_reset_tokens(db: Session, *, user_id: int) -> int:
    now = utcnow()
    stmt = select(AuthPasswordResetToken).where(
        AuthPasswordResetToken.user_id == user_id,
        AuthPasswordResetToken.consumed_at.is_(None),
    )
    invalidated = 0
    for token in db.scalars(stmt):
        token.consumed_at = now
        token.updated_at = now
        invalidated += 1
    return invalidated


def create_password_reset_token(
    db: Session,
    *,
    user: AuthUser,
    request: Request | None,
    settings: Settings,
) -> str:
    invalidate_password_reset_tokens(db, user_id=user.id)
    raw_token = generate_password_reset_token()
    db.add(
        AuthPasswordResetToken(
            user=user,
            token_hash=hash_password_reset_token(raw_token),
            expires_at=utcnow() + timedelta(minutes=settings.password_reset_ttl_minutes),
            requested_by_ip=get_client_ip(request),
            user_agent=request.headers.get("user-agent") if request else None,
        )
    )
    db.flush()
    return raw_token


def reset_password_with_token(
    db: Session,
    *,
    raw_token: str,
    new_password: str,
    settings: Settings,
) -> AuthUser:
    token_hash = hash_password_reset_token(raw_token)
    stmt = (
        select(AuthPasswordResetToken)
        .join(AuthUser, AuthUser.id == AuthPasswordResetToken.user_id)
        .where(
            AuthPasswordResetToken.token_hash == token_hash,
            AuthPasswordResetToken.consumed_at.is_(None),
            AuthPasswordResetToken.expires_at > utcnow(),
        )
    )
    reset_token = db.scalar(stmt)
    if reset_token is None:
        raise ApiError(
            status_code=400,
            error_code="password_reset_token_invalid",
            message="Reset token is invalid or expired.",
        )

    user = reset_token.user
    validate_password(new_password, email=user.email, username=user.username, settings=settings)
    if verify_password(new_password, user.password_hash):
        raise ApiError(
            status_code=400,
            error_code="password_unchanged",
            message="New password must differ from the current password.",
        )

    now = utcnow()
    user.password_hash = hash_password(new_password)
    user.updated_at = now
    reset_token.consumed_at = now
    reset_token.updated_at = now
    invalidate_password_reset_tokens(db, user_id=user.id)
    revoke_user_sessions(db, user_id=user.id)
    db.flush()
    return user


def create_admin_user(
    db: Session,
    *,
    email: str,
    username: str,
    display_name: str | None,
    password: str,
    roles: list[str],
    is_active: bool,
    is_verified: bool,
    settings: Settings,
) -> AuthUser:
    normalized_email = normalize_email(email)
    normalized_username = normalize_username(username)
    normalized_roles = normalize_roles(roles)
    validate_password(password, email=normalized_email, username=normalized_username, settings=settings)
    ensure_unique_identity(db, email=normalized_email, username=normalized_username)
    user = AuthUser(
        email=normalized_email,
        username=normalized_username,
        display_name=display_name.strip() if display_name else None,
        password_hash=hash_password(password),
        roles=normalized_roles,
        is_active=is_active,
        is_verified=is_verified,
    )
    initialize_user_details(user)
    db.add(user)
    db.flush()
    return user


def count_owner_users(db: Session) -> int:
    owners = 0
    for user in db.scalars(select(AuthUser)):
        if "owner" in {role.lower() for role in user.roles} and user.is_active:
            owners += 1
    return owners


def has_owner_user(db: Session) -> bool:
    for user in db.scalars(select(AuthUser)):
        if "owner" in {role.lower() for role in user.roles}:
            return True
    return False


def setup_status(db: Session) -> tuple[bool, bool]:
    has_owner = has_owner_user(db)
    return (not has_owner, has_owner)


def create_initial_owner(
    db: Session,
    *,
    email: str,
    username: str,
    display_name: str | None,
    password: str,
    settings: Settings,
) -> AuthUser:
    if has_owner_user(db):
        raise ApiError(
            status_code=409,
            error_code="setup_already_completed",
            message="Initial owner setup is already completed.",
        )
    user = create_admin_user(
        db,
        email=email,
        username=username,
        display_name=display_name,
        password=password,
        roles=["user", "admin", "owner"],
        is_active=True,
        is_verified=True,
        settings=settings,
    )
    log_event(
        db,
        event_type="system.initial_owner_created",
        actor_user_id=user.id,
        target_user_id=user.id,
        metadata={"username": user.username},
    )
    return user


def avatar_storage_path(settings: Settings, storage_key: str) -> Path:
    relative = Path(storage_key)
    if relative.is_absolute() or ".." in relative.parts:
        raise ApiError(status_code=404, error_code="avatar_not_found", message="Avatar not found.")
    return Path(settings.upload_dir) / relative


def resolve_managed_avatar_path(settings: Settings, profile: AuthUserProfile) -> Path | None:
    if profile.avatar_storage_key:
        return avatar_storage_path(settings, profile.avatar_storage_key)
    if not profile.avatar_url:
        return None
    if not profile.avatar_url.startswith(LEGACY_AVATAR_ROUTE_PREFIX):
        return None
    relative_path = profile.avatar_url.removeprefix(LEGACY_AVATAR_ROUTE_PREFIX)
    if not relative_path or "/" in relative_path or "\\" in relative_path:
        return None
    return Path(settings.upload_dir) / "avatars" / relative_path


def avatar_media_type(storage_key: str) -> str:
    media_type = AVATAR_CONTENT_TYPES_BY_SUFFIX.get(Path(storage_key).suffix.lower())
    if media_type is None:
        raise ApiError(status_code=404, error_code="avatar_not_found", message="Avatar not found.")
    return media_type


def get_avatar_profile_or_404(db: Session, avatar_id: str) -> AuthUserProfile:
    profile = db.scalar(select(AuthUserProfile).where(AuthUserProfile.avatar_url == build_avatar_public_url(avatar_id)))
    if profile is None or not profile.avatar_storage_key:
        raise ApiError(status_code=404, error_code="avatar_not_found", message="Avatar not found.")
    return profile


def get_profile_avatar_or_404(user: AuthUser) -> AuthUserProfile:
    profile = user.profile
    if profile is None or not profile.avatar_storage_key:
        raise ApiError(status_code=404, error_code="avatar_not_found", message="Avatar not found.")
    return profile


def store_user_avatar(
    db: Session,
    *,
    user: AuthUser,
    content_type: str | None,
    contents: bytes,
    settings: Settings,
) -> AuthUserProfile:
    if content_type not in AVATAR_CONTENT_TYPES:
        raise ApiError(
            status_code=400,
            error_code="avatar_invalid_content_type",
            message="Avatar must be a PNG, JPEG, or WebP image.",
        )
    if not contents:
        raise ApiError(status_code=400, error_code="avatar_empty", message="Avatar file is empty.")
    if len(contents) > avatar_max_bytes(settings):
        raise ApiError(
            status_code=413,
            error_code="avatar_too_large",
            message=f"Avatar must be {settings.avatar_max_mb} MB or smaller.",
        )

    ensure_user_details(db, user)
    profile = user.profile
    assert profile is not None

    avatar_id, storage_key_base = build_avatar_storage_key()
    extension = AVATAR_CONTENT_TYPES[content_type]
    storage_key = f"{storage_key_base}{extension}"
    target_path = avatar_storage_path(settings, storage_key)
    target_path.parent.mkdir(parents=True, exist_ok=True)
    target_path.write_bytes(contents)

    previous_path = resolve_managed_avatar_path(settings, profile)
    profile.avatar_url = build_avatar_public_url(avatar_id)
    profile.avatar_storage_key = storage_key
    profile.updated_at = utcnow()
    db.flush()

    if previous_path is not None and previous_path != target_path and previous_path.exists():
        previous_path.unlink()

    return profile


def require_owner_for_owner_target(actor: AuthUser, target: AuthUser) -> None:
    actor_roles = {role.lower() for role in actor.roles}
    target_roles = {role.lower() for role in target.roles}
    if "owner" in target_roles and "owner" not in actor_roles:
        raise ApiError(
            status_code=403,
            error_code="owner_role_required",
            message="Owner accounts can only be managed by an owner.",
        )


def update_admin_user(
    db: Session,
    *,
    actor: AuthUser,
    target: AuthUser,
    email: str | None = None,
    username: str | None = None,
    display_name: str | None | UnsetType = UNSET,
    roles: list[str] | None = None,
    is_active: bool | None = None,
    is_verified: bool | None = None,
) -> AuthUser:
    require_owner_for_owner_target(actor, target)

    next_email = normalize_email(email) if email is not None else target.email
    next_username = normalize_username(username) if username is not None else target.username
    ensure_unique_identity(db, email=next_email, username=next_username, exclude_user_id=target.id)
    target.email = next_email
    target.username = next_username
    if is_set(display_name):
        target.display_name = _clean_optional_string(display_name)
    if roles is not None:
        normalized_roles = normalize_roles(roles)
        current_roles = {role.lower() for role in target.roles}
        actor_roles = {role.lower() for role in actor.roles}
        if "owner" in current_roles and "owner" not in normalized_roles and count_owner_users(db) <= 1:
            raise ApiError(
                status_code=400,
                error_code="last_active_owner_required",
                message="Cannot remove the last active owner.",
            )
        if "owner" in normalized_roles and "owner" not in actor_roles:
            raise ApiError(
                status_code=403,
                error_code="owner_role_assignment_forbidden",
                message="Only an owner can assign the owner role.",
            )
        target.roles = normalized_roles
    if is_active is not None:
        if "owner" in {role.lower() for role in target.roles} and not is_active and count_owner_users(db) <= 1:
            raise ApiError(
                status_code=400,
                error_code="last_active_owner_required",
                message="Cannot disable the last active owner.",
            )
        target.is_active = is_active
        if not is_active:
            revoke_user_sessions(db, user_id=target.id)
    if is_verified is not None:
        target.is_verified = is_verified
    target.updated_at = utcnow()
    return target


def update_user_profile(
    db: Session,
    *,
    user: AuthUser,
    bio: str | None | UnsetType = UNSET,
    locale: str | None | UnsetType = UNSET,
    timezone: str | None | UnsetType = UNSET,
) -> AuthUserProfile:
    ensure_user_details(db, user)
    profile = user.profile
    assert profile is not None
    if is_set(bio):
        profile.bio = _clean_optional_string(bio)
    if is_set(locale):
        profile.locale = _clean_optional_string(locale)
    if is_set(timezone):
        profile.timezone = _clean_optional_string(timezone)
    profile.updated_at = utcnow()
    db.flush()
    return profile


def list_user_addresses(db: Session, user_id: int) -> list[AuthUserAddress]:
    stmt = (
        select(AuthUserAddress)
        .where(AuthUserAddress.user_id == user_id)
        .order_by(AuthUserAddress.is_default.desc(), AuthUserAddress.created_at.asc())
    )
    return list(db.scalars(stmt))


def create_user_address(
    db: Session,
    *,
    user: AuthUser,
    type: str,
    name: str | None,
    street_line_1: str,
    street_line_2: str | None,
    postal_code: str,
    city: str,
    state: str | None,
    country: str,
    is_default: bool,
) -> AuthUserAddress:
    should_be_default = is_default or not user.addresses
    if should_be_default:
        for existing in list_user_addresses(db, user.id):
            existing.is_default = False
            existing.updated_at = utcnow()

    address = AuthUserAddress(
        user=user,
        type=_clean_required_string(type, "type"),
        name=_clean_optional_string(name),
        street_line_1=_clean_required_string(street_line_1, "street_line_1"),
        street_line_2=_clean_optional_string(street_line_2),
        postal_code=_clean_required_string(postal_code, "postal_code"),
        city=_clean_required_string(city, "city"),
        state=_clean_optional_string(state),
        country=_clean_required_string(country, "country"),
        is_default=should_be_default,
    )
    db.add(address)
    db.flush()
    return address


def update_user_address(
    db: Session,
    *,
    address: AuthUserAddress,
    type: str | None | UnsetType = UNSET,
    name: str | None | UnsetType = UNSET,
    street_line_1: str | None | UnsetType = UNSET,
    street_line_2: str | None | UnsetType = UNSET,
    postal_code: str | None | UnsetType = UNSET,
    city: str | None | UnsetType = UNSET,
    state: str | None | UnsetType = UNSET,
    country: str | None | UnsetType = UNSET,
    is_default: bool | None | UnsetType = UNSET,
) -> AuthUserAddress:
    if is_set(type):
        address.type = _clean_required_string(type, "type")
    if is_set(name):
        address.name = _clean_optional_string(name)
    if is_set(street_line_1):
        address.street_line_1 = _clean_required_string(street_line_1, "street_line_1")
    if is_set(street_line_2):
        address.street_line_2 = _clean_optional_string(street_line_2)
    if is_set(postal_code):
        address.postal_code = _clean_required_string(postal_code, "postal_code")
    if is_set(city):
        address.city = _clean_required_string(city, "city")
    if is_set(state):
        address.state = _clean_optional_string(state)
    if is_set(country):
        address.country = _clean_required_string(country, "country")
    if is_set(is_default):
        if bool(is_default):
            for existing in list_user_addresses(db, address.user_id):
                if existing.id != address.id and existing.is_default:
                    existing.is_default = False
                    existing.updated_at = utcnow()
            address.is_default = True
        else:
            address.is_default = False
    address.updated_at = utcnow()
    db.flush()
    return address


def delete_user_address(db: Session, *, address: AuthUserAddress) -> None:
    db.delete(address)


def update_user_contact(
    db: Session,
    *,
    user: AuthUser,
    phone: str | None | UnsetType = UNSET,
    website: str | None | UnsetType = UNSET,
    social_links: dict[str, str] | None | UnsetType = UNSET,
) -> AuthUserContact:
    ensure_user_details(db, user)
    contact = user.contact
    assert contact is not None
    if is_set(phone):
        contact.phone = _clean_optional_string(phone)
    if is_set(website):
        contact.website = _clean_optional_string(website)
    if is_set(social_links):
        contact.social_links = social_links or {}
    contact.updated_at = utcnow()
    db.flush()
    return contact


def update_user_preferences(
    db: Session,
    *,
    user: AuthUser,
    theme: str | None | UnsetType = UNSET,
    language: str | None | UnsetType = UNSET,
    notification_settings: dict[str, Any] | None | UnsetType = UNSET,
) -> AuthUserPreferences:
    ensure_user_details(db, user)
    preferences = user.preferences
    assert preferences is not None
    if is_set(theme):
        preferences.theme = _clean_optional_string(theme)
    if is_set(language):
        preferences.language = _clean_optional_string(language)
    if is_set(notification_settings):
        preferences.notification_settings = notification_settings or {}
    preferences.updated_at = utcnow()
    db.flush()
    return preferences


def update_user_security(
    db: Session,
    *,
    user: AuthUser,
    two_factor_enabled: bool | None | UnsetType = UNSET,
    passkeys_enabled: bool | None | UnsetType = UNSET,
    recovery_codes_enabled: bool | None | UnsetType = UNSET,
    trusted_devices_enabled: bool | None | UnsetType = UNSET,
) -> AuthUserSecurity:
    ensure_user_details(db, user)
    security = user.security
    assert security is not None
    if is_set(two_factor_enabled) and two_factor_enabled is not None:
        security.two_factor_enabled = two_factor_enabled
    if is_set(passkeys_enabled) and passkeys_enabled is not None:
        security.passkeys_enabled = passkeys_enabled
    if is_set(recovery_codes_enabled) and recovery_codes_enabled is not None:
        security.recovery_codes_enabled = recovery_codes_enabled
    if is_set(trusted_devices_enabled) and trusted_devices_enabled is not None:
        security.trusted_devices_enabled = trusted_devices_enabled
    security.updated_at = utcnow()
    db.flush()
    return security


def admin_reset_password(
    db: Session,
    *,
    actor: AuthUser,
    target: AuthUser,
    new_password: str,
    settings: Settings,
) -> None:
    require_owner_for_owner_target(actor, target)
    validate_password(new_password, email=target.email, username=target.username, settings=settings)
    target.password_hash = hash_password(new_password)
    target.updated_at = utcnow()
    invalidate_password_reset_tokens(db, user_id=target.id)
    revoke_user_sessions(db, user_id=target.id)


def admin_set_user_enabled(
    db: Session,
    *,
    actor: AuthUser,
    target: AuthUser,
    enabled: bool,
) -> AuthUser:
    require_owner_for_owner_target(actor, target)
    if "owner" in {role.lower() for role in target.roles} and not enabled and count_owner_users(db) <= 1:
        raise ApiError(
            status_code=400,
            error_code="last_active_owner_required",
            message="Cannot disable the last active owner.",
        )
    target.is_active = enabled
    target.updated_at = utcnow()
    if not enabled:
        revoke_user_sessions(db, user_id=target.id)
    return target


def ensure_bootstrap_owner(session_factory: sessionmaker[Session], settings: Settings) -> None:
    if not settings.bootstrap_owner_enabled:
        return
    required_values = {
        "AUTHKIT_BOOTSTRAP_OWNER_EMAIL": settings.bootstrap_owner_email,
        "AUTHKIT_BOOTSTRAP_OWNER_USERNAME": settings.bootstrap_owner_username,
        "AUTHKIT_BOOTSTRAP_OWNER_PASSWORD": settings.bootstrap_owner_password,
        "AUTHKIT_BOOTSTRAP_OWNER_DISPLAY_NAME": settings.bootstrap_owner_display_name,
    }
    missing = [name for name, value in required_values.items() if not value]
    if missing:
        raise RuntimeError(f"bootstrap owner is enabled but missing values: {', '.join(missing)}")

    db = session_factory()
    try:
        for user in db.scalars(select(AuthUser)):
            if "owner" in {role.lower() for role in user.roles}:
                ensure_user_details(db, user)
                db.commit()
                return

        user = create_admin_user(
            db,
            email=settings.bootstrap_owner_email or "",
            username=settings.bootstrap_owner_username or "",
            display_name=settings.bootstrap_owner_display_name,
            password=settings.bootstrap_owner_password or "",
            roles=["user", "admin", "owner"],
            is_active=True,
            is_verified=True,
            settings=settings,
        )
        log_event(
            db,
            event_type="system.bootstrap_owner_created",
            actor_user_id=user.id,
            target_user_id=user.id,
            metadata={"username": user.username},
        )
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()
