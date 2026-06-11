from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import AliasChoices, BaseModel, ConfigDict, EmailStr, Field


class ResponseModel(BaseModel):
    model_config = ConfigDict(from_attributes=True)


class RequestModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class UserProfilePublic(ResponseModel):
    avatar_url: str | None
    bio: str | None
    locale: str | None
    timezone: str | None
    created_at: datetime
    updated_at: datetime


class UserAddressPublic(ResponseModel):
    id: int
    type: str
    name: str | None
    street_line_1: str
    street_line_2: str | None
    postal_code: str
    city: str
    state: str | None
    country: str
    is_default: bool
    created_at: datetime
    updated_at: datetime


class UserContactPublic(ResponseModel):
    phone: str | None
    website: str | None
    social_links: dict[str, str]
    created_at: datetime
    updated_at: datetime


class UserPreferencesPublic(ResponseModel):
    theme: str | None
    language: str | None
    notification_settings: dict[str, Any]
    created_at: datetime
    updated_at: datetime


class UserSecurityPublic(ResponseModel):
    two_factor_enabled: bool
    passkeys_enabled: bool
    recovery_codes_enabled: bool
    trusted_devices_enabled: bool
    pending_two_factor_setup: bool = False
    recovery_codes_remaining: int = 0
    trusted_devices_count: int = 0
    created_at: datetime
    updated_at: datetime


class UserPublic(ResponseModel):
    id: int
    email: EmailStr
    username: str
    display_name: str | None
    roles: list[str]
    is_active: bool
    is_verified: bool
    created_at: datetime
    updated_at: datetime
    last_login_at: datetime | None


class AuthMePublic(UserPublic):
    profile: UserProfilePublic | None = None
    preferences: UserPreferencesPublic | None = None


class AdminUserDetailPublic(UserPublic):
    profile: UserProfilePublic | None = None
    addresses: list[UserAddressPublic] = Field(default_factory=list)
    contact: UserContactPublic | None = None
    preferences: UserPreferencesPublic | None = None
    security: UserSecurityPublic | None = None


class SessionPublic(ResponseModel):
    id: UUID
    created_at: datetime
    updated_at: datetime
    expires_at: datetime
    revoked_at: datetime | None
    user_agent: str | None
    ip_address: str | None
    is_current: bool


class LoginRequest(RequestModel):
    identifier: str = Field(
        min_length=1,
        validation_alias=AliasChoices("identifier", "email", "username"),
    )
    password: str = Field(min_length=1)


class LoginTwoFactorRequiredResponse(ResponseModel):
    ok: bool = True
    message: str
    requires_two_factor: bool = True
    available_methods: list[str] = Field(default_factory=lambda: ["totp", "recovery_code"])
    challenge_expires_at: datetime


class RegisterRequest(RequestModel):
    email: EmailStr
    username: str = Field(min_length=3, max_length=64)
    display_name: str | None = Field(default=None, max_length=255)
    password: str = Field(min_length=1)


class ChangePasswordRequest(RequestModel):
    current_password: str = Field(min_length=1)
    new_password: str = Field(min_length=1)


class VerifyTwoFactorLoginRequest(RequestModel):
    code: str = Field(min_length=1)
    trust_device: bool = False
    device_label: str | None = Field(default=None, max_length=255)


class ForgotPasswordRequest(RequestModel):
    email: EmailStr


class ResetPasswordRequest(RequestModel):
    token: str = Field(min_length=1)
    new_password: str = Field(min_length=1)


class UserProfilePatchRequest(RequestModel):
    bio: str | None = Field(default=None, max_length=4000)
    locale: str | None = Field(default=None, max_length=32)
    timezone: str | None = Field(default=None, max_length=64)


class UserAddressCreateRequest(RequestModel):
    type: str = Field(min_length=1, max_length=32)
    name: str | None = Field(default=None, max_length=255)
    street_line_1: str = Field(min_length=1, max_length=255)
    street_line_2: str | None = Field(default=None, max_length=255)
    postal_code: str = Field(min_length=1, max_length=32)
    city: str = Field(min_length=1, max_length=128)
    state: str | None = Field(default=None, max_length=128)
    country: str = Field(min_length=1, max_length=128)
    is_default: bool = False


class UserAddressPatchRequest(RequestModel):
    type: str | None = Field(default=None, min_length=1, max_length=32)
    name: str | None = Field(default=None, max_length=255)
    street_line_1: str | None = Field(default=None, min_length=1, max_length=255)
    street_line_2: str | None = Field(default=None, max_length=255)
    postal_code: str | None = Field(default=None, min_length=1, max_length=32)
    city: str | None = Field(default=None, min_length=1, max_length=128)
    state: str | None = Field(default=None, max_length=128)
    country: str | None = Field(default=None, min_length=1, max_length=128)
    is_default: bool | None = None


class UserContactPatchRequest(RequestModel):
    phone: str | None = Field(default=None, max_length=64)
    website: str | None = Field(default=None, max_length=2048)
    social_links: dict[str, str] | None = None


class UserPreferencesPatchRequest(RequestModel):
    theme: str | None = Field(default=None, max_length=64)
    language: str | None = Field(default=None, max_length=32)
    notification_settings: dict[str, Any] | None = None


class UserSecurityPatchRequest(RequestModel):
    two_factor_enabled: bool | None = None
    passkeys_enabled: bool | None = None
    recovery_codes_enabled: bool | None = None
    trusted_devices_enabled: bool | None = None


class TwoFactorSetupResponse(ResponseModel):
    secret: str
    otpauth_uri: str
    qr_data: str
    security: UserSecurityPublic


class EnableTwoFactorRequest(RequestModel):
    code: str = Field(min_length=1)


class RecoveryCodesResponse(ResponseModel):
    ok: bool = True
    message: str
    recovery_codes: list[str]
    security: UserSecurityPublic


class DisableTwoFactorRequest(RequestModel):
    current_password: str = Field(min_length=1)


class RegenerateRecoveryCodesRequest(RequestModel):
    current_password: str = Field(min_length=1)


class TrustedDevicePublic(ResponseModel):
    id: UUID
    device_label: str | None
    user_agent: str | None
    ip_address: str | None
    created_at: datetime
    updated_at: datetime
    last_used_at: datetime | None
    expires_at: datetime
    revoked_at: datetime | None
    is_current: bool


class AdminCreateUserRequest(RequestModel):
    email: EmailStr
    username: str = Field(min_length=3, max_length=64)
    display_name: str | None = Field(default=None, max_length=255)
    password: str = Field(min_length=1)
    roles: list[str] = Field(default_factory=lambda: ["user"])
    is_active: bool = True
    is_verified: bool = True


class AdminUpdateUserRequest(RequestModel):
    email: EmailStr | None = None
    username: str | None = Field(default=None, min_length=3, max_length=64)
    display_name: str | None = Field(default=None, max_length=255)
    roles: list[str] | None = None
    is_active: bool | None = None
    is_verified: bool | None = None
    profile: UserProfilePatchRequest | None = None
    contact: UserContactPatchRequest | None = None
    preferences: UserPreferencesPatchRequest | None = None


class AdminResetPasswordRequest(RequestModel):
    new_password: str = Field(min_length=1)


class StatusResponse(ResponseModel):
    ok: bool = True


class StatusMessageResponse(StatusResponse):
    message: str


class ErrorResponse(BaseModel):
    error_code: str
    message: str
    details: list[dict[str, Any]] | None = None


class HealthResponse(ResponseModel):
    status: str
    database: str


class VersionResponse(ResponseModel):
    name: str
    version: str


class CsrfTokenResponse(ResponseModel):
    csrf_token: str


class SetupStatusResponse(ResponseModel):
    needs_setup: bool
    has_owner: bool


class SetupOwnerRequest(RequestModel):
    email: EmailStr
    username: str = Field(min_length=3, max_length=64)
    display_name: str | None = Field(default=None, max_length=255)
    password: str = Field(min_length=1)
