from __future__ import annotations

from datetime import datetime
from uuid import UUID, uuid4

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.ext.mutable import MutableDict, MutableList
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.types import JSON, Uuid

from .db import Base, utcnow

STANDARD_ROLES = {"user", "admin", "owner"}


class TimestampMixin:
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)


class AuthUser(TimestampMixin, Base):
    __tablename__ = "auth_user"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    email: Mapped[str] = mapped_column(String(320), unique=True, index=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    display_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    password_hash: Mapped[str] = mapped_column(String(512))
    roles: Mapped[list[str]] = mapped_column(MutableList.as_mutable(JSON), default=lambda: ["user"])
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    is_verified: Mapped[bool] = mapped_column(Boolean, default=False)
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    sessions: Mapped[list[AuthSession]] = relationship(
        back_populates="user",
        cascade="all, delete-orphan",
    )
    password_reset_tokens: Mapped[list[AuthPasswordResetToken]] = relationship(
        back_populates="user",
        cascade="all, delete-orphan",
    )
    profile: Mapped[AuthUserProfile | None] = relationship(
        back_populates="user",
        cascade="all, delete-orphan",
        uselist=False,
        single_parent=True,
    )
    addresses: Mapped[list[AuthUserAddress]] = relationship(
        back_populates="user",
        cascade="all, delete-orphan",
        order_by="AuthUserAddress.created_at",
    )
    contact: Mapped[AuthUserContact | None] = relationship(
        back_populates="user",
        cascade="all, delete-orphan",
        uselist=False,
        single_parent=True,
    )
    preferences: Mapped[AuthUserPreferences | None] = relationship(
        back_populates="user",
        cascade="all, delete-orphan",
        uselist=False,
        single_parent=True,
    )
    security: Mapped[AuthUserSecurity | None] = relationship(
        back_populates="user",
        cascade="all, delete-orphan",
        uselist=False,
        single_parent=True,
    )


class AuthSession(TimestampMixin, Base):
    __tablename__ = "auth_session"

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    user_id: Mapped[int] = mapped_column(ForeignKey("auth_user.id", ondelete="CASCADE"), index=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    user_agent: Mapped[str | None] = mapped_column(Text, nullable=True)
    ip_address: Mapped[str | None] = mapped_column(String(64), nullable=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    user: Mapped[AuthUser] = relationship(back_populates="sessions")


class AuthAuditLog(TimestampMixin, Base):
    __tablename__ = "auth_audit_log"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    actor_user_id: Mapped[int | None] = mapped_column(ForeignKey("auth_user.id", ondelete="SET NULL"), nullable=True)
    event_type: Mapped[str] = mapped_column(String(128), index=True)
    target_user_id: Mapped[int | None] = mapped_column(ForeignKey("auth_user.id", ondelete="SET NULL"), nullable=True)
    ip_address: Mapped[str | None] = mapped_column(String(64), nullable=True)
    user_agent: Mapped[str | None] = mapped_column(Text, nullable=True)
    metadata_json: Mapped[dict[str, object]] = mapped_column(MutableDict.as_mutable(JSON), default=dict)


class AuthPasswordResetToken(TimestampMixin, Base):
    __tablename__ = "auth_password_reset_token"

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    user_id: Mapped[int] = mapped_column(ForeignKey("auth_user.id", ondelete="CASCADE"), index=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    consumed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    requested_by_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    user_agent: Mapped[str | None] = mapped_column(Text, nullable=True)

    user: Mapped[AuthUser] = relationship(back_populates="password_reset_tokens")


class AuthUserProfile(TimestampMixin, Base):
    __tablename__ = "auth_user_profile"

    user_id: Mapped[int] = mapped_column(
        ForeignKey("auth_user.id", ondelete="CASCADE"),
        primary_key=True,
    )
    avatar_url: Mapped[str | None] = mapped_column(String(2048), nullable=True)
    avatar_storage_key: Mapped[str | None] = mapped_column(String(512), nullable=True)
    bio: Mapped[str | None] = mapped_column(Text, nullable=True)
    locale: Mapped[str | None] = mapped_column(String(32), nullable=True)
    timezone: Mapped[str | None] = mapped_column(String(64), nullable=True)

    user: Mapped[AuthUser] = relationship(back_populates="profile")


class AuthUserAddress(TimestampMixin, Base):
    __tablename__ = "auth_user_address"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("auth_user.id", ondelete="CASCADE"), index=True)
    type: Mapped[str] = mapped_column(String(32))
    name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    street_line_1: Mapped[str] = mapped_column(String(255))
    street_line_2: Mapped[str | None] = mapped_column(String(255), nullable=True)
    postal_code: Mapped[str] = mapped_column(String(32))
    city: Mapped[str] = mapped_column(String(128))
    state: Mapped[str | None] = mapped_column(String(128), nullable=True)
    country: Mapped[str] = mapped_column(String(128))
    is_default: Mapped[bool] = mapped_column(Boolean, default=False)

    user: Mapped[AuthUser] = relationship(back_populates="addresses")


class AuthUserContact(TimestampMixin, Base):
    __tablename__ = "auth_user_contact"

    user_id: Mapped[int] = mapped_column(
        ForeignKey("auth_user.id", ondelete="CASCADE"),
        primary_key=True,
    )
    phone: Mapped[str | None] = mapped_column(String(64), nullable=True)
    website: Mapped[str | None] = mapped_column(String(2048), nullable=True)
    social_links: Mapped[dict[str, str]] = mapped_column(MutableDict.as_mutable(JSON), default=dict)

    user: Mapped[AuthUser] = relationship(back_populates="contact")


class AuthUserPreferences(TimestampMixin, Base):
    __tablename__ = "auth_user_preferences"

    user_id: Mapped[int] = mapped_column(
        ForeignKey("auth_user.id", ondelete="CASCADE"),
        primary_key=True,
    )
    theme: Mapped[str | None] = mapped_column(String(64), nullable=True)
    language: Mapped[str | None] = mapped_column(String(32), nullable=True)
    notification_settings: Mapped[dict[str, object]] = mapped_column(MutableDict.as_mutable(JSON), default=dict)

    user: Mapped[AuthUser] = relationship(back_populates="preferences")


class AuthUserSecurity(TimestampMixin, Base):
    __tablename__ = "auth_user_security"

    user_id: Mapped[int] = mapped_column(
        ForeignKey("auth_user.id", ondelete="CASCADE"),
        primary_key=True,
    )
    two_factor_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    passkeys_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    recovery_codes_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    trusted_devices_enabled: Mapped[bool] = mapped_column(Boolean, default=False)

    user: Mapped[AuthUser] = relationship(back_populates="security")
