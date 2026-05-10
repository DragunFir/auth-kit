"""add auth-kit user detail tables

Revision ID: 20260510_02
Revises: 20260510_01
Create Date: 2026-05-10 21:15:00
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = "20260510_02"
down_revision = "20260510_01"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "auth_session",
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("CURRENT_TIMESTAMP"),
        ),
    )
    op.add_column(
        "auth_audit_log",
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("CURRENT_TIMESTAMP"),
        ),
    )

    op.create_table(
        "auth_user_profile",
        sa.Column("user_id", sa.Integer(), sa.ForeignKey("auth_user.id", ondelete="CASCADE"), primary_key=True),
        sa.Column("avatar_url", sa.String(length=2048), nullable=True),
        sa.Column("bio", sa.Text(), nullable=True),
        sa.Column("locale", sa.String(length=32), nullable=True),
        sa.Column("timezone", sa.String(length=64), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
    )
    op.create_table(
        "auth_user_address",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("user_id", sa.Integer(), sa.ForeignKey("auth_user.id", ondelete="CASCADE"), nullable=False),
        sa.Column("type", sa.String(length=32), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=True),
        sa.Column("street_line_1", sa.String(length=255), nullable=False),
        sa.Column("street_line_2", sa.String(length=255), nullable=True),
        sa.Column("postal_code", sa.String(length=32), nullable=False),
        sa.Column("city", sa.String(length=128), nullable=False),
        sa.Column("state", sa.String(length=128), nullable=True),
        sa.Column("country", sa.String(length=128), nullable=False),
        sa.Column("is_default", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
    )
    op.create_index("ix_auth_user_address_user_id", "auth_user_address", ["user_id"], unique=False)
    op.create_table(
        "auth_user_contact",
        sa.Column("user_id", sa.Integer(), sa.ForeignKey("auth_user.id", ondelete="CASCADE"), primary_key=True),
        sa.Column("phone", sa.String(length=64), nullable=True),
        sa.Column("website", sa.String(length=2048), nullable=True),
        sa.Column("social_links", sa.JSON(), nullable=False, server_default=sa.text("'{}'")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
    )
    op.create_table(
        "auth_user_preferences",
        sa.Column("user_id", sa.Integer(), sa.ForeignKey("auth_user.id", ondelete="CASCADE"), primary_key=True),
        sa.Column("theme", sa.String(length=64), nullable=True),
        sa.Column("language", sa.String(length=32), nullable=True),
        sa.Column("notification_settings", sa.JSON(), nullable=False, server_default=sa.text("'{}'")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
    )
    op.create_table(
        "auth_user_security",
        sa.Column("user_id", sa.Integer(), sa.ForeignKey("auth_user.id", ondelete="CASCADE"), primary_key=True),
        sa.Column("two_factor_enabled", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("passkeys_enabled", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("recovery_codes_enabled", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("trusted_devices_enabled", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
    )

    op.execute(
        """
        INSERT INTO auth_user_profile (user_id, created_at, updated_at)
        SELECT id, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP FROM auth_user
        """
    )
    op.execute(
        """
        INSERT INTO auth_user_contact (user_id, social_links, created_at, updated_at)
        SELECT id, '{}', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP FROM auth_user
        """
    )
    op.execute(
        """
        INSERT INTO auth_user_preferences (user_id, notification_settings, created_at, updated_at)
        SELECT id, '{}', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP FROM auth_user
        """
    )
    op.execute(
        """
        INSERT INTO auth_user_security (
            user_id,
            two_factor_enabled,
            passkeys_enabled,
            recovery_codes_enabled,
            trusted_devices_enabled,
            created_at,
            updated_at
        )
        SELECT id, false, false, false, false, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP FROM auth_user
        """
    )


def downgrade() -> None:
    op.drop_table("auth_user_security")
    op.drop_table("auth_user_preferences")
    op.drop_table("auth_user_contact")
    op.drop_index("ix_auth_user_address_user_id", table_name="auth_user_address")
    op.drop_table("auth_user_address")
    op.drop_table("auth_user_profile")
    op.drop_column("auth_audit_log", "updated_at")
    op.drop_column("auth_session", "updated_at")
