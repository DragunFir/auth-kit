"""auth-kit v2 initial schema

Revision ID: 20260510_01
Revises:
Create Date: 2026-05-10 20:30:00
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = "20260510_01"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "auth_user",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("email", sa.String(length=320), nullable=False),
        sa.Column("username", sa.String(length=64), nullable=False),
        sa.Column("display_name", sa.String(length=255), nullable=True),
        sa.Column("password_hash", sa.String(length=512), nullable=False),
        sa.Column("roles", sa.JSON(), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("is_verified", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.Column("last_login_at", sa.DateTime(timezone=True), nullable=True),
        sa.UniqueConstraint("email"),
        sa.UniqueConstraint("username"),
    )
    op.create_index("ix_auth_user_email", "auth_user", ["email"], unique=False)
    op.create_index("ix_auth_user_username", "auth_user", ["username"], unique=False)

    op.create_table(
        "auth_session",
        sa.Column("id", sa.Uuid(), primary_key=True, nullable=False),
        sa.Column("user_id", sa.Integer(), sa.ForeignKey("auth_user.id", ondelete="CASCADE"), nullable=False),
        sa.Column("token_hash", sa.String(length=64), nullable=False),
        sa.Column("user_agent", sa.Text(), nullable=True),
        sa.Column("ip_address", sa.String(length=64), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.UniqueConstraint("token_hash"),
    )
    op.create_index("ix_auth_session_expires_at", "auth_session", ["expires_at"], unique=False)
    op.create_index("ix_auth_session_token_hash", "auth_session", ["token_hash"], unique=False)
    op.create_index("ix_auth_session_user_id", "auth_session", ["user_id"], unique=False)

    op.create_table(
        "auth_audit_log",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("actor_user_id", sa.Integer(), sa.ForeignKey("auth_user.id", ondelete="SET NULL"), nullable=True),
        sa.Column("event_type", sa.String(length=128), nullable=False),
        sa.Column("target_user_id", sa.Integer(), sa.ForeignKey("auth_user.id", ondelete="SET NULL"), nullable=True),
        sa.Column("ip_address", sa.String(length=64), nullable=True),
        sa.Column("user_agent", sa.Text(), nullable=True),
        sa.Column("metadata_json", sa.JSON(), nullable=False, server_default=sa.text("'{}'")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
    )
    op.create_index("ix_auth_audit_log_event_type", "auth_audit_log", ["event_type"], unique=False)


def downgrade() -> None:
    op.drop_index("ix_auth_audit_log_event_type", table_name="auth_audit_log")
    op.drop_table("auth_audit_log")

    op.drop_index("ix_auth_session_user_id", table_name="auth_session")
    op.drop_index("ix_auth_session_token_hash", table_name="auth_session")
    op.drop_index("ix_auth_session_expires_at", table_name="auth_session")
    op.drop_table("auth_session")

    op.drop_index("ix_auth_user_username", table_name="auth_user")
    op.drop_index("ix_auth_user_email", table_name="auth_user")
    op.drop_table("auth_user")
