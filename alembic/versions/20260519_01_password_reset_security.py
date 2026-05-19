"""add password reset token table

Revision ID: 20260519_01
Revises: 20260510_03
Create Date: 2026-05-19 13:45:00
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = "20260519_01"
down_revision = "20260510_03"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "auth_password_reset_token",
        sa.Column("id", sa.Uuid(), primary_key=True, nullable=False),
        sa.Column("user_id", sa.Integer(), sa.ForeignKey("auth_user.id", ondelete="CASCADE"), nullable=False),
        sa.Column("token_hash", sa.String(length=64), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("consumed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("requested_by_ip", sa.String(length=64), nullable=True),
        sa.Column("user_agent", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.UniqueConstraint("token_hash"),
    )
    op.create_index("ix_auth_password_reset_token_user_id", "auth_password_reset_token", ["user_id"], unique=False)
    op.create_index(
        "ix_auth_password_reset_token_token_hash",
        "auth_password_reset_token",
        ["token_hash"],
        unique=False,
    )
    op.create_index(
        "ix_auth_password_reset_token_expires_at",
        "auth_password_reset_token",
        ["expires_at"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index("ix_auth_password_reset_token_expires_at", table_name="auth_password_reset_token")
    op.drop_index("ix_auth_password_reset_token_token_hash", table_name="auth_password_reset_token")
    op.drop_index("ix_auth_password_reset_token_user_id", table_name="auth_password_reset_token")
    op.drop_table("auth_password_reset_token")
