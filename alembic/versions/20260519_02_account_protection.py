"""add account protection tables

Revision ID: 20260519_02
Revises: 20260519_01
Create Date: 2026-05-19 19:10:00
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = "20260519_02"
down_revision = "20260519_01"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("auth_user_security", sa.Column("totp_secret_protected", sa.Text(), nullable=True))
    op.add_column("auth_user_security", sa.Column("pending_totp_secret_protected", sa.Text(), nullable=True))
    op.add_column("auth_user_security", sa.Column("two_factor_confirmed_at", sa.DateTime(timezone=True), nullable=True))

    op.create_table(
        "auth_login_challenge",
        sa.Column("id", sa.Uuid(), primary_key=True, nullable=False),
        sa.Column("user_id", sa.Integer(), sa.ForeignKey("auth_user.id", ondelete="CASCADE"), nullable=False),
        sa.Column("token_hash", sa.String(length=64), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("user_agent", sa.Text(), nullable=True),
        sa.Column("ip_address", sa.String(length=64), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.UniqueConstraint("token_hash"),
    )
    op.create_index("ix_auth_login_challenge_user_id", "auth_login_challenge", ["user_id"], unique=False)
    op.create_index("ix_auth_login_challenge_token_hash", "auth_login_challenge", ["token_hash"], unique=False)
    op.create_index("ix_auth_login_challenge_expires_at", "auth_login_challenge", ["expires_at"], unique=False)

    op.create_table(
        "auth_recovery_code",
        sa.Column("id", sa.Uuid(), primary_key=True, nullable=False),
        sa.Column("user_id", sa.Integer(), sa.ForeignKey("auth_user.id", ondelete="CASCADE"), nullable=False),
        sa.Column("code_hash", sa.String(length=64), nullable=False),
        sa.Column("consumed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.UniqueConstraint("code_hash"),
    )
    op.create_index("ix_auth_recovery_code_user_id", "auth_recovery_code", ["user_id"], unique=False)
    op.create_index("ix_auth_recovery_code_code_hash", "auth_recovery_code", ["code_hash"], unique=False)

    op.create_table(
        "auth_trusted_device",
        sa.Column("id", sa.Uuid(), primary_key=True, nullable=False),
        sa.Column("user_id", sa.Integer(), sa.ForeignKey("auth_user.id", ondelete="CASCADE"), nullable=False),
        sa.Column("token_hash", sa.String(length=64), nullable=False),
        sa.Column("device_label", sa.String(length=255), nullable=True),
        sa.Column("user_agent", sa.Text(), nullable=True),
        sa.Column("ip_address", sa.String(length=64), nullable=True),
        sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.UniqueConstraint("token_hash"),
    )
    op.create_index("ix_auth_trusted_device_user_id", "auth_trusted_device", ["user_id"], unique=False)
    op.create_index("ix_auth_trusted_device_token_hash", "auth_trusted_device", ["token_hash"], unique=False)
    op.create_index("ix_auth_trusted_device_expires_at", "auth_trusted_device", ["expires_at"], unique=False)

    op.create_table(
        "auth_passkey_credential",
        sa.Column("id", sa.Uuid(), primary_key=True, nullable=False),
        sa.Column("user_id", sa.Integer(), sa.ForeignKey("auth_user.id", ondelete="CASCADE"), nullable=False),
        sa.Column("credential_id", sa.String(length=512), nullable=False),
        sa.Column("public_key", sa.Text(), nullable=False),
        sa.Column("sign_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("transports", sa.JSON(), nullable=False),
        sa.Column("aaguid", sa.String(length=64), nullable=True),
        sa.Column("friendly_name", sa.String(length=255), nullable=True),
        sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.UniqueConstraint("credential_id"),
    )
    op.create_index("ix_auth_passkey_credential_user_id", "auth_passkey_credential", ["user_id"], unique=False)
    op.create_index("ix_auth_passkey_credential_credential_id", "auth_passkey_credential", ["credential_id"], unique=False)


def downgrade() -> None:
    op.drop_index("ix_auth_passkey_credential_credential_id", table_name="auth_passkey_credential")
    op.drop_index("ix_auth_passkey_credential_user_id", table_name="auth_passkey_credential")
    op.drop_table("auth_passkey_credential")

    op.drop_index("ix_auth_trusted_device_expires_at", table_name="auth_trusted_device")
    op.drop_index("ix_auth_trusted_device_token_hash", table_name="auth_trusted_device")
    op.drop_index("ix_auth_trusted_device_user_id", table_name="auth_trusted_device")
    op.drop_table("auth_trusted_device")

    op.drop_index("ix_auth_recovery_code_code_hash", table_name="auth_recovery_code")
    op.drop_index("ix_auth_recovery_code_user_id", table_name="auth_recovery_code")
    op.drop_table("auth_recovery_code")

    op.drop_index("ix_auth_login_challenge_expires_at", table_name="auth_login_challenge")
    op.drop_index("ix_auth_login_challenge_token_hash", table_name="auth_login_challenge")
    op.drop_index("ix_auth_login_challenge_user_id", table_name="auth_login_challenge")
    op.drop_table("auth_login_challenge")

    op.drop_column("auth_user_security", "two_factor_confirmed_at")
    op.drop_column("auth_user_security", "pending_totp_secret_protected")
    op.drop_column("auth_user_security", "totp_secret_protected")
