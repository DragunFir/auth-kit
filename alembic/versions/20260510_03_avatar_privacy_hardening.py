"""harden avatar storage privacy

Revision ID: 20260510_03
Revises: 20260510_02
Create Date: 2026-05-10 23:10:00
"""

from __future__ import annotations

from uuid import uuid4

from alembic import op
import sqlalchemy as sa


revision = "20260510_03"
down_revision = "20260510_02"
branch_labels = None
depends_on = None

LEGACY_AVATAR_ROUTE_PREFIX = "/uploads/avatars/"
AVATAR_ROUTE_PREFIX = "/api/auth/avatars/"


def upgrade() -> None:
    op.add_column("auth_user_profile", sa.Column("avatar_storage_key", sa.String(length=512), nullable=True))

    bind = op.get_bind()
    rows = bind.execute(sa.text("SELECT user_id, avatar_url FROM auth_user_profile WHERE avatar_url IS NOT NULL")).mappings()
    for row in rows:
        avatar_url = row["avatar_url"]
        if not avatar_url:
            continue
        if avatar_url.startswith(LEGACY_AVATAR_ROUTE_PREFIX):
            filename = avatar_url.removeprefix(LEGACY_AVATAR_ROUTE_PREFIX)
            if filename and "/" not in filename and "\\" not in filename:
                bind.execute(
                    sa.text(
                        """
                        UPDATE auth_user_profile
                        SET avatar_url = :avatar_url,
                            avatar_storage_key = :avatar_storage_key
                        WHERE user_id = :user_id
                        """
                    ),
                    {
                        "user_id": row["user_id"],
                        "avatar_url": f"{AVATAR_ROUTE_PREFIX}{uuid4().hex}",
                        "avatar_storage_key": f"avatars/{filename}",
                    },
                )
                continue
        bind.execute(
            sa.text(
                """
                UPDATE auth_user_profile
                SET avatar_url = NULL,
                    avatar_storage_key = NULL
                WHERE user_id = :user_id
                """
            ),
            {"user_id": row["user_id"]},
        )


def downgrade() -> None:
    op.drop_column("auth_user_profile", "avatar_storage_key")
