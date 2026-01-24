from __future__ import annotations

from datetime import datetime, timedelta, timezone
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.engine import Engine

from .models import User
from .settings import Settings


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def create_session(engine: Engine, settings: Settings, user_id: int) -> UUID:
    expires_at = _utcnow() + timedelta(days=settings.session_ttl_days)
    q = text("""
        INSERT INTO user_session (user_id, expires_at)
        VALUES (:uid, :exp)
        RETURNING id
    """)
    with engine.begin() as conn:
        sid = conn.execute(q, {"uid": user_id, "exp": expires_at}).scalar_one()
    return sid


def delete_session(engine: Engine, sid: UUID) -> None:
    q = text("DELETE FROM user_session WHERE id = :sid")
    with engine.begin() as conn:
        conn.execute(q, {"sid": sid})


def get_user_by_session(engine: Engine, sid: UUID) -> User | None:
    q = text("""
        SELECT u.id, u.email, u.display_name, u.roles, u.is_active
        FROM user_session s
        JOIN auth_user u ON u.id = s.user_id
        WHERE s.id = :sid
          AND s.expires_at > now()
        LIMIT 1
    """)
    with engine.begin() as conn:
        row = conn.execute(q, {"sid": sid}).mappings().first()
    if not row:
        return None
    return User(
        id=int(row["id"]),
        email=str(row["email"]),
        display_name=row["display_name"],
        roles=list(row["roles"] or []),
        is_active=bool(row["is_active"]),
    )
