from __future__ import annotations

from collections.abc import Iterable


def has_role(subject: object, *roles: str) -> bool:
    raw_roles: Iterable[str]
    if hasattr(subject, "roles"):
        raw_roles = getattr(subject, "roles")
    else:
        raw_roles = subject  # type: ignore[assignment]
    subject_roles = {str(role).lower() for role in raw_roles}
    return any(role.lower() in subject_roles for role in roles)
