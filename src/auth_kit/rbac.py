from __future__ import annotations

from .models import User


def has_role(user: User, *roles: str) -> bool:
    user_roles = set(r.lower() for r in user.roles)
    for r in roles:
        if r.lower() in user_roles:
            return True
    return False
