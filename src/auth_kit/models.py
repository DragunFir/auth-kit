from __future__ import annotations

from dataclasses import dataclass
from typing import Sequence


@dataclass(frozen=True)
class User:
    id: int
    email: str
    display_name: str | None
    roles: Sequence[str]
    is_active: bool
