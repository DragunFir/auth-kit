from __future__ import annotations

from dataclasses import dataclass


@dataclass(slots=True)
class ApiError(Exception):
    status_code: int
    error_code: str
    message: str

    def to_response(self) -> dict[str, object]:
        return {
            "error_code": self.error_code,
            "message": self.message,
        }


class PasswordValidationError(ApiError):
    pass
