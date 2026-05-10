from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy import text
from sqlalchemy.orm import Session

from ..core.config import Settings
from ..deps import get_db, get_settings_dep
from ..schemas import HealthResponse, VersionResponse

router = APIRouter(tags=["system"])


@router.get("/health", response_model=HealthResponse)
def health(db: Session = Depends(get_db)) -> HealthResponse:
    db.execute(text("SELECT 1"))
    return HealthResponse(status="ok", database="ok")


@router.get("/version", response_model=VersionResponse)
def version(settings: Settings = Depends(get_settings_dep)) -> VersionResponse:
    return VersionResponse(name=settings.app_name, version=settings.app_version)
