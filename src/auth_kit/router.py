from __future__ import annotations

from fastapi import APIRouter

from .routes.admin import router as admin_routes
from .routes.auth import router as auth_routes
from .routes.setup import router as setup_routes
from .routes.system import router as system_routes

api_router = APIRouter(prefix="/api")
api_router.include_router(auth_routes)
api_router.include_router(admin_routes)
api_router.include_router(setup_routes)
api_router.include_router(system_routes)

auth_router = api_router
