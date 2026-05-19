from __future__ import annotations

from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from .core.config import Settings, get_settings
from .db import create_db_engine, create_session_factory
from .errors import ApiError
from .rate_limit import InMemoryRateLimiter
from .router import api_router
from .services import ensure_bootstrap_owner


def ensure_upload_directories(settings: Settings) -> Path:
    upload_root = Path(settings.upload_dir)
    upload_root.mkdir(parents=True, exist_ok=True)
    (upload_root / "avatars").mkdir(parents=True, exist_ok=True)
    return upload_root


def http_status_error_code(status_code: int) -> str:
    return {
        400: "bad_request",
        401: "unauthorized",
        403: "forbidden",
        404: "not_found",
        409: "conflict",
        422: "validation_error",
    }.get(status_code, f"http_{status_code}")


def create_app(settings: Settings | None = None) -> FastAPI:
    app_settings = settings or get_settings()
    engine = create_db_engine(app_settings)
    session_factory = create_session_factory(engine)
    ensure_upload_directories(app_settings)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        ensure_bootstrap_owner(session_factory, app_settings)
        yield
        engine.dispose()

    app = FastAPI(
        title=app_settings.app_name,
        version=app_settings.app_version,
        lifespan=lifespan,
    )
    if app_settings.cors_allow_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=app_settings.cors_allow_origins,
            allow_credentials=True,
            allow_methods=["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
            allow_headers=["Content-Type", app_settings.csrf_header_name],
        )
    app.state.settings = app_settings
    app.state.db_engine = engine
    app.state.session_factory = session_factory
    app.state.rate_limiter = InMemoryRateLimiter()

    @app.middleware("http")
    async def apply_security_headers(request, call_next):
        response = await call_next(request)
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
        response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        response.headers.setdefault("Cross-Origin-Opener-Policy", "same-origin")
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
        )
        if app_settings.session_cookie_secure:
            response.headers.setdefault(
                "Strict-Transport-Security",
                f"max-age={app_settings.security_hsts_max_age}; includeSubDomains",
            )
        if request.url.path.startswith("/api/auth") or request.url.path.startswith("/api/admin"):
            response.headers.setdefault("Cache-Control", "no-store")
            response.headers.setdefault("Pragma", "no-cache")
        return response

    @app.exception_handler(ApiError)
    async def handle_api_error(_: object, exc: ApiError) -> JSONResponse:
        return JSONResponse(status_code=exc.status_code, content=exc.to_response())

    @app.exception_handler(HTTPException)
    async def handle_http_exception(_: object, exc: HTTPException) -> JSONResponse:
        if isinstance(exc.detail, dict):
            error_code = str(exc.detail.get("error_code") or http_status_error_code(exc.status_code))
            message = str(exc.detail.get("message") or exc.detail.get("detail") or "Request failed.")
            details = exc.detail.get("details")
            content = {"error_code": error_code, "message": message}
            if details is not None:
                content["details"] = details
            return JSONResponse(status_code=exc.status_code, content=content)
        message = str(exc.detail) if exc.detail else "Request failed."
        return JSONResponse(
            status_code=exc.status_code,
            content={"error_code": http_status_error_code(exc.status_code), "message": message},
        )

    @app.exception_handler(RequestValidationError)
    async def handle_request_validation_error(_: object, exc: RequestValidationError) -> JSONResponse:
        return JSONResponse(
            status_code=422,
            content={
                "error_code": "validation_error",
                "message": "Request validation failed.",
                "details": exc.errors(),
            },
        )

    app.include_router(api_router)
    return app
