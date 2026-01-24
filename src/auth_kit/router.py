from __future__ import annotations

from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, EmailStr
from sqlalchemy import text
from sqlalchemy.engine import Engine

from .deps import current_user, get_engine, get_settings_dep
from .models import User
from .security import hash_password, verify_password
from .sessions import create_session, delete_session
from .settings import Settings
from .rbac import has_role
from .oidc import discover, exchange_code_for_tokens, fetch_userinfo


router = APIRouter(prefix="/auth", tags=["auth"])


class LoginIn(BaseModel):
    email: EmailStr
    password: str


class MeOut(BaseModel):
    id: int
    email: str
    displayName: str | None
    roles: list[str]


def _set_cookie(resp: Response, settings: Settings, sid: UUID) -> None:
    resp.set_cookie(
        key=settings.session_cookie_name,
        value=str(sid),
        httponly=True,
        secure=settings.cookie_secure,
        samesite=settings.cookie_samesite,
        domain=settings.cookie_domain,
        max_age=settings.session_ttl_days * 24 * 3600,
        path="/",
    )


def _clear_cookie(resp: Response, settings: Settings) -> None:
    resp.delete_cookie(
        key=settings.session_cookie_name,
        path="/",
        domain=settings.cookie_domain,
    )


@router.post("/login")
def login_local(
    payload: LoginIn,
    response: Response,
    engine: Engine = Depends(get_engine),
    settings: Settings = Depends(get_settings_dep),
) -> dict[str, Any]:
    if not settings.allow_local_login:
        raise HTTPException(status_code=400, detail="Local login disabled")

    q = text("""
        SELECT id, email, password_hash, display_name, roles, is_active
        FROM auth_user
        WHERE email = :email
        LIMIT 1
    """)
    with engine.begin() as conn:
        row = conn.execute(q, {"email": str(payload.email)}).mappings().first()

    if not row or not row["password_hash"]:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    if not bool(row["is_active"]):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Inactive user")

    if not verify_password(settings, payload.password, str(row["password_hash"])):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    sid = create_session(engine, settings, int(row["id"]))
    _set_cookie(response, settings, sid)
    return {"ok": True}


@router.get("/me", response_model=MeOut)
def me(user: User = Depends(current_user)) -> MeOut:
    return MeOut(id=user.id, email=user.email, displayName=user.display_name, roles=list(user.roles))


@router.post("/logout")
def logout(request: Request, response: Response, engine: Engine = Depends(get_engine), settings: Settings = Depends(get_settings_dep)) -> dict[str, Any]:
    raw = request.cookies.get(settings.session_cookie_name)
    if raw:
        try:
            delete_session(engine, UUID(raw))
        except Exception:
            pass
    _clear_cookie(response, settings)
    return {"ok": True}


# -------- OIDC --------

@router.get("/oidc/login")
async def oidc_login(settings: Settings = Depends(get_settings_dep)) -> Response:
    if not settings.oidc_enabled:
        raise HTTPException(status_code=400, detail="OIDC disabled")
    if not (settings.oidc_client_id and settings.oidc_redirect_url):
        raise HTTPException(status_code=500, detail="OIDC not configured")

    d = await discover(settings)
    # Minimal state handling: in production, store state+nonce in short-lived server store
    # For MVP we skip nonce and use a simple state, but you SHOULD harden this.
    state = "mvp-state"
    scopes = settings.oidc_scopes
    url = (
        f"{d.authorization_endpoint}"
        f"?response_type=code"
        f"&client_id={settings.oidc_client_id}"
        f"&redirect_uri={settings.oidc_redirect_url}"
        f"&scope={scopes}"
        f"&state={state}"
    )
    return Response(status_code=307, headers={"Location": url})


@router.get("/oidc/callback")
async def oidc_callback(
    code: str,
    response: Response,
    engine: Engine = Depends(get_engine),
    settings: Settings = Depends(get_settings_dep),
) -> dict[str, Any]:
    if not settings.oidc_enabled:
        raise HTTPException(status_code=400, detail="OIDC disabled")

    d = await discover(settings)
    tokens = await exchange_code_for_tokens(settings, d.token_endpoint, code)
    access_token = tokens.get("access_token")
    id_token = tokens.get("id_token")

    # Prefer userinfo if available; id_token parsing/verification can be added later
    claims: dict[str, Any] = {}
    if d.userinfo_endpoint and access_token:
        claims = await fetch_userinfo(d.userinfo_endpoint, access_token)
    elif isinstance(tokens.get("userinfo"), dict):
        claims = tokens["userinfo"]
    else:
        # MVP fallback: minimal; real impl should verify id_token and read claims
        raise HTTPException(status_code=500, detail="No userinfo available (enable userinfo or implement id_token verification)")

    email_key = settings.oidc_claim_email
    name_key = settings.oidc_claim_name
    groups_key = settings.oidc_claim_groups

    email = claims.get(email_key)
    if not email:
        raise HTTPException(status_code=400, detail=f"OIDC claim '{email_key}' missing")

    display_name = claims.get(name_key)
    groups = claims.get(groups_key) or []
    if isinstance(groups, str):
        groups = [groups]

    # Map roles
    roles = [r.strip() for r in settings.default_roles.split(",") if r.strip()]
    # Example mapping: if groups contain "admin" -> add admin
    groups_lower = {str(g).lower() for g in groups}
    if "owner" in groups_lower:
        roles.append("owner")
    if "admin" in groups_lower:
        roles.append("admin")

    # Owner bootstrap by email
    if settings.owner_email and str(email).lower() == settings.owner_email.lower():
        if "owner" not in roles:
            roles.append("owner")

    # Upsert user by email
    q = text("""
        INSERT INTO auth_user (email, display_name, roles, is_active)
        VALUES (:email, :dn, :roles, TRUE)
        ON CONFLICT (email)
        DO UPDATE SET
          display_name = EXCLUDED.display_name,
          roles = EXCLUDED.roles,
          updated_at = now()
        RETURNING id
    """)
    with engine.begin() as conn:
        user_id = conn.execute(q, {"email": str(email), "dn": display_name, "roles": roles}).scalar_one()

    sid = create_session(engine, settings, int(user_id))
    _set_cookie(response, settings, sid)
    return {"ok": True, "idTokenPresent": bool(id_token)}
