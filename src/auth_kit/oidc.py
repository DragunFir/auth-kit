from __future__ import annotations

from dataclasses import dataclass
from typing import Any
import httpx

from .settings import Settings


@dataclass(frozen=True)
class OidcDiscovery:
    authorization_endpoint: str
    token_endpoint: str
    jwks_uri: str
    userinfo_endpoint: str | None


async def discover(settings: Settings) -> OidcDiscovery:
    if not settings.oidc_issuer:
        raise RuntimeError("OIDC issuer missing")
    url = settings.oidc_issuer.rstrip("/") + "/.well-known/openid-configuration"
    async with httpx.AsyncClient(timeout=10) as client:
        r = await client.get(url)
        r.raise_for_status()
        data = r.json()
    return OidcDiscovery(
        authorization_endpoint=data["authorization_endpoint"],
        token_endpoint=data["token_endpoint"],
        jwks_uri=data["jwks_uri"],
        userinfo_endpoint=data.get("userinfo_endpoint"),
    )


async def exchange_code_for_tokens(settings: Settings, token_endpoint: str, code: str) -> dict[str, Any]:
    if not (settings.oidc_client_id and settings.oidc_client_secret and settings.oidc_redirect_url):
        raise RuntimeError("OIDC client config missing (client_id/client_secret/redirect_url)")
    form = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": settings.oidc_redirect_url,
        "client_id": settings.oidc_client_id,
        "client_secret": settings.oidc_client_secret,
    }
    async with httpx.AsyncClient(timeout=10) as client:
        r = await client.post(token_endpoint, data=form)
        r.raise_for_status()
        return r.json()


async def fetch_userinfo(userinfo_endpoint: str, access_token: str) -> dict[str, Any]:
    async with httpx.AsyncClient(timeout=10) as client:
        r = await client.get(
            userinfo_endpoint,
            headers={"Authorization": f"Bearer {access_token}"},
        )
        r.raise_for_status()
        return r.json()
