AUTH_DATABASE_URL=postgresql+psycopg://user:pass@localhost:5432/yourdb
AUTH_SESSION_COOKIE_NAME=kora_sid
AUTH_SESSION_TTL_DAYS=30
AUTH_COOKIE_SECURE=false
AUTH_COOKIE_SAMESITE=lax

AUTH_ALLOW_LOCAL_LOGIN=true

# Optional OIDC
AUTH_OIDC_ENABLED=false
AUTH_OIDC_ISSUER=https://idp.example.com/realms/nexus
AUTH_OIDC_CLIENT_ID=nexus-app
AUTH_OIDC_CLIENT_SECRET=secret
AUTH_OIDC_REDIRECT_URL=https://nexus.example.com/api/auth/oidc/callback
AUTH_OWNER_EMAIL=you@example.com
