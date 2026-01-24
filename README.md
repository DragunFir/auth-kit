# auth-kit

auth-kit ist ein **modulares Authentifizierungs-Kit für Python/FastAPI** mit dem Fokus auf
**Standalone-First**, **Selfhosting** und **optionaler SSO-Integration**.

Jede Anwendung kann vollständig eigenständig laufen (eigene User, eigene Datenbank),
kann aber optional über OAuth2 / OpenID Connect an einen zentralen Identity Provider
angebunden werden.

---

## Zielsetzung

- Wiederverwendbare Authentifizierungsbasis für mehrere Projekte
- Keine Abhängigkeit von einem zentralen Auth-Server
- Optionale Integration in bestehende SSO-Infrastrukturen
- Klare Trennung von Authentifizierung und Anwendungslogik

---

## Funktionsumfang

### Lokale Authentifizierung (Standard)
- Login per E-Mail + Passwort
- Passwort-Hashing (bcrypt)
- Cookie-basierte Sessions (HttpOnly)
- Session-Persistenz in PostgreSQL

### Rollen & Zugriff
- Rollenbasiertes Modell (`user`, `admin`, `owner`)
- Erweiterbar für eigene Permission-Logik
- Bootstrap-Owner per ENV möglich

### OAuth2 / OpenID Connect (optional)
- Unterstützung gängiger IdPs (z. B. Keycloak, Authentik, Authelia)
- Login via Authorization Code Flow
- Claim-Mapping auf lokale User & Rollen
- Aktivierung ausschließlich per Environment-Variablen

---

## env
### Pflicht 
AUTH_DATABASE_URL=postgresql+psycopg://user:password@localhost:5432/app_db

### Session & Cookies  
AUTH_SESSION_COOKIE_NAME=auth_sid
AUTH_SESSION_TTL_DAYS=30
AUTH_COOKIE_SECURE=false
AUTH_COOKIE_SAMESITE=lax
AUTH_COOKIE_DOMAIN=

- In produktiven HTTPS-Umgebungen sollte AUTH_COOKIE_SECURE=true gesetzt werden.  

### Lokale Authentifizierung  
AUTH_ALLOW_LOCAL_LOGIN=true

### OAuth2 / OpenID Connect (optional)
AUTH_OIDC_ENABLED=true
AUTH_OIDC_ISSUER=https://idp.example.com/realms/example
AUTH_OIDC_CLIENT_ID=example-app
AUTH_OIDC_CLIENT_SECRET=secret
AUTH_OIDC_REDIRECT_URL=https://app.example.com/api/auth/oidc/callback

AUTH_OIDC_SCOPES=openid profile email
AUTH_OIDC_CLAIM_EMAIL=email
AUTH_OIDC_CLAIM_NAME=name
AUTH_OIDC_CLAIM_GROUPS=groups

### Rollen & Bootstrap
AUTH_DEFAULT_ROLES=user
AUTH_OWNER_EMAIL=admin@example.com

- Meldet sich diese E-Mail per OIDC an, wird automatisch die Rolle owner vergeben.

## API-Endpoints
```
| Methode | Pfad                  | Beschreibung        |
| ------- | --------------------- | ------------------- |
| POST    | `/auth/login`         | Lokaler Login       |
| POST    | `/auth/logout`        | Session beenden     |
| GET     | `/auth/me`            | Aktueller Benutzer  |
| GET     | `/auth/oidc/login`    | OIDC Login Redirect |
| GET     | `/auth/oidc/callback` | OIDC Callback       |
```

## Sicherheitshinweise
- Cookies sollten in produktiven Umgebungen ausschließlich über HTTPS verwendet werden
- OIDC-State und Nonce sind im MVP minimal gehalten
- Rollen aus OIDC-Claims nur verwenden, wenn der IdP vertrauenswürdig konfiguriert ist