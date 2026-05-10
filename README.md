# auth-kit v2

auth-kit v2 ist ein eigenständiges Identity-, Profil-, Rollen- und Session-System mit FastAPI-Backend und eigener React-Weboberfläche.

Es verwaltet:

- Login und Registrierung
- Benutzeridentität und Profile
- Adressen, Kontakt- und Webdaten
- Preferences und Security-Status
- Sessions/Geräte
- Admin-Userverwaltung und Rollen

Andere Apps können auth-kit später optional nutzen, aber auth-kit bringt keine Fachlogik fremder Anwendungen mit.

## Setup

1. Python-Venv anlegen:

```bash
python3 -m venv .venv
```

2. Backend-Dependencies installieren:

```bash
.venv/bin/pip install -e '.[dev]'
```

3. Frontend-Dependencies installieren:

```bash
npm --prefix web install
```

Alternativ installiert `make setup` beide Seiten:

```bash
make setup
```

## ENV

Eine lokale Basis-Konfiguration liegt in [.env.example](/srv/dev/auth-kit/.env.example).

Wichtige Variablen:

```env
AUTHKIT_DATABASE_URL=postgresql+psycopg://authkit:authkit@127.0.0.1:5432/authkit
AUTHKIT_SESSION_COOKIE_NAME=authkit_sid
AUTHKIT_SESSION_COOKIE_SECURE=false
AUTHKIT_SESSION_COOKIE_SAMESITE=lax
AUTHKIT_SESSION_TTL_DAYS=30
AUTHKIT_UPLOAD_DIR=./data/uploads
AUTHKIT_AVATAR_MAX_MB=5

AUTHKIT_BOOTSTRAP_OWNER_ENABLED=true
AUTHKIT_BOOTSTRAP_OWNER_EMAIL=owner@example.com
AUTHKIT_BOOTSTRAP_OWNER_USERNAME=owner
AUTHKIT_BOOTSTRAP_OWNER_PASSWORD=PrimaryPass!123
AUTHKIT_BOOTSTRAP_OWNER_DISPLAY_NAME="Bootstrap Owner"
```

## Datenbank starten

Für die lokale Entwicklung liegt eine Postgres-Definition in [docker-compose.yml](/srv/dev/auth-kit/docker-compose.yml).

Start:

```bash
make db-up
```

Stop:

```bash
make db-down
```

## Migrationen

Migrationen werden mit Alembic ausgeführt:

```bash
make migrate
```

`make migrate` und `make dev-api` lesen beide dieselbe `AUTHKIT_DATABASE_URL` aus der Shell-Umgebung oder aus `.env`.

## Entwicklung

Backend starten:

```bash
make dev-api
```

Frontend starten:

```bash
make dev-web
```

Backend und Frontend zusammen starten:

```bash
make dev
```

Standardports:

- API: `http://127.0.0.1:8000`
- Web: `http://127.0.0.1:5173`

Die Vite-Entwicklung nutzt einen Proxy auf `/api` zum FastAPI-Backend. Avatare werden über kontrollierte API-Endpunkte unter `/api/auth/...` ausgeliefert, nicht über direkt sichtbare Dateipfade.

Wenn noch kein Owner existiert, zeigt die Weboberfläche automatisch einen First-Owner-Setup-Flow über `/api/setup/status` und `/api/setup/owner`.

## Tests

```bash
make test
```

## Lint / Format / Typecheck

```bash
make check
```

`make check` führt aus:

- `ruff check`
- `ruff format --check`
- `mypy src`
- `npm run lint`
- `npm run typecheck`
- `npm run build`

## Frontend-Struktur

Die Weboberfläche liegt unter [web](/srv/dev/auth-kit/web) und enthält:

- Login und Registrierung
- `/me`- und Account-Ansicht
- Profil-, Avatar-, Kontakt- und Preferences-Editoren
- Adressverwaltung
- Session-/Geräteübersicht
- Admin-Userliste und Admin-Editor
- Rollenverwaltung

## Backend-Struktur

Das Backend liegt unter [src/auth_kit](/srv/dev/auth-kit/src/auth_kit) und setzt auf:

- FastAPI
- SQLAlchemy 2.x
- Alembic
- Pydantic v2
- Argon2id

Architektur und Backend-Plan:

- [auth-kit-v2.md](/srv/dev/auth-kit/docs/architecture/auth-kit-v2.md)
- [auth-kit-v2-backend-plan.md](/srv/dev/auth-kit/docs/architecture/auth-kit-v2-backend-plan.md)
