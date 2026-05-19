# auth-kit 1.0

auth-kit ist ein eigenständiger Auth-, Profil-, Rollen- und Session-Service mit FastAPI-Backend, Alembic-Migrationen und React-Weboberfläche.

Der aktuelle Stand umfasst:

- Registrierung und Login mit serverseitigen Cookie-Sessions
- Profil-, Avatar-, Kontakt-, Präferenz- und Adressverwaltung
- Admin-Userverwaltung mit Rollen (`user`, `admin`, `owner`)
- Passwort-Änderung und Passwort-zurücksetzen-Flow
- Audit-Logs, Rate-Limits, CSRF-Schutz und Security-Header

OIDC/SSO ist im aktuellen Release nicht umgesetzt und wird hier bewusst nicht dokumentiert.

## Schnellstart

```bash
python3 -m venv .venv
.venv/bin/pip install -e '.[dev]'
npm --prefix web install
```

Alternativ:

```bash
make setup
```

## Umgebung

Die Basis-Konfiguration liegt in `.env.example`. Alle Variablen nutzen das Prefix `AUTHKIT_`.

Wichtige Variablen:

```env
AUTHKIT_DATABASE_URL=postgresql+psycopg://authkit:authkit@127.0.0.1:5432/authkit
AUTHKIT_SESSION_COOKIE_NAME=authkit_sid
AUTHKIT_SESSION_COOKIE_SECURE=false
AUTHKIT_SESSION_COOKIE_SAMESITE=lax
AUTHKIT_SESSION_TTL_DAYS=30
AUTHKIT_CORS_ALLOW_ORIGINS=http://127.0.0.1:5173,http://localhost:5173
AUTHKIT_UPLOAD_DIR=./data/uploads
AUTHKIT_AVATAR_MAX_MB=5

AUTHKIT_PASSWORD_RESET_TTL_MINUTES=30
AUTHKIT_MAIL_MODE=dev
AUTHKIT_PASSWORD_RESET_URL_BASE=http://127.0.0.1:5173/reset-password
AUTHKIT_DEV_MAIL_OUTBOX_ENABLED=true
AUTHKIT_DEV_MAIL_OUTBOX_PATH=./data/dev-mail/outbox.jsonl

AUTHKIT_BOOTSTRAP_OWNER_ENABLED=true
AUTHKIT_BOOTSTRAP_OWNER_EMAIL=owner@example.com
AUTHKIT_BOOTSTRAP_OWNER_USERNAME=owner
AUTHKIT_BOOTSTRAP_OWNER_PASSWORD=ChangeMeNow!2026
AUTHKIT_BOOTSTRAP_OWNER_DISPLAY_NAME="Bootstrap Owner"
```

Produktivempfehlungen:

- `AUTHKIT_SESSION_COOKIE_SECURE=true`
- `AUTHKIT_CORS_ALLOW_ORIGINS` nur auf explizite Origins setzen
- Bootstrap-Owner nur für initiales Provisioning aktivieren
- Passwort-Reset in Produktion auf `AUTHKIT_MAIL_MODE=smtp` umstellen

Optionale SMTP-Variablen sind in `.env.example` vorbereitet.

## Entwicklung

Postgres lokal starten:

```bash
make db-up
```

Migrationen ausführen:

```bash
make migrate
```

Backend starten:

```bash
make dev-api
```

Frontend starten:

```bash
make dev-web
```

Beides zusammen:

```bash
make dev
```

Standardports:

- API: `http://127.0.0.1:8000`
- Web: `http://127.0.0.1:5173`

Die Vite-Entwicklung nutzt `/api` per Proxy. Avatare werden ausschließlich über kontrollierte API-Routen ausgeliefert.

## Passwort-Reset

Die API stellt bereit:

- `POST /api/auth/forgot-password`
- `POST /api/auth/reset-password`

Eigenschaften:

- Reset-Tokens werden nur gehasht gespeichert
- TTL ist per ENV konfigurierbar
- Responses vermeiden Email-Enumeration
- Im Dev-Modus (`AUTHKIT_MAIL_MODE=dev` oder `log`) wird keine echte Email versendet
- Der Reset-Link erscheint im Backend-Log als `[auth-kit] password reset link for <email>: <url>`
- Optional wird der Link zusätzlich in `data/dev-mail/outbox.jsonl` geschrieben
- Für echte Emails müssen `AUTHKIT_MAIL_MODE=smtp` sowie die SMTP-ENV gesetzt sein

Die Weboberfläche enthält einen vollständigen Forgot-/Reset-Flow.

## Security

Aktiv im aktuellen Stand:

- Argon2id für Passwort-Hashing
- serverseitige Session-Invalidierung bei Logout
- Session-Rotation bei erneutem Login
- CSRF-Schutz für mutierende Requests
- Rate-Limits für Login, Register, Forgot Password und Reset Password
- Security-Header auf API-Antworten
- Audit-Logs für Auth- und Sicherheitsereignisse
- CORS nur über explizite `AUTHKIT_CORS_ALLOW_ORIGINS`

## Historie / Rotation

Frühere Commits enthielten versehentlich Laufzeit-Artefakte und sensible Entwicklungswerte, darunter `.env`, `auth-kit.db`, `data/uploads/` und `.idea/`.

Betroffene Historie:

- `183792c`
- `6b0460f`

Behandle daraus abgeleitete Zugangsdaten als kompromittiert. Insbesondere muss jedes live verwendete Bootstrap-Owner-Passwort rotiert werden.

## Qualitätssicherung

Tests:

```bash
make test
```

Checks:

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
