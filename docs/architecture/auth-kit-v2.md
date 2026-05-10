# auth-kit v2 Architecture

## 1. Ziel

auth-kit v2 ist ein eigenständiges Authentifizierungs- und Benutzerverwaltungssystem.

Es soll standalone laufen können, aber später optional von NEXUS und anderen Apps genutzt werden.

auth-kit v2 ersetzt die alte auth-kit-Implementierung vollständig.

## 2. Grundprinzipien

- Standalone-first
- API-first
- Selfhosted
- Keine harte Abhängigkeit zu NEXUS
- Lokale Benutzerverwaltung
- Lokale Rollen und Rechte
- Später optional OIDC/SSO
- Sichere Cookie-basierte Sessions
- Saubere Migration auf neue Architektur

## 3. Zielsysteme

auth-kit v2 soll später nutzbar sein für:

- NEXUS Main Hub
- MakerDesk
- KORA
- Writer
- Calendar
- Musiform Studio
- Engineering Studio
- HomeBib
- GameHub
- AVALOR
- weitere Selfhost-Apps

## 4. Modi

### Standalone Mode

auth-kit läuft als eigenes System mit eigener Datenbank, eigenen Benutzern und eigenen Sessions.

### Integrated Mode

Andere Apps können auth-kit als zentrale Login-Instanz nutzen.

### Future OIDC Mode

auth-kit kann später als OIDC Provider dienen.

OIDC wird vorbereitet, aber im MVP noch nicht umgesetzt.

## 5. Tech Stack

### Backend

- Python
- FastAPI
- SQLAlchemy 2.x
- Alembic
- PostgreSQL
- Pydantic v2

### Security

- Argon2id für Passwort-Hashing
- HttpOnly Cookies
- SameSite=Lax als Standard
- Secure Cookies per ENV steuerbar
- Session-Token werden nur gehasht gespeichert
- Bootstrap-Owner per ENV

### Frontend später

- React
- Vite
- TypeScript
- MUI

## 6. Datenmodell MVP

### auth_user

Speichert nur Login, Identität und Rollen.

Nicht in `auth_user` gespeichert werden Profil-, Adress-, Kontakt-, Präferenz- oder Security-Details.

Felder:

- id
- email
- username
- display_name
- password_hash
- roles
- is_active
- is_verified
- created_at
- updated_at
- last_login_at

### auth_user_profile

1:1-Tabelle für Profilinformationen.

Felder:

- user_id
- avatar_url
- bio
- locale
- timezone
- created_at
- updated_at

Wichtig:

- `avatar_url` speichert nur eine URL oder einen Pfad auf ein externes Asset.
- Es werden keine Bilddaten in der Datenbank gespeichert.

### auth_user_address

1:n-Tabelle für mehrere Adressen pro Benutzer.

Felder:

- id
- user_id
- type
- name
- street_line_1
- street_line_2
- postal_code
- city
- state
- country
- is_default
- created_at
- updated_at

Wichtig:

- Ein Benutzer kann mehrere Adressen besitzen.
- Alle Adressen referenzieren `auth_user` per Foreign Key mit `ON DELETE CASCADE`.

### auth_user_contact

1:1-Tabelle für Kontaktinformationen.

Felder:

- user_id
- phone
- website
- social_links
- created_at
- updated_at

### auth_user_preferences

1:1-Tabelle für Benutzerpräferenzen.

Felder:

- user_id
- theme
- language
- notification_settings
- created_at
- updated_at

### auth_user_security

1:1-Tabelle für sicherheitsrelevante Statusdaten.

Felder:

- user_id
- two_factor_enabled
- passkeys_enabled
- recovery_codes_enabled
- trusted_devices_enabled
- created_at
- updated_at

Wichtig:

- Passwort-Hashes bleiben ausschließlich in `auth_user`.
- Security-Statusdaten liegen getrennt, damit sicherheitskritische Flows später sauber erweitert werden können.

### auth_session

Speichert aktive Sessions.

Felder:

- id
- user_id
- token_hash
- user_agent
- ip_address
- created_at
- updated_at
- expires_at
- revoked_at

### auth_audit_log

Speichert sicherheitsrelevante Ereignisse.

Felder:

- id
- actor_user_id
- event_type
- target_user_id
- ip_address
- user_agent
- metadata_json
- created_at
- updated_at

## 7. Rollenmodell MVP

Standardrollen:

- user
- admin
- owner

Bedeutung:

- user: normaler Benutzer
- admin: Benutzerverwaltung
- owner: volle Systemkontrolle

Der erste Owner wird per ENV beim Start angelegt.

## 8. API MVP

### Public Auth

- POST /api/auth/register
- POST /api/auth/login
- POST /api/auth/logout
- GET /api/auth/me
- POST /api/auth/change-password
- GET /api/auth/profile
- PATCH /api/auth/profile
- GET /api/auth/addresses
- POST /api/auth/addresses
- PATCH /api/auth/addresses/{address_id}
- DELETE /api/auth/addresses/{address_id}
- GET /api/auth/contact
- PATCH /api/auth/contact
- GET /api/auth/preferences
- PATCH /api/auth/preferences
- GET /api/auth/security
- PATCH /api/auth/security

### Session Management

- GET /api/auth/sessions
- DELETE /api/auth/sessions/{session_id}
- DELETE /api/auth/sessions/current

### Admin

- GET /api/admin/users
- POST /api/admin/users
- GET /api/admin/users/{user_id}
- PATCH /api/admin/users/{user_id}
- POST /api/admin/users/{user_id}/reset-password
- POST /api/admin/users/{user_id}/disable
- POST /api/admin/users/{user_id}/enable

Admin-Regeln:

- Admin darf Basisdaten und nicht-sensitive Benutzerdaten lesen und verwalten.
- Passwortänderungen laufen nur über dedizierte Passwort-Endpoints.
- Security-Daten dürfen nicht über generische Admin-Update-Payloads unsicher überschrieben werden.

### System

- GET /api/health
- GET /api/version

### /api/auth/me

`GET /api/auth/me` liefert Basisdaten aus `auth_user` sowie optionale eingebettete Daten aus:

- `profile`
- `preferences`

Die zusätzlichen Bereiche sind optional, damit Clients fehlende Detaildaten robust behandeln können.

## 9. Passwortregeln MVP

Passwörter müssen:

- mindestens 12 Zeichen lang sein
- mindestens einen Kleinbuchstaben enthalten
- mindestens einen Großbuchstaben enthalten
- mindestens eine Zahl enthalten
- mindestens ein Sonderzeichen enthalten
- nicht die Email enthalten
- nicht den Username enthalten

## 10. Cookie-Strategie

Cookie-Name:

- authkit_sid

Cookie-Eigenschaften:

- HttpOnly
- SameSite=Lax
- Secure per ENV
- Path=/
- TTL per ENV

ENV-Beispiele:

- AUTHKIT_SESSION_COOKIE_NAME=authkit_sid
- AUTHKIT_SESSION_COOKIE_SECURE=false
- AUTHKIT_SESSION_COOKIE_SAMESITE=lax
- AUTHKIT_SESSION_COOKIE_PATH=/
- AUTHKIT_SESSION_TTL_DAYS=30

## 11. Bootstrap Owner

Der erste Owner darf nur angelegt werden, wenn folgende ENV-Werte gesetzt sind:

- AUTHKIT_BOOTSTRAP_OWNER_ENABLED=true
- AUTHKIT_BOOTSTRAP_OWNER_EMAIL
- AUTHKIT_BOOTSTRAP_OWNER_USERNAME
- AUTHKIT_BOOTSTRAP_OWNER_PASSWORD
- AUTHKIT_BOOTSTRAP_OWNER_DISPLAY_NAME

Wenn bereits ein Owner existiert, wird kein neuer Owner erzeugt.

## 12. Konfiguration

Alle Einstellungen laufen zentral über:

```text
app/core/config.py
```

## 13. Persistenzregeln

- Alle neuen User-Detailtabellen werden als SQLAlchemy-2.x-Modelle umgesetzt.
- Alembic-Migrationen müssen die neuen Tabellen und Foreign Keys anlegen.
- Alle Foreign Keys auf `auth_user` verwenden `ON DELETE CASCADE`.
- Alle neuen Tabellen besitzen `created_at` und `updated_at`.
- Pydantic-v2-Schemas werden getrennt für Read, Create und Patch vorbereitet.

## 14. Implementierungsgrenzen im ersten Backend-Schritt

- Kein Frontend und keine UI
- Keine Bildspeicherung in der Datenbank
- Keine OIDC-Umsetzung in diesem Schritt
- Keine 2FA- oder Passkey-Enrollment-Flows in diesem Schritt
- Vorbereitung der Security-Tabelle und APIs erfolgt dennoch im Backend
