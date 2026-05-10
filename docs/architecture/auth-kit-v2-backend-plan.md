# auth-kit v2 Backend Plan

## 1. Ziel des nächsten Backend-Schnitts

Der nächste Schnitt erweitert auth-kit v2 um getrennte User-Detailtabellen und Self-Service-APIs, ohne `auth_user` zu einem Sammelcontainer für alle Profildaten zu machen.

## 2. Modellgrenzen

### auth_user

Bleibt ausschließlich für:

- Login-Identität
- Passwort-Hash
- Rollen
- Aktiv-/Verifizierungsstatus
- Login- und Änderungszeitpunkte

### Separate Detailtabellen

Es werden eingeführt:

- `auth_user_profile`
- `auth_user_address`
- `auth_user_contact`
- `auth_user_preferences`
- `auth_user_security`

Regeln:

- `profile`, `contact`, `preferences` und `security` sind 1:1 zu `auth_user`
- `address` ist 1:n zu `auth_user`
- alle Foreign Keys auf `auth_user` nutzen `ON DELETE CASCADE`
- `avatar_url` speichert nur Referenzen, keine Binärdaten

## 3. Migrationen

Alembic muss:

1. die neuen Tabellen anlegen
2. Indizes und Constraints setzen
3. bestehende Benutzer auf Default-1:1-Datensätze backfillen
4. das Schema für SQLAlchemy-2.x-Modelle und Pydantic-v2-Schemas vorbereiten

## 4. Schemas

Benötigte Schema-Gruppen:

- Read-Schemas für `profile`, `address`, `contact`, `preferences`, `security`
- Create-Schema für neue Adressen
- Patch-Schemas für Self-Service-Updates
- erweiterte `/me`-Antwort mit optionalem `profile` und `preferences`
- Admin-Detail-Schema für lesende Admin-Ansichten

Wichtig:

- Patch-Schemas arbeiten partiell
- unbekannte Felder werden verboten
- Security- und Passwortfelder werden nicht über generische Admin-Update-Schemas freigegeben

## 5. Services

Services müssen:

- fehlende 1:1-Datensätze sicher erzeugen oder laden
- Profil-, Kontakt-, Präferenz- und Security-Updates kapseln
- mehrere Adressen pro User verwalten
- Default-Adresslogik sauber behandeln
- Audit-Events für Self-Service- und Admin-Änderungen schreiben

## 6. Routen

### Self-Service

- `GET /api/auth/profile`
- `PATCH /api/auth/profile`
- `GET /api/auth/addresses`
- `POST /api/auth/addresses`
- `PATCH /api/auth/addresses/{address_id}`
- `DELETE /api/auth/addresses/{address_id}`
- `GET /api/auth/contact`
- `PATCH /api/auth/contact`
- `GET /api/auth/preferences`
- `PATCH /api/auth/preferences`
- `GET /api/auth/security`
- `PATCH /api/auth/security`

### Admin

Bestehende Admin-Routen bleiben erhalten und werden so erweitert, dass Admins Benutzerdaten lesen und nicht-sensitive Daten verwalten können.

Grenzen:

- keine direkte `password_hash`-Manipulation
- keine unsichere generische Security-Überschreibung
- Passwortänderungen nur über dedizierte Reset- oder Change-Endpoints

## 7. Tests

Pflichtfälle:

- Profil lesen und ändern
- Kontakt, Preferences und Security lesen und patchen
- Adresse erstellen, ändern und löschen
- mehrere Adressen pro User
- nur eingeloggte Benutzer dürfen eigene Daten ändern
- fremde Adressen sind nicht änderbar
- `/api/auth/me` liefert Basisdaten plus optional `profile` und `preferences`
- Admin kann Userdaten lesen und nicht-sensitive Daten verwalten
- Admin kann Passwort/Security nicht über generische Update-Payloads überschreiben

## 8. Nicht Teil dieses Schritts

- Frontend-UI
- Avatar-Upload-Handling
- OIDC-Profile-Mapping
- Passkey- oder 2FA-Enrollment
