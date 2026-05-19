SHELL := /bin/bash

PYTHON := .venv/bin/python
PIP := .venv/bin/pip
UVICORN := .venv/bin/uvicorn
ALEMBIC := .venv/bin/alembic
NPM := npm --prefix web

.PHONY: setup db-up db-down migrate dev-api dev-web dev test test-mail check

.venv/bin/python:
	python3 -m venv .venv

.venv/.deps-stamp: .venv/bin/python pyproject.toml
	@printf '\n[auth-kit] installing backend dependencies\n'
	@if $(PYTHON) -c "import alembic, argon2, email_validator, fastapi, multipart, mypy, psycopg, pydantic, pydantic_settings, pytest, ruff, sqlalchemy, uvicorn" >/dev/null 2>&1; then \
		printf '[auth-kit] backend dependencies already available in .venv\n'; \
	else \
		$(PIP) install -e '.[dev]'; \
	fi
	@touch $@

web/.deps-stamp: web/package.json web/package-lock.json
	@printf '\n[auth-kit] installing frontend dependencies\n'
	@if [ -d web/node_modules ]; then \
		printf '[auth-kit] frontend dependencies already available in web/node_modules\n'; \
	else \
		cd web && npm install; \
	fi
	@touch $@

setup: .venv/.deps-stamp web/.deps-stamp
	@printf '\n[auth-kit] setup complete\n'

db-up:
	@printf '\n[auth-kit] starting PostgreSQL on port 5432\n'
	@docker compose up -d db

db-down:
	@printf '\n[auth-kit] stopping PostgreSQL\n'
	@docker compose down

migrate: .venv/.deps-stamp
	@printf '\n[auth-kit] applying database migrations using AUTHKIT_DATABASE_URL from environment/.env\n'
	@$(ALEMBIC) upgrade head

dev-api: .venv/.deps-stamp
	@MAIL_MODE=$$($(PYTHON) -c "from auth_kit.core.config import get_settings; print(get_settings().mail_mode)"); \
	OUTBOX=$$($(PYTHON) -c "from auth_kit.core.config import get_settings; s=get_settings(); print(s.dev_mail_outbox_path if s.dev_mail_outbox_enabled and s.mail_mode in {'dev', 'log'} else '')"); \
	printf '\n[auth-kit] API dev server -> http://127.0.0.1:8000\n'; \
	printf '[auth-kit] Mail mode -> %s\n' "$$MAIL_MODE"; \
	if [ -n "$$OUTBOX" ]; then printf '[auth-kit] Dev outbox -> %s\n' "$$OUTBOX"; fi; \
	printf '\n'; \
	$(UVICORN) auth_kit.main:app --reload --host 0.0.0.0 --port 8000

dev-web: web/.deps-stamp
	@printf '\n[auth-kit] Web dev server -> http://127.0.0.1:5173\n\n'
	@$(NPM) run dev -- --host 0.0.0.0 --port 5173

dev: .venv/.deps-stamp web/.deps-stamp
	@MAIL_MODE=$$($(PYTHON) -c "from auth_kit.core.config import get_settings; print(get_settings().mail_mode)"); \
	OUTBOX=$$($(PYTHON) -c "from auth_kit.core.config import get_settings; s=get_settings(); print(s.dev_mail_outbox_path if s.dev_mail_outbox_enabled and s.mail_mode in {'dev', 'log'} else '')"); \
	printf '\n[auth-kit] starting API and Web dev servers\n'; \
	printf '[auth-kit] API  -> http://127.0.0.1:8000\n'; \
	printf '[auth-kit] Web  -> http://127.0.0.1:5173\n'; \
	printf '[auth-kit] Mail mode -> %s\n' "$$MAIL_MODE"; \
	if [ -n "$$OUTBOX" ]; then printf '[auth-kit] Dev outbox -> %s\n' "$$OUTBOX"; fi; \
	printf '\n'; \
	trap 'kill 0' EXIT INT TERM; \
	$(MAKE) --no-print-directory dev-api & \
	API_PID=$$!; \
	sleep 1; \
	$(MAKE) --no-print-directory dev-web & \
	WEB_PID=$$!; \
	wait $$API_PID $$WEB_PID

test: .venv/.deps-stamp
	@printf '\n[auth-kit] running backend tests\n\n'
	@$(PYTHON) -m pytest

test-mail: .venv/.deps-stamp
	@if [ -z "$(TO)" ]; then \
		printf '\n[auth-kit] usage: make test-mail TO=user@example.com\n'; \
		exit 2; \
	fi
	@printf '\n[auth-kit] sending SMTP test mail to %s\n\n' "$(TO)"
	@$(PYTHON) -m auth_kit.mail_cli --to "$(TO)"

check: .venv/.deps-stamp web/.deps-stamp
	@printf '\n[auth-kit] running lint, format and type checks\n\n'
	@$(PYTHON) -m ruff check src tests
	@$(PYTHON) -m ruff format --check src tests
	@$(PYTHON) -m mypy src
	@$(NPM) run lint
	@$(NPM) run typecheck
	@$(NPM) run build
