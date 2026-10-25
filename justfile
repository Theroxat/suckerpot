# SuckerPot task runner. Everything runs in Docker: the host only needs Docker and `just`.
# Variables from .env are loaded so recipes can pass them through.

set dotenv-load := true
set shell := ["bash", "-euo", "pipefail", "-c"]

uv_image := "ghcr.io/astral-sh/uv:0.8.24-python3.13-bookworm-slim"
uv_cache := "suckerpot-uv-cache"
project := env_var_or_default("COMPOSE_PROJECT_NAME", "suckerpot")
node_image := "node:22.21.1-bookworm-slim"
playwright_image := "mcr.microsoft.com/playwright:v1.64.1-noble"
web_cache := "suckerpot-web-cache"
web_env := "-e HOME=/tmp -e CI=1 -e COREPACK_ENABLE_DOWNLOAD_PROMPT=0 -e COREPACK_HOME=/cache/corepack -e npm_config_store_dir=/cache/pnpm-store"
pnpm_setup := "mkdir -p /tmp/bin && corepack enable --install-directory /tmp/bin && export PATH=/tmp/bin:$PATH"
packages := "sensors/common sensors/ssh sensors/rdp sensors/web sensors/telnet scripts/demo db ingest api"

# List recipes.
default:
    @just --list

# Build the images and start the stack, waiting until everything is healthy.
up: ports
    docker compose up -d --build --wait

# Start the stack for tests: dashboard authentication OFF (docker-compose.ci.yml).
# Required auth settings get dummy values when .env has none. Never on an exposed machine.
# The test recipes below (ssh-test, rdp-test, telnet-test) need this stack.
up-test: ports
    #!/usr/bin/env bash
    set -euo pipefail
    : "${ADMIN_PASSWORD_HASH:=test-placeholder}"
    : "${SESSION_SECRET:=test-placeholder-session-secret-not-used}"
    export ADMIN_PASSWORD_HASH SESSION_SECRET
    COMPOSE_FILE=docker-compose.yml:docker-compose.ci.yml docker compose up -d --build --wait

# Stop the stack (volumes are kept).
down:
    ADMIN_PASSWORD_HASH="${ADMIN_PASSWORD_HASH:-x}" SESSION_SECRET="${SESSION_SECRET:-x}" docker compose down

# Follow logs, optionally for some services: just logs ingest api
logs *svc:
    docker compose logs -f --tail=100 {{svc}}

# Show service status.
ps:
    docker compose ps

# Check the port layout (see scripts/check-ports.sh).
ports:
    scripts/check-ports.sh

# Validate the compose file.
config: ports
    docker compose config -q

# Generate demo data once: just demo --sessions 200 --days 3
demo *args:
    docker compose --profile tools run --rm demo {{args}}

# Keep generating live demo traffic (stop with Ctrl+C).
demo-live:
    docker compose --profile tools run --rm demo --live

# Everything: lint, type-check, unit tests and the web build.
check: lint typecheck test web-build

# Install the web dependencies (frozen lockfile).
web-install:
    {{just_executable()}} _web "true"

# Lint, format check and type-check the web app.
web-lint:
    {{just_executable()}} _web "pnpm run lint && pnpm run typecheck"

# Unit tests of the web app.
web-test:
    {{just_executable()}} _web "pnpm run test"

# Production build of the web app into web/dist.
web-build:
    {{just_executable()}} _web "pnpm run build"

# Vite dev server on http://127.0.0.1:5173 with mock data (Ctrl+C to stop).
web-dev:
    {{just_executable()}} _cache_vol
    docker run --rm -it --user "$(id -u):$(id -g)" -p 127.0.0.1:5173:5173 \
      -v "$PWD/web:/web" -v "{{web_cache}}:/cache" -w /web {{web_env}} \
      {{node_image}} sh -c "{{pnpm_setup}} && pnpm install --frozen-lockfile && VITE_MOCK=1 pnpm exec vite --host 0.0.0.0"

# Screenshots on mock data (desktop and mobile, dark and light) into web/screenshots.
screenshots:
    {{just_executable()}} _cache_vol
    docker run --rm --ipc=host --user "$(id -u):$(id -g)" \
      -v "$PWD/web:/web" -v "{{web_cache}}:/cache" -w /web {{web_env}} \
      {{playwright_image}} sh -c "{{pnpm_setup}} && pnpm install --frozen-lockfile && pnpm run build:mock && pnpm exec playwright test"

# Real SSH login against the sensor from a throwaway container, then check the API.
ssh-test:
    scripts/ssh-test.sh

# RDP connection request against the sensor from a throwaway container, then check the API.
rdp-test:
    scripts/rdp-test.sh

# Telnet login and fake download against the sensor from a throwaway container, then check the API.
telnet-test:
    scripts/telnet-test.sh

# Dump the database into ./backups (BACKUP_DIR, BACKUP_KEEP): see scripts/backup-db.sh.
backup:
    scripts/backup-db.sh

# Restore a dump, replacing the whole database (asks for confirmation): just restore backups/FILE.dump
restore file:
    scripts/restore-db.sh {{file}}

# Open a psql shell in the database container.
psql:
    docker compose exec db sh -c 'PGPASSWORD="$POSTGRES_PASSWORD" exec psql -U "$POSTGRES_USER" -d "$POSTGRES_DB"'

# Lint every Python package (ruff check + format check).
lint:
    #!/usr/bin/env bash
    # Runs everything even when a step fails, then exits non-zero with a summary.
    rc=0
    {{just_executable()}} _py "uv run ruff check && uv run ruff format --check" || rc=1
    {{just_executable()}} web-lint || { echo "FAILED: web (lint/typecheck)"; rc=1; }
    exit $rc

# Format every Python package.
fmt:
    {{just_executable()}} _py "uv run ruff check --fix && uv run ruff format"

# Type-check every Python package (mypy strict).
typecheck:
    {{just_executable()}} _py "uv run mypy ."

# Unit tests of every Python package (integration tests are excluded).
test:
    #!/usr/bin/env bash
    rc=0
    {{just_executable()}} _py "uv run pytest -q -p no:cacheprovider -m 'not integration'" || rc=1
    {{just_executable()}} web-test || { echo "FAILED: web (tests)"; rc=1; }
    exit $rc

# Integration tests against the real database and Redis of the compose stack.
test-integration:
    #!/usr/bin/env bash
    set -euo pipefail
    # Use a throwaway compose project: the ingest tests reset the database roles'
    # passwords, which must never touch the real stack and its data volume.
    it="{{project}}-it"
    trap 'docker compose -p "$it" down -v >/dev/null 2>&1' EXIT
    docker compose -p "$it" up -d --build --wait db redis
    {{just_executable()}} _cache
    for pkg in db ingest api; do
      [ -f "$pkg/pyproject.toml" ] || continue
      echo "== integration: $pkg"
      cid=$(docker create --user "$(id -u):$(id -g)" \
        -v "$PWD:/work" -v "{{uv_cache}}:/cache" -w "/work/$pkg" \
        -e HOME=/tmp -e UV_CACHE_DIR=/cache -e UV_LINK_MODE=copy -e UV_PROJECT_ENVIRONMENT=/tmp/venv \
        -e POSTGRES_HOST=db -e POSTGRES_PORT=5432 \
        -e POSTGRES_DB -e POSTGRES_USER -e POSTGRES_PASSWORD \
        -e POSTGRES_INGEST_USER -e POSTGRES_INGEST_PASSWORD -e POSTGRES_API_USER -e POSTGRES_API_PASSWORD \
        -e SUCKERPOT_ALLOW_DEFAULT_SECRETS -e DB_DIR=/work/db \
        -e REDIS_HOST=redis -e REDIS_PORT=6379 -e REDIS_USER=admin -e "REDIS_PASSWORD=$REDIS_PASSWORD" -e REDIS_ADMIN_USER=admin -e "REDIS_ADMIN_PASSWORD=$REDIS_PASSWORD" \
        {{uv_image}} sh -c "uv sync --refresh-package suckerpot-common --refresh-package suckerpot-db --refresh-package suckerpot-api && uv run pytest -q -p no:cacheprovider -m integration; rc=\$?; [ \$rc -eq 5 ] && exit 0; exit \$rc")
      # Default bridge first (to download packages), then the backend network (to reach db/redis).
      docker network connect "${it}_backend" "$cid"
      docker start -a "$cid" || { docker rm -f "$cid" >/dev/null; exit 1; }
      docker rm -f "$cid" >/dev/null
    done

# Make the shared web cache volume (corepack + pnpm store) writable by any user.
_cache_vol:
    @docker run --rm --user root -v {{web_cache}}:/cache {{uv_image}} chmod 1777 /cache

# Run a shell command in the web app inside the pinned Node image, as the host user.
_web cmd: _cache_vol
    docker run --rm --user "$(id -u):$(id -g)" \
      -v "$PWD/web:/web" -v "{{web_cache}}:/cache" -w /web {{web_env}} \
      {{node_image}} sh -c "{{pnpm_setup}} && pnpm install --frozen-lockfile && {{cmd}}"

# Make the shared uv cache volume writable by any user.
_cache:
    @docker run --rm --user root -v {{uv_cache}}:/cache {{uv_image}} chmod 1777 /cache

# Run a shell command in each Python package inside the pinned uv container.
# Nothing is installed on the host; caches and the venv live in the container or the cache volume.
_py cmd: _cache
    #!/usr/bin/env bash
    set -euo pipefail
    status=0
    failed=""
    for pkg in {{packages}}; do
      [ -f "$pkg/pyproject.toml" ] || { echo "-- skip $pkg (no pyproject.toml)"; continue; }
      echo "== $pkg"
      docker run --rm --user "$(id -u):$(id -g)" \
        -v "$PWD:/work" -v "{{uv_cache}}:/cache" -w "/work/$pkg" \
        -e HOME=/tmp -e UV_CACHE_DIR=/cache -e UV_LINK_MODE=copy -e UV_PROJECT_ENVIRONMENT=/tmp/venv \
        -e RUFF_CACHE_DIR=/tmp/ruff -e MYPY_CACHE_DIR=/tmp/mypy -e USER=x -e LOGNAME=x \
        {{uv_image}} sh -c "uv sync --refresh-package suckerpot-common --refresh-package suckerpot-db --refresh-package suckerpot-api && {{cmd}}" || { status=1; failed="$failed $pkg"; }
    done
    if [ "$status" -ne 0 ]; then echo "FAILED packages:$failed" >&2; fi
    exit $status
