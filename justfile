# SuckerPot task runner. Everything runs in Docker: the host only needs Docker and `just`.
# Variables from .env are loaded so recipes can pass them through.

set dotenv-load := true
set shell := ["bash", "-euo", "pipefail", "-c"]

uv_image := "ghcr.io/astral-sh/uv:0.8.24-python3.13-bookworm-slim"
uv_cache := "suckerpot-uv-cache"
project := env_var_or_default("COMPOSE_PROJECT_NAME", "suckerpot")
packages := "sensors/common scripts/demo db ingest api"

# List recipes.
default:
    @just --list

# Build the images and start the stack, waiting until everything is healthy.
up:
    docker compose up -d --build --wait

# Stop the stack (volumes are kept).
down:
    docker compose down

# Follow logs, optionally for some services: just logs ingest api
logs *svc:
    docker compose logs -f --tail=100 {{svc}}

# Show service status.
ps:
    docker compose ps

# Validate the compose file.
config:
    docker compose config -q

# Generate demo data once: just demo --sessions 200 --days 3
demo *args:
    docker compose --profile tools run --rm demo {{args}}

# Keep generating live demo traffic (stop with Ctrl+C).
demo-live:
    docker compose --profile tools run --rm demo --live

# Open a psql shell in the database container.
psql:
    docker compose exec db sh -c 'PGPASSWORD="$POSTGRES_PASSWORD" exec psql -U "$POSTGRES_USER" -d "$POSTGRES_DB"'

# Lint every Python package (ruff check + format check).
lint:
    {{just_executable()}} _py "uv run ruff check && uv run ruff format --check"

# Format every Python package.
fmt:
    {{just_executable()}} _py "uv run ruff check --fix && uv run ruff format"

# Type-check every Python package (mypy strict).
typecheck:
    {{just_executable()}} _py "uv run mypy ."

# Unit tests of every Python package (integration tests are excluded).
test:
    {{just_executable()}} _py "uv run pytest -q -p no:cacheprovider -m 'not integration'"

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
        -e REDIS_HOST=redis -e REDIS_PORT=6379 -e REDIS_USER=admin -e "REDIS_PASSWORD=$REDIS_PASSWORD" \
        {{uv_image}} sh -c "uv sync --refresh-package suckerpot-common --refresh-package suckerpot-db --refresh-package suckerpot-api && uv run pytest -q -p no:cacheprovider -m integration; rc=\$?; [ \$rc -eq 5 ] && exit 0; exit \$rc")
      # Default bridge first (to download packages), then the backend network (to reach db/redis).
      docker network connect "${it}_backend" "$cid"
      docker start -a "$cid" || { docker rm -f "$cid" >/dev/null; exit 1; }
      docker rm -f "$cid" >/dev/null
    done

# Make the shared uv cache volume writable by any user.
_cache:
    @docker run --rm --user root -v {{uv_cache}}:/cache {{uv_image}} chmod 1777 /cache

# Run a shell command in each Python package inside the pinned uv container.
# Nothing is installed on the host; caches and the venv live in the container or the cache volume.
_py cmd: _cache
    #!/usr/bin/env bash
    set -euo pipefail
    status=0
    for pkg in {{packages}}; do
      [ -f "$pkg/pyproject.toml" ] || { echo "-- skip $pkg (no pyproject.toml)"; continue; }
      echo "== $pkg"
      docker run --rm --user "$(id -u):$(id -g)" \
        -v "$PWD:/work" -v "{{uv_cache}}:/cache" -w "/work/$pkg" \
        -e HOME=/tmp -e UV_CACHE_DIR=/cache -e UV_LINK_MODE=copy -e UV_PROJECT_ENVIRONMENT=/tmp/venv \
        -e RUFF_CACHE_DIR=/tmp/ruff -e MYPY_CACHE_DIR=/tmp/mypy \
        {{uv_image}} sh -c "uv sync --refresh-package suckerpot-common --refresh-package suckerpot-db --refresh-package suckerpot-api && {{cmd}}" || status=1
    done
    exit $status
