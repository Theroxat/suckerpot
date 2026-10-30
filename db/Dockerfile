# syntax=docker/dockerfile:1
# One-shot migration image. Build context: repository root.
FROM ghcr.io/astral-sh/uv:0.13.6 AS uv

FROM python:3.15.0-slim-bookworm AS builder
COPY --from=uv /uv /usr/local/bin/uv
ENV UV_LINK_MODE=copy UV_COMPILE_BYTECODE=0 UV_PROJECT_ENVIRONMENT=/opt/venv UV_PYTHON_DOWNLOADS=never
WORKDIR /src/db
COPY db/pyproject.toml db/uv.lock ./
COPY db/suckerpot_db ./suckerpot_db
RUN uv sync --frozen --no-dev --no-editable

FROM python:3.15.0-slim-bookworm
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PATH=/opt/venv/bin:$PATH
RUN groupadd --system --gid 10001 app && useradd --system --uid 10001 --gid 10001 --no-create-home app
COPY --from=builder /opt/venv /opt/venv
WORKDIR /app
COPY db/alembic.ini ./alembic.ini
COPY db/migrations ./migrations
USER 10001:10001
HEALTHCHECK NONE
ENTRYPOINT ["python", "-m", "suckerpot_db.entrypoint"]
CMD ["alembic", "upgrade", "head"]
