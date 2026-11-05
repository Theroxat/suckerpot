# syntax=docker/dockerfile:1
# Hub image (API, worker, migrate and admin CLI share it). Build context: repository root.
FROM ghcr.io/astral-sh/uv:0.13.7 AS uv

FROM python:3.15.0-slim-bookworm AS builder
COPY --from=uv /uv /usr/local/bin/uv
ENV UV_LINK_MODE=copy UV_COMPILE_BYTECODE=0 UV_PROJECT_ENVIRONMENT=/opt/venv UV_PYTHON_DOWNLOADS=never
WORKDIR /src
COPY netproto/pyproject.toml netproto/uv.lock ./netproto/
COPY netproto/suckerpot_netproto ./netproto/suckerpot_netproto
COPY hub/pyproject.toml hub/uv.lock ./hub/
COPY hub/hub ./hub/hub
WORKDIR /src/hub
RUN uv sync --frozen --no-dev --no-editable

FROM python:3.15.0-slim-bookworm
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PATH=/opt/venv/bin:$PATH
RUN groupadd --system --gid 10001 app && useradd --system --uid 10001 --gid 10001 --no-create-home app \
    && mkdir /keys /srv/feeds && chown 10001:10001 /keys /srv/feeds
COPY --from=builder /opt/venv /opt/venv
WORKDIR /app
COPY hub/alembic.ini ./alembic.ini
COPY hub/migrations ./migrations
# The public README template and the delisting page (published into the feeds volume).
COPY hub/static ./static
USER 10001:10001
HEALTHCHECK --interval=15s --timeout=5s --start-period=20s --retries=3 \
    CMD ["python", "-m", "hub.healthcheck"]
# No access log, no Server header, bounded concurrency. The client address is never logged.
CMD ["uvicorn", "hub.main:app_factory", "--factory", "--host", "0.0.0.0", "--port", "8080", \
     "--no-access-log", "--no-server-header", "--limit-concurrency", "200", \
     "--timeout-keep-alive", "10", "--log-level", "warning"]
