# syntax=docker/dockerfile:1
# Build context: repository root. One image, two services: `python -m collector fetch` (collector)
# and `python -m collector analyze` (analyzer). Compose sets the command, networks and DB role.
FROM ghcr.io/astral-sh/uv:0.8.24 AS uv

FROM python:3.13.17-slim-bookworm AS builder
COPY --from=uv /uv /usr/local/bin/uv
# py-tlsh has no cp313 wheel: it is compiled here, only the finished venv reaches the runtime image.
RUN apt-get update \
    && apt-get install -y --no-install-recommends g++ cmake make \
    && rm -rf /var/lib/apt/lists/*
ENV UV_LINK_MODE=copy UV_COMPILE_BYTECODE=0 UV_PROJECT_ENVIRONMENT=/opt/venv UV_PYTHON_DOWNLOADS=never
WORKDIR /src
COPY db/pyproject.toml db/uv.lock ./db/
COPY db/suckerpot_db ./db/suckerpot_db
COPY egress/pyproject.toml egress/uv.lock ./egress/
COPY egress/suckerpot_egress ./egress/suckerpot_egress
COPY analysis/pyproject.toml analysis/uv.lock ./analysis/
COPY analysis/suckerpot_analysis ./analysis/suckerpot_analysis
COPY collector/pyproject.toml collector/uv.lock ./collector/
COPY collector/collector ./collector/collector
WORKDIR /src/collector
RUN uv sync --frozen --no-dev --no-editable --extra tlsh

FROM python:3.13.17-slim-bookworm
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PATH=/opt/venv/bin:$PATH \
    RULES_DIR=/app/rules/yara QUARANTINE_DIR=/quarantine HEARTBEAT_PATH=/tmp/heartbeat
RUN groupadd --system --gid 10001 app && useradd --system --uid 10001 --gid 10001 --no-create-home app
COPY --from=builder /opt/venv /opt/venv
# /quarantine is the mount point of the quarantine volume (initial ownership comes from here).
RUN mkdir -p /quarantine && chown 10001:10001 /quarantine && chmod 0700 /quarantine
WORKDIR /app
COPY collector/rules /app/rules
USER 10001:10001
HEALTHCHECK --interval=15s --timeout=5s --start-period=20s --retries=3 \
    CMD ["python", "-m", "collector.healthcheck"]
CMD ["python", "-m", "collector", "fetch"]
