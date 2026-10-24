# syntax=docker/dockerfile:1
# Build context: repository root.
FROM ghcr.io/astral-sh/uv:0.8.24 AS uv

FROM python:3.13.17-slim-bookworm AS builder
COPY --from=uv /uv /usr/local/bin/uv
ENV UV_LINK_MODE=copy UV_COMPILE_BYTECODE=0 UV_PROJECT_ENVIRONMENT=/opt/venv UV_PYTHON_DOWNLOADS=never
WORKDIR /src
COPY sensors/common ./sensors/common
COPY db/pyproject.toml db/uv.lock ./db/
COPY db/suckerpot_db ./db/suckerpot_db
COPY ingest/pyproject.toml ingest/uv.lock ./ingest/
COPY ingest/ingest ./ingest/ingest
WORKDIR /src/ingest
RUN uv sync --frozen --no-dev --no-editable

FROM python:3.13.17-slim-bookworm
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PATH=/opt/venv/bin:$PATH \
    RULES_DIR=/app/rules GEOIP_DIR=/data/geoip
RUN groupadd --system --gid 10001 app && useradd --system --uid 10001 --gid 10001 --no-create-home app
COPY --from=builder /opt/venv /opt/venv
# /data/geoip is the mount point of the geoip-data volume (initial ownership comes from here).
RUN mkdir -p /data/geoip && chown -R 10001:10001 /data
WORKDIR /app
COPY ingest/rules /app/rules
USER 10001:10001
HEALTHCHECK --interval=15s --timeout=5s --start-period=20s --retries=3 \
    CMD ["python", "-m", "ingest.healthcheck"]
CMD ["python", "-m", "ingest"]
