# syntax=docker/dockerfile:1
# Build context: repository root.
FROM ghcr.io/astral-sh/uv:0.13.7 AS uv

# Web UI build. Node is only used in this stage and never ends up in the final image.
FROM --platform=$BUILDPLATFORM node:22.21.1-bookworm-slim AS web-build
ENV COREPACK_ENABLE_DOWNLOAD_PROMPT=0 CI=1
RUN corepack enable
WORKDIR /web
# The package manager version comes from "packageManager" in package.json.
COPY web/package.json web/pnpm-lock.yaml ./
RUN pnpm install --frozen-lockfile
COPY web/ ./
RUN pnpm build

FROM python:3.15.2-slim-trixie AS builder
COPY --from=uv /uv /usr/local/bin/uv
ENV UV_LINK_MODE=copy UV_COMPILE_BYTECODE=0 UV_PROJECT_ENVIRONMENT=/opt/venv UV_PYTHON_DOWNLOADS=never
WORKDIR /src
COPY db/pyproject.toml db/uv.lock ./db/
COPY db/suckerpot_db ./db/suckerpot_db
COPY netproto/pyproject.toml netproto/uv.lock ./netproto/
COPY netproto/suckerpot_netproto ./netproto/suckerpot_netproto
COPY reporting/pyproject.toml reporting/uv.lock ./reporting/
COPY reporting/suckerpot_reporting ./reporting/suckerpot_reporting
COPY api/pyproject.toml api/uv.lock ./api/
COPY api/api ./api/api
WORKDIR /src/api
RUN uv sync --frozen --no-dev --no-editable

FROM python:3.15.2-slim-trixie
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PATH=/opt/venv/bin:$PATH
RUN groupadd --system --gid 10001 app && useradd --system --uid 10001 --gid 10001 --no-create-home app
COPY --from=builder /opt/venv /opt/venv
WORKDIR /app
# Built SPA, served by the API. Read-only for the app user.
RUN mkdir -p /app/web
# Mount point of the quarantine volume (the first container to mount it fixes its owner: keep it
# the same uid as the collector). The API mounts it read-only.
RUN mkdir -p /quarantine && chown 10001:10001 /quarantine && chmod 0700 /quarantine
# Mount point of the vpn-config volume (M23): owned by the API user, 0755 so gluetun's root
# (no CAP_DAC_OVERRIDE) can still traverse it and read the 0644 files.
RUN mkdir -p /vpn-config && chown 10001:10001 /vpn-config && chmod 0755 /vpn-config
COPY --from=web-build /web/dist /app/web
# Build metadata (M28): passed by compose or the release workflow, read by the api and ingest.
ARG VERSION=dev BUILD_KIND=source COMMIT=unknown
ENV SUCKERPOT_RUNNING_VERSION=$VERSION SUCKERPOT_BUILD_KIND=$BUILD_KIND SUCKERPOT_COMMIT=$COMMIT
LABEL org.opencontainers.image.version=$VERSION org.opencontainers.image.revision=$COMMIT
USER 10001:10001
EXPOSE 8000
HEALTHCHECK --interval=15s --timeout=5s --start-period=20s --retries=3 \
    CMD ["python", "-m", "api.healthcheck"]
CMD ["uvicorn", "api.main:app", "--host", "0.0.0.0", "--port", "8000", "--no-access-log", "--no-server-header", "--ws-ping-interval", "20", "--ws-ping-timeout", "20", "--ws-max-size", "4096", "--limit-concurrency", "200"]
