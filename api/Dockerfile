# syntax=docker/dockerfile:1
# Build context: repository root.
FROM ghcr.io/astral-sh/uv:0.8.24 AS uv

FROM python:3.13.17-slim-bookworm AS builder
COPY --from=uv /uv /usr/local/bin/uv
ENV UV_LINK_MODE=copy UV_COMPILE_BYTECODE=0 UV_PROJECT_ENVIRONMENT=/opt/venv UV_PYTHON_DOWNLOADS=never
WORKDIR /src
COPY db/pyproject.toml db/uv.lock ./db/
COPY db/suckerpot_db ./db/suckerpot_db
COPY api/pyproject.toml api/uv.lock ./api/
COPY api/api ./api/api
WORKDIR /src/api
RUN uv sync --frozen --no-dev --no-editable

FROM python:3.13.17-slim-bookworm
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PATH=/opt/venv/bin:$PATH
RUN groupadd --system --gid 10001 app && useradd --system --uid 10001 --gid 10001 --no-create-home app
COPY --from=builder /opt/venv /opt/venv
WORKDIR /app
# Built SPA goes here. The web build stage adds, before USER:
#   COPY --from=web-build /web/dist /app/web
RUN mkdir -p /app/web
USER 10001:10001
EXPOSE 8000
HEALTHCHECK --interval=15s --timeout=5s --start-period=20s --retries=3 \
    CMD ["python", "-m", "api.healthcheck"]
CMD ["uvicorn", "api.main:app", "--host", "0.0.0.0", "--port", "8000", "--no-access-log", "--no-server-header", "--ws-ping-interval", "20", "--ws-ping-timeout", "20", "--ws-max-size", "4096"]
