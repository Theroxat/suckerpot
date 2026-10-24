# syntax=docker/dockerfile:1
# Build context: repository root. One-shot tool: publishes synthetic events to Redis.
FROM ghcr.io/astral-sh/uv:0.8.24 AS uv

FROM python:3.13.17-slim-bookworm AS builder
COPY --from=uv /uv /usr/local/bin/uv
ENV UV_LINK_MODE=copy UV_COMPILE_BYTECODE=0 UV_PROJECT_ENVIRONMENT=/opt/venv UV_PYTHON_DOWNLOADS=never
WORKDIR /src
COPY sensors/common/pyproject.toml ./sensors/common/
COPY sensors/common/suckerpot_common ./sensors/common/suckerpot_common
COPY scripts/demo/pyproject.toml scripts/demo/uv.lock ./scripts/demo/
COPY scripts/demo/demo ./scripts/demo/demo
WORKDIR /src/scripts/demo
RUN uv sync --frozen --no-dev --no-editable

FROM python:3.13.17-slim-bookworm
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PATH=/opt/venv/bin:$PATH
RUN groupadd --system --gid 10001 app && useradd --system --uid 10001 --gid 10001 --no-create-home app
COPY --from=builder /opt/venv /opt/venv
WORKDIR /app
USER 10001:10001
HEALTHCHECK NONE
ENTRYPOINT ["python", "-m", "demo"]
