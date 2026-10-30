# syntax=docker/dockerfile:1
# Build context: repository root.
FROM ghcr.io/astral-sh/uv:0.13.6 AS uv

FROM python:3.15.0-slim-bookworm AS builder
COPY --from=uv /uv /usr/local/bin/uv
ENV UV_LINK_MODE=copy UV_COMPILE_BYTECODE=0 UV_PROJECT_ENVIRONMENT=/opt/venv UV_PYTHON_DOWNLOADS=never
WORKDIR /src
COPY sensors/common ./sensors/common
COPY sensors/ssh/pyproject.toml sensors/ssh/uv.lock ./sensors/ssh/
COPY sensors/ssh/ssh_sensor ./sensors/ssh/ssh_sensor
WORKDIR /src/sensors/ssh
RUN uv sync --frozen --no-dev --no-editable

FROM python:3.15.0-slim-bookworm
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PATH=/opt/venv/bin:$PATH \
    MALLOC_ARENA_MAX=2
RUN groupadd --system --gid 10001 app \
    && useradd --system --uid 10001 --gid 10001 --no-create-home app \
    && mkdir -p /data/host_keys \
    && chown -R 10001:10001 /data \
    && chmod 700 /data/host_keys
COPY --from=builder /opt/venv /opt/venv
WORKDIR /app
USER 10001:10001
VOLUME ["/data"]
EXPOSE 2222
HEALTHCHECK --interval=15s --timeout=5s --start-period=20s --retries=3 \
    CMD ["python", "-m", "ssh_sensor.healthcheck"]
CMD ["python", "-m", "ssh_sensor"]
