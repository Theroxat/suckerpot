# syntax=docker/dockerfile:1
# Build context: repository root.
FROM ghcr.io/astral-sh/uv:0.13.6 AS uv

FROM python:3.15.0-slim-bookworm AS builder
COPY --from=uv /uv /usr/local/bin/uv
ENV UV_LINK_MODE=copy UV_COMPILE_BYTECODE=0 UV_PROJECT_ENVIRONMENT=/opt/venv UV_PYTHON_DOWNLOADS=never
WORKDIR /src
COPY sensors/common ./sensors/common
COPY sensors/sip/pyproject.toml sensors/sip/uv.lock ./sensors/sip/
COPY sensors/sip/sip_sensor ./sensors/sip/sip_sensor
WORKDIR /src/sensors/sip
RUN uv sync --frozen --no-dev --no-editable

FROM python:3.15.0-slim-bookworm
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PATH=/opt/venv/bin:$PATH
RUN groupadd --system --gid 10001 app \
    && useradd --system --uid 10001 --gid 10001 --no-create-home app \
    && mkdir -p /data \
    && chown -R 10001:10001 /data \
    && chmod 700 /data
COPY --from=builder /opt/venv /opt/venv
WORKDIR /app
USER 10001:10001
VOLUME ["/data"]
EXPOSE 5060/udp 5060/tcp
HEALTHCHECK --interval=15s --timeout=5s --start-period=20s --retries=3 \
    CMD ["python", "-m", "sip_sensor.healthcheck"]
CMD ["python", "-m", "sip_sensor"]
