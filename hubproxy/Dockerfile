# syntax=docker/dockerfile:1
# Build context: repository root. Standard library only: the venv holds just the package itself.
FROM ghcr.io/astral-sh/uv:0.13.7 AS uv

FROM python:3.15.2-slim-trixie AS builder
COPY --from=uv /uv /usr/local/bin/uv
ENV UV_LINK_MODE=copy UV_COMPILE_BYTECODE=0 UV_PROJECT_ENVIRONMENT=/opt/venv UV_PYTHON_DOWNLOADS=never
WORKDIR /src/hubproxy
COPY hubproxy/pyproject.toml hubproxy/uv.lock ./
COPY hubproxy/hubproxy ./hubproxy
RUN uv sync --frozen --no-dev --no-editable

FROM python:3.15.2-slim-trixie
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PATH=/opt/venv/bin:$PATH
RUN groupadd --system --gid 10001 app && useradd --system --uid 10001 --gid 10001 --no-create-home app
COPY --from=builder /opt/venv /opt/venv
# Build metadata (M28): passed by compose or the release workflow.
ARG VERSION=dev BUILD_KIND=source COMMIT=unknown
ENV SUCKERPOT_RUNNING_VERSION=$VERSION SUCKERPOT_BUILD_KIND=$BUILD_KIND SUCKERPOT_COMMIT=$COMMIT
LABEL org.opencontainers.image.version=$VERSION org.opencontainers.image.revision=$COMMIT
USER 10001:10001
EXPOSE 8888 8000
HEALTHCHECK --interval=15s --timeout=3s --start-period=5s --retries=3 \
    CMD ["python", "-m", "hubproxy.healthcheck"]
CMD ["python", "-m", "hubproxy"]
