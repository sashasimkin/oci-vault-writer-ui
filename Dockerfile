FROM ghcr.io/astral-sh/uv:0.13.0 AS uv

FROM python:3.12-slim-bookworm AS build
COPY --from=uv /uv /uvx /bin/

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PROJECT_ENVIRONMENT=/opt/venv

WORKDIR /app
COPY pyproject.toml uv.lock ./
RUN uv sync --locked --no-dev --no-install-project

FROM python:3.12-slim-bookworm

ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app
COPY --from=build /opt/venv /opt/venv
RUN groupadd --gid 10001 app \
    && useradd --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin app

COPY --chown=10001:10001 server.py ./server.py
COPY --chown=10001:10001 web ./web
COPY --chown=10001:10001 static ./static
USER 10001:10001
EXPOSE 8080
ENTRYPOINT ["gunicorn", "--bind=0.0.0.0:8080", "--workers=1", "--threads=4", "--access-logfile=/dev/null", "--error-logfile=/dev/null", "--capture-output", "app:app"]
