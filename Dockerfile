FROM python:3.12-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app
COPY requirements.txt ./requirements.txt
RUN pip install --no-cache-dir --no-compile --requirement requirements.txt \
    && groupadd --gid 10001 app \
    && useradd --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin app

COPY --chown=10001:10001 server.py ./server.py
COPY --chown=10001:10001 web ./web
COPY --chown=10001:10001 static ./static
USER 10001:10001
EXPOSE 8080
ENTRYPOINT ["gunicorn", "--bind=0.0.0.0:8080", "--workers=1", "--threads=4", "--access-logfile=/dev/null", "--error-logfile=/dev/null", "--capture-output", "app:app"]
