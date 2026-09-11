FROM python:3.11-slim AS base

# Don't write .pyc files, don't buffer stdout/stderr (so logs show up promptly)
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# build-essential is needed to build the argon2-cffi/cryptography wheels
# used by passlib[argon2] / python-jose[cryptography] on the slim image.
RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY main.py .

# No local data directory needed — all state lives in the Supabase
# (hosted Postgres) database configured via DATABASE_URL.

RUN useradd --create-home --uid 1000 appuser \
    && chown -R appuser:appuser /app
USER appuser

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import os,urllib.request; urllib.request.urlopen('http://127.0.0.1:' + os.environ.get('PORT', '8000') + '/health', timeout=3)" || exit 1

# $PORT lets the same image run on platforms that inject it (e.g. Render)
# and locally/in docker-compose, where it falls back to 8000.
CMD ["sh", "-c", "uvicorn main:app --host 0.0.0.0 --port ${PORT:-8000}"]
