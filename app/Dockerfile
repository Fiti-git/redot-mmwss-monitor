FROM python:3.12-slim AS base

RUN useradd --create-home --uid 1000 mmwss

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY src ./src
COPY static ./static
COPY scripts ./scripts

USER mmwss

ENV PYTHONPATH=/app/src
EXPOSE 3000

# Behind Caddy at /mmwss — Uvicorn just serves on 3000; basePath is handled
# by FastAPI sub-app mount (see main.py).
CMD ["uvicorn", "mmwss_app.main:app", "--host", "0.0.0.0", "--port", "3000", "--proxy-headers", "--forwarded-allow-ips=*"]
