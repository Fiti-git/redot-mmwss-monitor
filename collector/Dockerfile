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
COPY migrations ./migrations

USER mmwss

ENV PYTHONPATH=/app/src

ENTRYPOINT ["python", "-m", "mmwss_collector"]
CMD ["scheduler"]
