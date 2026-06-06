FROM python:3.12-slim AS base

# WeasyPrint native deps (cairo, pango, glib, fonts).
# fonts-inter gives us the Inter typeface that matches the MMWSS web UI;
# DejaVu and Noto are fallbacks for symbol coverage.
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpangocairo-1.0-0 libpango-1.0-0 libcairo2 libgdk-pixbuf-2.0-0 \
    libffi8 shared-mime-info \
    fonts-inter fonts-dejavu-core fonts-noto-core \
    && rm -rf /var/lib/apt/lists/*

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

# Reports get written here; mounted as a named volume so they survive
# container restarts and so the app container can read them.
RUN mkdir -p /app/reports && chown -R mmwss:mmwss /app/reports

USER mmwss

ENV PYTHONPATH=/app/src

ENTRYPOINT ["python", "-m", "mmwss_collector"]
CMD ["scheduler"]
