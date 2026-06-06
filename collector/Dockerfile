FROM python:3.12-slim AS base

# WeasyPrint native deps (cairo, pango, glib, fonts) + scanner runtime deps.
# fonts-inter gives us the Inter typeface that matches the MMWSS web UI;
# DejaVu and Noto are fallbacks for symbol coverage.
#
# Scanner binaries:
#   - nuclei, subfinder, httpx  → installed from ProjectDiscovery release tarballs
#   - wpscan                    → Ruby gem (needs ruby + libcurl)
#   - testssl.sh                → cloned from GitHub (bash + openssl + bsdmainutils)
#   - bind9-dnsutils            → host/dig used by some testssl checks
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpangocairo-1.0-0 libpango-1.0-0 libcairo2 libgdk-pixbuf-2.0-0 \
    libffi8 shared-mime-info \
    fonts-inter fonts-dejavu-core fonts-noto-core \
    curl ca-certificates unzip git bash \
    ruby ruby-dev build-essential libcurl4-openssl-dev libxml2-dev libxslt1-dev zlib1g-dev \
    openssl bsdmainutils bind9-dnsutils procps \
    && rm -rf /var/lib/apt/lists/*

# ───── ProjectDiscovery binaries (nuclei, subfinder, httpx) ─────
# Pinned versions for reproducibility. Update by bumping these and rebuilding.
ARG NUCLEI_VERSION=3.3.7
ARG SUBFINDER_VERSION=2.6.7
ARG HTTPX_VERSION=1.6.10

RUN set -eux; \
    arch="$(dpkg --print-architecture)"; \
    case "$arch" in \
      amd64) PD_ARCH="amd64" ;; \
      arm64) PD_ARCH="arm64" ;; \
      *) echo "unsupported arch $arch" && exit 1 ;; \
    esac; \
    cd /tmp; \
    curl -fsSL -o nuclei.zip    "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_${PD_ARCH}.zip"; \
    curl -fsSL -o subfinder.zip "https://github.com/projectdiscovery/subfinder/releases/download/v${SUBFINDER_VERSION}/subfinder_${SUBFINDER_VERSION}_linux_${PD_ARCH}.zip"; \
    curl -fsSL -o httpx.zip     "https://github.com/projectdiscovery/httpx/releases/download/v${HTTPX_VERSION}/httpx_${HTTPX_VERSION}_linux_${PD_ARCH}.zip"; \
    unzip -o nuclei.zip    nuclei    -d /usr/local/bin/; \
    unzip -o subfinder.zip subfinder -d /usr/local/bin/; \
    unzip -o httpx.zip     httpx     -d /usr/local/bin/; \
    chmod +x /usr/local/bin/nuclei /usr/local/bin/subfinder /usr/local/bin/httpx; \
    rm -f nuclei.zip subfinder.zip httpx.zip

# ───── testssl.sh ─────
# Clone the 3.2 release branch (stable) into /opt and symlink into PATH.
RUN set -eux; \
    git clone --depth 1 --branch 3.2 https://github.com/drwetter/testssl.sh.git /opt/testssl.sh; \
    ln -sf /opt/testssl.sh/testssl.sh /usr/local/bin/testssl.sh; \
    chmod +x /opt/testssl.sh/testssl.sh

# ───── WPScan (FOSS edition) ─────
RUN gem install wpscan --no-document

# ───── User + workdir ─────
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
# Scan artifacts share the same volume in a subdirectory.
RUN mkdir -p /app/reports/scans && chown -R mmwss:mmwss /app/reports

# Update nuclei templates as the mmwss user so the cache lives in $HOME.
USER mmwss

# Pre-fetch nuclei templates (fails gracefully on no-network builds — collector
# can also refresh templates at runtime via -update-templates).
RUN nuclei -update-templates -silent 2>/dev/null || true

ENV PYTHONPATH=/app/src
ENV MMWSS_SCAN_ARTIFACTS=/app/reports/scans

ENTRYPOINT ["python", "-m", "mmwss_collector"]
CMD ["scheduler"]
