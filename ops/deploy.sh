#!/usr/bin/env bash
# Deploy MMWSS on the callora VPS.
# Idempotent: safe to re-run. Pulls latest main, rebuilds, restarts.
set -euo pipefail

REPO_DIR="/srv/mmwss/repo"
ENV_FILE="/srv/mmwss/.env"
COMPOSE="docker compose -f ${REPO_DIR}/ops/docker-compose.yml --env-file ${ENV_FILE}"

if [[ ! -f "${ENV_FILE}" ]]; then
    echo "ERROR: ${ENV_FILE} not found. Copy ${REPO_DIR}/ops/.env.example to ${ENV_FILE} and fill it in."
    exit 1
fi

echo "==> git pull"
cd "${REPO_DIR}"
git fetch --quiet
git reset --hard origin/main

echo "==> docker compose build"
${COMPOSE} build

echo "==> docker compose up -d"
${COMPOSE} up -d

echo "==> Status:"
${COMPOSE} ps

echo
echo "Logs:    sudo ${COMPOSE} logs -f --tail=100"
echo "Psql:    sudo docker exec -it mmwss-db psql -U mmwss -d mmwss"
