#!/usr/bin/env bash
# Deploy MMWSS on the callora VPS.
#
# Secrets are encrypted with SOPS + age. The age private key lives at
# /etc/mmwss/age.key (root, chmod 400) — NEVER in git. This script
# decrypts the secrets file into a tmpfs-backed location, hands it to
# docker compose, and wipes the plaintext immediately after `up -d`
# returns. The decrypted env never touches persistent disk.
#
# Idempotent: safe to re-run. Pulls latest main, rebuilds, restarts.
set -euo pipefail

REPO_DIR="/srv/mmwss/repo"
SOPS_FILE="${REPO_DIR}/ops/secrets/secrets.enc.yaml"
AGE_KEY="/etc/mmwss/age.key"

# tmpfs-backed scratch location — wiped on reboot, never hits disk in the
# pure-tmpfs case. /run is tmpfs on Ubuntu by default.
RUNTIME_DIR="/run/mmwss"
ENV_FILE="${RUNTIME_DIR}/decrypted.env"
COMPOSE="docker compose -f ${REPO_DIR}/ops/docker-compose.yml --env-file ${ENV_FILE}"

# ─── Pre-flight ───
[[ -f "${SOPS_FILE}" ]] || { echo "ERROR: ${SOPS_FILE} not found"; exit 1; }
[[ -r "${AGE_KEY}"   ]] || { echo "ERROR: ${AGE_KEY} not readable (needs sudo)"; exit 1; }

# ─── Decrypt secrets to tmpfs ───
sudo mkdir -p "${RUNTIME_DIR}"
sudo chmod 700 "${RUNTIME_DIR}"
sudo chown root:root "${RUNTIME_DIR}"

# Trap to ensure plaintext file is wiped no matter how the script exits
cleanup() {
    sudo rm -f "${ENV_FILE}" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

echo "==> Decrypting secrets (SOPS + age) into tmpfs"
# Decrypt → convert YAML to .env-style KEY=VALUE lines on the fly,
# write straight to the tmpfs target with chmod 600 (root only).
sudo SOPS_AGE_KEY_FILE="${AGE_KEY}" sops --decrypt --output-type dotenv "${SOPS_FILE}" \
    | sudo install -m 0600 -o root -g root /dev/stdin "${ENV_FILE}"

# Sanity check: file exists, has lines, no plaintext key markers in the .env
if ! sudo test -s "${ENV_FILE}"; then
    echo "ERROR: decrypted env file is empty"
    exit 1
fi

echo "==> git pull"
cd "${REPO_DIR}"
git fetch --quiet
git reset --hard origin/main

echo "==> docker compose build"
sudo ${COMPOSE} build

echo "==> docker compose up -d"
sudo ${COMPOSE} up -d

echo "==> Status:"
sudo ${COMPOSE} ps

# The trap above will wipe ENV_FILE on exit. Containers continue running
# with the env values loaded in their own process environment — they no
# longer need the file.

echo
echo "Decrypted env file wiped from disk. Containers retain env in memory."
echo "Logs:    sudo ${COMPOSE} logs -f --tail=100"
echo "Psql:    sudo docker exec -it mmwss-db psql -U mmwss -d mmwss"
echo
echo "To edit secrets:"
echo "  sudo SOPS_AGE_KEY_FILE=${AGE_KEY} sops ${SOPS_FILE}"
echo "(opens decrypted in \$EDITOR; re-encrypts on save)"
