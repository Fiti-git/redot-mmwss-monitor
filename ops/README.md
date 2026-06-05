# Ops — MMWSS deploy

Runs on the existing `callora` EC2 host (Ubuntu 24.04, Docker), but in its own isolated stack.

## First-time setup on the VPS

```bash
ssh ubuntu@54.254.167.197

# Clone the repo into /srv/mmwss/repo (one-time)
sudo mkdir -p /srv/mmwss && sudo chown ubuntu:ubuntu /srv/mmwss
git clone https://github.com/Fiti-git/redot-mmwss-monitor.git /srv/mmwss/repo

# Create .env from the template
cp /srv/mmwss/repo/ops/.env.example /srv/mmwss/.env
nano /srv/mmwss/.env   # fill in the three secrets — see comments inside

chmod 600 /srv/mmwss/.env

# First deploy
bash /srv/mmwss/repo/ops/deploy.sh
```

## Subsequent deploys

After pushing changes to `main`:

```bash
ssh ubuntu@54.254.167.197
bash /srv/mmwss/repo/ops/deploy.sh
```

## Inspect

```bash
# follow collector + db logs
sudo docker compose -f /srv/mmwss/repo/ops/docker-compose.yml --env-file /srv/mmwss/.env logs -f --tail=200

# get a psql shell
sudo docker exec -it mmwss-db psql -U mmwss -d mmwss

# inspect synced zones
sudo docker exec mmwss-db psql -U mmwss -d mmwss -c "SELECT id, name, plan, status, last_synced_at FROM mmwss.zones ORDER BY name;"
```

## What lives where

| Path on VPS | What |
|---|---|
| `/srv/mmwss/repo/` | This repo (git clone) |
| `/srv/mmwss/.env` | Real secrets (NEVER in git, `chmod 600`) |
| Docker volume `mmwss_pgdata` | Postgres data (persists across container restarts) |
| Docker network `mmwss_net` | Isolated from `repo_default` (callora's network) |
| Ports | only `127.0.0.1:5434` (Postgres) — not internet-reachable |
