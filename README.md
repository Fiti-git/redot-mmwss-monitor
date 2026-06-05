# MMWSS — Security & Maintenance Monitoring Platform

Internal Redot Global tool that monitors Cloudflare-protected WordPress sites and produces daily, weekly, and monthly security + uptime reports. Used in client meetings.

**Status:** Phase 1 (Cloudflare-only). WPMUDEV integration deferred to Phase 2.

## What it does

- Pulls Cloudflare zone settings, DNS, SSL expiry, firewall rules every 6h
- Pulls Cloudflare GraphQL analytics (requests, cache hit %, threats, bandwidth) every hour
- Probes each site's origin every 60s for uptime + latency
- Auto-detects incidents (site down, SSL <30 days, security config drift, threat spikes)
- Generates daily / weekly / monthly HTML + PDF reports, downloadable from the UI
- Auth-gated web dashboard with admin / viewer roles

## Architecture

```
Internet
  └─ Cloudflare (mmwss reachable via coldcalling.redotglobal.agency/mmwss)
       └─ Caddy reverse proxy (existing on callora EC2)
            ├─ /mmwss/api/*  →  mmwss-app  (Next.js API routes, port 3001)
            └─ /mmwss/*      →  mmwss-app  (Next.js pages)

mmwss-collector (Python, cron'd)  ──┐
                                    ├──> callora-db (Postgres, shared instance, "mmwss" schema)
mmwss-app (Next.js + Tremor)  ──────┘     callora-redis (shared, "mmwss:" key prefix)
```

## Repo layout

```
db/migrations/        SQL migrations (idempotent, run in order)
collector/            Python collector (Docker container, cron'd)
app/                  Next.js + Tremor + shadcn/ui dashboard & API
ops/                  docker-compose, Caddy snippets, deploy scripts
docs/                 architecture, deployment, security docs
scratch/              early exploration scripts (cf_report.py etc.) — kept for reference
```

## Brand

UI follows the Redot Global brand. Primary red `#E11E27`, dark text `#1F1F1F`, light surfaces. See `docs/brand.md` once written.

## Setup (local dev — TBD)

Phase 1 development still in progress. Local dev instructions and Docker compose will appear here as services land.

## Deployment

Runs on the existing `callora` EC2 host (Ubuntu 24.04, Docker), sharing:
- `callora-db` Postgres (isolated to `mmwss` schema)
- `callora-redis` (isolated to `mmwss:` key prefix)
- `callora-caddy` reverse proxy (one route block added)

Deploy steps in `docs/deployment.md` once written.

## Security notes

- Cloudflare API tokens stored encrypted at rest (AES-GCM via pgcrypto)
- Passwords hashed with bcrypt
- All auth + admin actions in immutable `mmwss.audit_log` (append-only via trigger)
- No secrets in this repo — see `.env.example` for variable names
- Postgres bound to 127.0.0.1 on the host, never internet-reachable
