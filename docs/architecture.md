# Architecture

## Overview

MMWSS is an internal monitoring + reporting tool for Cloudflare-protected sites. Two long-running containers + one shared database.

## Components

### `mmwss-app` (Next.js 15 + Tremor + shadcn/ui)

- Serves the dashboard UI at `/mmwss/*`
- Hosts Next.js API routes at `/mmwss/api/*` (auth, zones, incidents, reports)
- Authentication: NextAuth credentials provider + bcrypt password hashing
- Roles: `admin` (full), `viewer` (read + download reports only)
- Talks to Postgres via Prisma client (`mmwss` schema)
- Talks to Redis for session storage + rate limiting

### `mmwss-collector` (Python 3.12)

- Runs **scheduled jobs** (internal cron via APScheduler):
  - **every 60s** — HTTP probe each tracked zone; write row to `uptime_checks`; open/close incidents
  - **every 1h** — Cloudflare GraphQL pull (httpRequests1hGroups → `analytics_hourly`)
  - **every 6h** — Full zone snapshot: settings, SSL cert packs, firewall rules, DNS records
  - **daily 07:00 SGT** — generate daily report (HTML + PDF), Slack-announce + persist
  - **weekly Monday 08:00 SGT** — weekly report
  - **monthly 1st 09:00 SGT** — monthly report
- Sources Cloudflare tokens from `mmwss.cf_tokens` (decrypts via `MMWSS_MASTER_KEY`)
- Headless Chromium via `playwright` for PDF rendering of reports
- No public ingress

### Shared infra (already on callora EC2)

- `callora-db` (Postgres 15 + pgvector) — MMWSS uses its own `mmwss` schema, own DB user with grants only on that schema
- `callora-redis` — all keys prefixed `mmwss:`
- `callora-caddy` — one new route block: `/mmwss/*` → `mmwss-app:3001`

## Data flow

```
Cloudflare API ──┐
                 v
            mmwss-collector ──┬──> mmwss.zones, zone_snapshots, dns_records_snapshot
                              ├──> mmwss.analytics_hourly
                              ├──> mmwss.uptime_checks
                              └──> mmwss.incidents (created/resolved automatically)

User browser ──> /mmwss ──> Caddy ──> mmwss-app ──> mmwss schema (read-only joins)
                                              └──> mmwss-app writes: users, sessions, cf_tokens, reports, audit_log
```

## Why this shape

- **Collector separated from API**: collector can crash without taking down the dashboard. Restart independently.
- **No new database instance**: 3.7 GB RAM box can't afford a second Postgres. Schema isolation in the existing DB is enough for an internal tool.
- **Python collector, TS API**: ports `cf_report.py` directly (already proven, GraphQL works). Frontend pattern matches the existing callora stack (Tremor + shadcn is industry standard for SaaS dashboards).
- **All scheduling inside the collector container**: no host crontab. One thing to deploy.

## Tenancy

Phase 1 is **single-tenant** — one Redot internal org, one set of Cloudflare credentials. The schema has `cf_tokens` as a list because tomorrow we may onboard more CF accounts, but there is intentionally no `organizations` table yet. If we ever expose this externally we add it then.

## Failure modes & posture

- **Postgres down** → both app + collector log loudly, retry with backoff. No data loss.
- **Redis down** → app fails session checks → users see "service degraded" page. Auth becomes unavailable, no compromise.
- **Cloudflare API down** → collector logs, retries hourly. Dashboard shows "data N hours stale" banner.
- **Collector down** → uptime gap visible in dashboard. Alert fires after 15 min of no heartbeat.
