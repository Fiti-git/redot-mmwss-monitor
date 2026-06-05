"""Read-only queries that drive every page. Plain SQL — easier to read than ORM."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from . import db


def overview_stats() -> dict:
    """KPI numbers for dashboard."""
    since = datetime.now(timezone.utc) - timedelta(hours=24)
    zones_count = db.fetch_one("SELECT COUNT(*)::int AS n FROM mmwss.zones WHERE status = 'active'")["n"]
    open_incidents = db.fetch_one("SELECT COUNT(*)::int AS n FROM mmwss.incidents WHERE ended_at IS NULL")["n"]
    totals = db.fetch_one(
        """
        SELECT COALESCE(SUM(requests), 0)::bigint        AS requests,
               COALESCE(SUM(cached_requests), 0)::bigint AS cached,
               COALESCE(SUM(bytes), 0)::bigint           AS bytes,
               COALESCE(SUM(threats), 0)::bigint         AS threats
        FROM mmwss.analytics_hourly
        WHERE hour >= %s
        """,
        (since,),
    )
    return {
        "zones": zones_count,
        "open_incidents": open_incidents,
        "requests_24h": int(totals["requests"]),
        "cached_24h": int(totals["cached"]),
        "bytes_24h": int(totals["bytes"]),
        "threats_24h": int(totals["threats"]),
        "hit_ratio": (int(totals["cached"]) / int(totals["requests"]) * 100) if totals["requests"] else 0.0,
    }


def zones_with_status() -> list[dict]:
    """Each zone with latest uptime, last snapshot, 24h traffic."""
    since = datetime.now(timezone.utc) - timedelta(hours=24)
    rows = db.fetch_all(
        """
        WITH latest_uptime AS (
            SELECT DISTINCT ON (zone_id) zone_id, ok, status_code, latency_ms, checked_at
            FROM mmwss.uptime_checks
            ORDER BY zone_id, checked_at DESC
        ),
        latest_snap AS (
            SELECT DISTINCT ON (zone_id) zone_id, settings_json, ssl_expiry,
                   fw_rules_enabled, fw_rules_total, dns_count
            FROM mmwss.zone_snapshots
            ORDER BY zone_id, captured_at DESC
        ),
        traffic AS (
            SELECT zone_id,
                   SUM(requests)::bigint AS requests,
                   SUM(cached_requests)::bigint AS cached,
                   SUM(bytes)::bigint AS bytes,
                   SUM(threats)::bigint AS threats
            FROM mmwss.analytics_hourly
            WHERE hour >= %s
            GROUP BY zone_id
        )
        SELECT z.id, z.name, z.plan, z.status, z.last_synced_at,
               u.ok AS uptime_ok, u.status_code AS uptime_code, u.latency_ms,
               s.settings_json, s.ssl_expiry, s.fw_rules_enabled, s.fw_rules_total, s.dns_count,
               t.requests, t.cached, t.bytes, t.threats
        FROM mmwss.zones z
        LEFT JOIN latest_uptime u ON u.zone_id = z.id
        LEFT JOIN latest_snap   s ON s.zone_id = z.id
        LEFT JOIN traffic       t ON t.zone_id = z.id
        WHERE z.status = 'active'
        ORDER BY z.name
        """,
        (since,),
    )
    return rows


def zone_by_id(zone_id: int) -> dict | None:
    return db.fetch_one(
        """
        SELECT z.id, z.name, z.plan, z.status, z.last_synced_at,
               z.name_servers_json, z.cf_zone_id
        FROM mmwss.zones z WHERE z.id = %s
        """,
        (zone_id,),
    )


def zone_latest_snapshot(zone_id: int) -> dict | None:
    return db.fetch_one(
        """
        SELECT id, captured_at, settings_json, ssl_expiry, ssl_packs_active,
               fw_rules_total, fw_rules_enabled, dns_count, dns_by_type_json, dns_proxied_count
        FROM mmwss.zone_snapshots
        WHERE zone_id = %s
        ORDER BY captured_at DESC
        LIMIT 1
        """,
        (zone_id,),
    )


def zone_dns_records(snapshot_id: int) -> list[dict]:
    return db.fetch_all(
        """
        SELECT type, name, content, proxied, ttl
        FROM mmwss.dns_records_snapshot
        WHERE zone_snapshot_id = %s
        ORDER BY type, name
        """,
        (snapshot_id,),
    )


def zone_uptime_recent(zone_id: int, limit: int = 20) -> list[dict]:
    return db.fetch_all(
        """
        SELECT id, checked_at, status_code, latency_ms, ok, error_message
        FROM mmwss.uptime_checks
        WHERE zone_id = %s
        ORDER BY checked_at DESC
        LIMIT %s
        """,
        (zone_id, limit),
    )


def zone_traffic_24h(zone_id: int) -> list[dict]:
    """For chart: 24 hourly buckets."""
    since = datetime.now(timezone.utc) - timedelta(hours=24)
    return db.fetch_all(
        """
        SELECT hour, requests, cached_requests, bytes, threats
        FROM mmwss.analytics_hourly
        WHERE zone_id = %s AND hour >= %s
        ORDER BY hour
        """,
        (zone_id, since),
    )


def zone_uptime_24h_summary(zone_id: int) -> dict:
    since = datetime.now(timezone.utc) - timedelta(hours=24)
    row = db.fetch_one(
        """
        SELECT
            COUNT(*)::int AS total,
            COUNT(*) FILTER (WHERE ok)::int AS ok,
            AVG(latency_ms) FILTER (WHERE ok) AS avg_latency
        FROM mmwss.uptime_checks
        WHERE zone_id = %s AND checked_at >= %s
        """,
        (zone_id, since),
    )
    total = row["total"] or 0
    ok = row["ok"] or 0
    pct = (ok / total * 100) if total else None
    return {"total": total, "ok": ok, "pct": pct, "avg_latency": row["avg_latency"]}


def recent_incidents(limit: int = 100) -> list[dict]:
    return db.fetch_all(
        """
        SELECT i.id, i.zone_id, z.name AS zone_name, i.type, i.severity,
               i.started_at, i.ended_at, i.summary
        FROM mmwss.incidents i
        JOIN mmwss.zones z ON z.id = i.zone_id
        ORDER BY i.started_at DESC
        LIMIT %s
        """,
        (limit,),
    )


def zone_incidents(zone_id: int, limit: int = 20) -> list[dict]:
    return db.fetch_all(
        """
        SELECT id, type, severity, started_at, ended_at, summary
        FROM mmwss.incidents WHERE zone_id = %s
        ORDER BY started_at DESC LIMIT %s
        """,
        (zone_id, limit),
    )


def uptime_summary_all() -> list[dict]:
    """Per-zone 24h uptime summary for the /uptime page."""
    since = datetime.now(timezone.utc) - timedelta(hours=24)
    return db.fetch_all(
        """
        WITH summary AS (
            SELECT zone_id,
                   COUNT(*)::int AS total,
                   COUNT(*) FILTER (WHERE ok)::int AS ok,
                   AVG(latency_ms) FILTER (WHERE ok) AS avg_latency
            FROM mmwss.uptime_checks
            WHERE checked_at >= %s
            GROUP BY zone_id
        ),
        latest AS (
            SELECT DISTINCT ON (zone_id) zone_id, ok, status_code, checked_at
            FROM mmwss.uptime_checks
            ORDER BY zone_id, checked_at DESC
        )
        SELECT z.id, z.name,
               COALESCE(s.total, 0) AS total,
               COALESCE(s.ok, 0)    AS ok,
               s.avg_latency,
               l.ok AS latest_ok,
               l.status_code AS latest_status
        FROM mmwss.zones z
        LEFT JOIN summary s ON s.zone_id = z.id
        LEFT JOIN latest  l ON l.zone_id = z.id
        WHERE z.status = 'active'
        ORDER BY z.name
        """,
        (since,),
    )


def list_users() -> list[dict]:
    return db.fetch_all(
        "SELECT id, email, name, role, is_active, created_at, last_login_at FROM mmwss.users ORDER BY email"
    )


def list_cf_tokens() -> list[dict]:
    return db.fetch_all(
        "SELECT id, label, last_4, created_at, last_used_at FROM mmwss.cf_tokens ORDER BY label"
    )


def list_reports(limit: int = 50) -> list[dict]:
    return db.fetch_all(
        """
        SELECT id, type, period_start, period_end, html_path, pdf_path,
               generated_at, downloaded_count
        FROM mmwss.reports
        ORDER BY generated_at DESC
        LIMIT %s
        """,
        (limit,),
    )
