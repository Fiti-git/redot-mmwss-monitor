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


def overview_traffic_24h() -> list[dict]:
    """Aggregate traffic across all zones, hourly buckets, last 24h."""
    since = datetime.now(timezone.utc) - timedelta(hours=24)
    return db.fetch_all(
        """
        SELECT hour,
               SUM(requests)::bigint        AS requests,
               SUM(cached_requests)::bigint AS cached,
               SUM(threats)::bigint         AS threats,
               SUM(bytes)::bigint           AS bytes
        FROM mmwss.analytics_hourly
        WHERE hour >= %s
        GROUP BY hour
        ORDER BY hour
        """,
        (since,),
    )


def overview_uptime_24h() -> dict:
    """Aggregate uptime % across all zones, last 24h."""
    since = datetime.now(timezone.utc) - timedelta(hours=24)
    r = db.fetch_one(
        """
        SELECT COUNT(*)::int AS total,
               COUNT(*) FILTER (WHERE ok)::int AS ok
        FROM mmwss.uptime_checks
        WHERE checked_at >= %s
        """,
        (since,),
    )
    total = r["total"] or 0
    ok = r["ok"] or 0
    return {"total": total, "ok": ok, "pct": (ok / total * 100) if total else None}


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


def latest_wp_check(zone_id: int) -> dict | None:
    return db.fetch_one(
        """
        SELECT id, captured_at, is_wordpress, wp_version, home_status,
               home_latency_ms, findings_json
        FROM mmwss.wp_checks
        WHERE zone_id = %s
        ORDER BY captured_at DESC
        LIMIT 1
        """,
        (zone_id,),
    )


def wp_findings_all() -> list[dict]:
    """Flatten the latest wp_checks into a row-per-finding list for the
    Recommendations page / a dedicated WP page."""
    rows = db.fetch_all(
        """
        WITH latest AS (
            SELECT DISTINCT ON (zone_id) zone_id, captured_at,
                   is_wordpress, wp_version, findings_json
            FROM mmwss.wp_checks
            ORDER BY zone_id, captured_at DESC
        )
        SELECT z.id AS zone_id, z.name, l.is_wordpress, l.wp_version,
               l.findings_json, l.captured_at
        FROM mmwss.zones z
        JOIN latest l ON l.zone_id = z.id
        WHERE z.status = 'active'
        ORDER BY z.name
        """
    )
    out: list[dict] = []
    sev_order = {"critical": 0, "warning": 1, "info": 2}
    for r in rows:
        for bucket in ("exposures", "config", "health", "info"):
            for f in (r["findings_json"] or {}).get(bucket, []):
                out.append({
                    "zone_id": r["zone_id"],
                    "zone_name": r["name"],
                    "is_wordpress": r["is_wordpress"],
                    "wp_version": r["wp_version"],
                    "captured_at": r["captured_at"],
                    "bucket": bucket,
                    "severity": f.get("severity", "info"),
                    "check": f.get("check"),
                    "details": f.get("details", ""),
                })
    out.sort(key=lambda x: (sev_order.get(x["severity"], 9), x["zone_name"]))
    return out


def list_users() -> list[dict]:
    return db.fetch_all(
        "SELECT id, email, name, role, is_active, created_at, last_login_at FROM mmwss.users ORDER BY email"
    )


def list_cf_tokens() -> list[dict]:
    return db.fetch_all(
        "SELECT id, label, last_4, created_at, last_used_at FROM mmwss.cf_tokens ORDER BY label"
    )


_TITLE_FOR_WP = {
    "wp_config_exposed":          "wp-config.php is publicly served",
    "env_exposed":                ".env file is publicly served",
    "install_script_accessible":  "WordPress installer is reachable",
    "wp_admin_exposed":           "Admin dashboard is exposed",
    "rest_users_enumerable":      "WP user list is publicly enumerable",
    "xmlrpc_enabled":             "XML-RPC endpoint is enabled",
    "wp_version_in_generator":    "WordPress version disclosed",
    "readme_html_present":        "/readme.html present",
    "home_5xx":                   "Home page returning 5xx",
    "home_4xx":                   "Home page returning 4xx",
    "home_unreachable":           "Home page unreachable",
    "error_text_on_page":         "Error text visible on home page",
    "backup_file_exposed":        "Backup or VCS file exposed",
}


def all_recommendations() -> list[dict]:
    """Unified issue stream: Cloudflare recommendations + WordPress findings.

    Each item is dict-shaped with: source ('cloudflare'|'wordpress'),
    zone_id, zone_name, severity, title, body, rule_id. Sorted by
    (severity, source, zone_name).
    """
    from . import recommendations as recs

    # ─── Cloudflare rules ───
    cf_rows = db.fetch_all(
        """
        WITH latest_snap AS (
            SELECT DISTINCT ON (zone_id) zone_id, settings_json, ssl_expiry,
                                          fw_rules_total
            FROM mmwss.zone_snapshots ORDER BY zone_id, captured_at DESC
        )
        SELECT z.id AS zone_id, z.name, z.plan,
               s.settings_json, s.ssl_expiry, s.fw_rules_total
        FROM mmwss.zones z
        LEFT JOIN latest_snap s ON s.zone_id = z.id
        WHERE z.status = 'active'
        ORDER BY z.name
        """
    )
    out: list[dict] = []
    for r in cf_rows:
        for rec in recs.evaluate(
            name=r["name"], settings=r["settings_json"],
            ssl_expiry=r["ssl_expiry"], fw_rules_total=r["fw_rules_total"],
        ):
            out.append({
                "source": "cloudflare", "zone_id": r["zone_id"], "zone_name": r["name"],
                "plan": r["plan"], "severity": rec.severity,
                "title": rec.title, "body": rec.body, "rule_id": rec.rule_id,
            })

    # ─── WordPress findings ───
    wp_rows = db.fetch_all(
        """
        WITH latest AS (
            SELECT DISTINCT ON (zone_id) zone_id, captured_at, findings_json
            FROM mmwss.wp_checks ORDER BY zone_id, captured_at DESC
        )
        SELECT z.id AS zone_id, z.name, l.findings_json, l.captured_at
        FROM mmwss.zones z
        JOIN latest l ON l.zone_id = z.id
        WHERE z.status = 'active'
        """
    )
    for r in wp_rows:
        for bucket in ("exposures", "config", "health", "info"):
            for f in (r["findings_json"] or {}).get(bucket, []):
                check = f.get("check", "")
                out.append({
                    "source": "wordpress",
                    "zone_id": r["zone_id"], "zone_name": r["name"], "plan": None,
                    "severity": f.get("severity", "info"),
                    "title": _TITLE_FOR_WP.get(check, check.replace("_", " ").title()),
                    "body": f.get("details", ""),
                    "rule_id": check,
                })

    severity_order = {"critical": 0, "warning": 1, "info": 2}
    out.sort(key=lambda r: (severity_order.get(r["severity"], 9), r["source"], r["zone_name"]))
    return out


def zone_recommendations(zone_id: int) -> list[dict]:
    """Return CF recommendations for one zone (per-zone page also renders
    the WP findings card separately, so we keep this query CF-only)."""
    from . import recommendations as recs
    snap = db.fetch_one(
        """
        SELECT z.name, s.settings_json, s.ssl_expiry, s.fw_rules_total
        FROM mmwss.zones z
        LEFT JOIN LATERAL (
            SELECT settings_json, ssl_expiry, fw_rules_total
            FROM mmwss.zone_snapshots
            WHERE zone_id = z.id ORDER BY captured_at DESC LIMIT 1
        ) s ON true
        WHERE z.id = %s
        """,
        (zone_id,),
    )
    if not snap:
        return []
    items = recs.evaluate(
        name=snap["name"], settings=snap["settings_json"],
        ssl_expiry=snap["ssl_expiry"], fw_rules_total=snap["fw_rules_total"],
    )
    return [
        {"severity": r.severity, "title": r.title, "body": r.body, "rule_id": r.rule_id}
        for r in items
    ]


def _wp_score_deduction_for(zone_id: int) -> tuple[int, int, int, int]:
    """Return (total_points, n_critical, n_warning, n_info) for one zone's
    latest WP check. Weights mirror CF: critical 15, warning 7, info 2."""
    weights = {"critical": 15, "warning": 7, "info": 2}
    r = db.fetch_one(
        "SELECT findings_json FROM mmwss.wp_checks WHERE zone_id = %s ORDER BY captured_at DESC LIMIT 1",
        (zone_id,),
    )
    if not r:
        return (0, 0, 0, 0)
    f = r["findings_json"] or {}
    crit = warn = info = 0
    for bucket in ("exposures", "config", "health", "info"):
        for it in f.get(bucket, []):
            sev = it.get("severity")
            if sev == "critical": crit += 1
            elif sev == "warning": warn += 1
            elif sev == "info": info += 1
    total = crit * weights["critical"] + warn * weights["warning"] + info * weights["info"]
    return (total, crit, warn, info)


def zones_scored() -> list[dict]:
    """Like zones_with_status() but adds a security score (0-100) that
    accounts for BOTH Cloudflare recommendations and WordPress findings.
    """
    from . import recommendations as recs
    base = zones_with_status()
    enriched = []
    for z in base:
        cf_items = recs.evaluate(
            name=z["name"],
            settings=z.get("settings_json") or {},
            ssl_expiry=z.get("ssl_expiry"),
            fw_rules_total=z.get("fw_rules_total"),
        )
        cf_deduction = sum(r.weight for r in cf_items)
        wp_deduction, wp_crit, wp_warn, wp_info = _wp_score_deduction_for(z["id"])
        score = max(0, 100 - cf_deduction - wp_deduction)
        letter, color = recs.score_to_grade(score)
        cf_crit = sum(1 for r in cf_items if r.severity == "critical")
        cf_warn = sum(1 for r in cf_items if r.severity == "warning")
        cf_info = sum(1 for r in cf_items if r.severity == "info")
        enriched.append({
            **z,
            "score": score, "grade": letter, "grade_color": color,
            "rec_count":    len(cf_items) + (wp_crit + wp_warn + wp_info),
            "rec_critical": cf_crit + wp_crit,
            "rec_warning":  cf_warn + wp_warn,
            "rec_info":     cf_info + wp_info,
        })
    return enriched


def aggregate_security_score() -> dict:
    """Average score + counts across all sites."""
    zs = zones_scored()
    if not zs:
        return {"score": None, "rec_count": 0, "rec_critical": 0, "rec_warning": 0, "rec_info": 0}
    return {
        "score": int(round(sum(z["score"] for z in zs) / len(zs))),
        "rec_count":    sum(z["rec_count"] for z in zs),
        "rec_critical": sum(z["rec_critical"] for z in zs),
        "rec_warning":  sum(z["rec_warning"] for z in zs),
        "rec_info":     sum(z["rec_info"] for z in zs),
    }


def analytics_daily(days: int = 30) -> list[dict]:
    """Aggregate analytics by UTC day across all zones, last N days."""
    since = datetime.now(timezone.utc) - timedelta(days=days)
    return db.fetch_all(
        """
        SELECT date_trunc('day', hour) AS day,
               COALESCE(SUM(requests), 0)::bigint        AS requests,
               COALESCE(SUM(cached_requests), 0)::bigint AS cached,
               COALESCE(SUM(bytes), 0)::bigint           AS bytes,
               COALESCE(SUM(threats), 0)::bigint         AS threats
        FROM mmwss.analytics_hourly
        WHERE hour >= %s
        GROUP BY day
        ORDER BY day
        """,
        (since,),
    )


def uptime_daily(days: int = 30) -> list[dict]:
    """Per-zone, per-day uptime %."""
    since = datetime.now(timezone.utc) - timedelta(days=days)
    return db.fetch_all(
        """
        SELECT date_trunc('day', uc.checked_at) AS day,
               z.id AS zone_id, z.name AS zone_name,
               COUNT(*)::int AS total,
               COUNT(*) FILTER (WHERE ok)::int AS ok
        FROM mmwss.uptime_checks uc
        JOIN mmwss.zones z ON z.id = uc.zone_id
        WHERE uc.checked_at >= %s
        GROUP BY day, z.id, z.name
        ORDER BY day, z.name
        """,
        (since,),
    )


def top_sites_by_threats(days: int = 30, limit: int = 6) -> list[dict]:
    since = datetime.now(timezone.utc) - timedelta(days=days)
    return db.fetch_all(
        """
        SELECT z.id, z.name, COALESCE(SUM(a.threats), 0)::bigint AS threats
        FROM mmwss.zones z
        LEFT JOIN mmwss.analytics_hourly a
            ON a.zone_id = z.id AND a.hour >= %s
        WHERE z.status = 'active'
        GROUP BY z.id, z.name
        ORDER BY threats DESC NULLS LAST
        LIMIT %s
        """,
        (since, limit),
    )


def top_sites_by_traffic(days: int = 30, limit: int = 6) -> list[dict]:
    since = datetime.now(timezone.utc) - timedelta(days=days)
    return db.fetch_all(
        """
        SELECT z.id, z.name,
               COALESCE(SUM(a.requests), 0)::bigint AS requests,
               COALESCE(SUM(a.bytes), 0)::bigint    AS bytes
        FROM mmwss.zones z
        LEFT JOIN mmwss.analytics_hourly a
            ON a.zone_id = z.id AND a.hour >= %s
        WHERE z.status = 'active'
        GROUP BY z.id, z.name
        ORDER BY requests DESC NULLS LAST
        LIMIT %s
        """,
        (since, limit),
    )


def period_totals(days: int = 30) -> dict:
    since = datetime.now(timezone.utc) - timedelta(days=days)
    a = db.fetch_one(
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
    u = db.fetch_one(
        """
        SELECT COUNT(*)::int AS total,
               COUNT(*) FILTER (WHERE ok)::int AS ok
        FROM mmwss.uptime_checks WHERE checked_at >= %s
        """,
        (since,),
    )
    requests = int(a["requests"])
    cached = int(a["cached"])
    return {
        "requests": requests,
        "cached":   cached,
        "bytes":    int(a["bytes"]),
        "threats":  int(a["threats"]),
        "hit_ratio": (cached / requests * 100) if requests else 0.0,
        "uptime_pct": (u["ok"] / u["total"] * 100) if u["total"] else None,
        "incidents": db.fetch_one(
            "SELECT COUNT(*)::int AS n FROM mmwss.incidents WHERE started_at >= %s",
            (since,),
        )["n"],
    }


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
