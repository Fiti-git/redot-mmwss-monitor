"""Report generation — daily / weekly / monthly HTML + PDF, persisted to disk + DB.

Layout:
- HTML rendered from templates/report.html (Jinja)
- PDF rendered from the same HTML via WeasyPrint (no Chromium)
- Files written to /app/reports/{type}/{YYYY-MM-DD}.{html,pdf}
- A row inserted into mmwss.reports with paths + summary_json
- A Slack alert fires when a report is ready (with the dashboard URL)

Recommendations engine: rules-based for now. A handful of high-signal checks
that match what Cloudflare doesn't tell you and what a client meeting would
care about.
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from . import alerts, db
from .config import Settings

log = logging.getLogger(__name__)

REPORTS_DIR = Path("/app/reports")
TEMPLATE_DIR = Path(__file__).parent / "templates"


# ───────── period helpers ─────────


def _period_for(kind: str, ref: datetime | None = None) -> tuple[datetime, datetime, str]:
    """Return (start, end, label) UTC, exclusive end."""
    now = (ref or datetime.now(timezone.utc)).replace(microsecond=0)
    if kind == "daily":
        end = now.replace(hour=0, minute=0, second=0)
        start = end - timedelta(days=1)
        return start, end, start.strftime("%A, %d %b %Y")
    if kind == "weekly":
        # last Monday → this Monday (UTC), so a full 7-day window
        days_since_mon = now.weekday()
        this_mon = (now - timedelta(days=days_since_mon)).replace(hour=0, minute=0, second=0)
        start = this_mon - timedelta(days=7)
        return start, this_mon, f"Week of {start.strftime('%d %b')} – {(this_mon - timedelta(days=1)).strftime('%d %b %Y')}"
    if kind == "monthly":
        # previous calendar month
        first_of_this = now.replace(day=1, hour=0, minute=0, second=0)
        last_month_end = first_of_this
        last_month_start = (first_of_this - timedelta(days=1)).replace(day=1)
        return last_month_start, last_month_end, last_month_start.strftime("%B %Y")
    raise ValueError(f"unknown report kind: {kind}")


# ───────── filters for the template ─────────


def _fmt_int(n) -> str:
    if n is None:
        return "0"
    try:
        return f"{int(n):,}"
    except (TypeError, ValueError):
        return str(n)


def _human_bytes(n) -> str:
    if n is None:
        return "—"
    try:
        num = float(n)
    except (TypeError, ValueError):
        return "—"
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if num < 1024:
            return f"{num:.1f} {unit}"
        num /= 1024
    return f"{num:.1f} PB"


def _env() -> Environment:
    env = Environment(loader=FileSystemLoader(str(TEMPLATE_DIR)), autoescape=select_autoescape(["html"]))
    env.filters["format_int"] = _fmt_int
    env.filters["human_bytes"] = _human_bytes
    env.filters["secs_to_human"] = _secs_to_human
    return env


# ───────── queries (period-scoped) ─────────


def _q1(conn, sql, params=()):
    with conn.cursor() as cur:
        cur.execute(sql, params)
        return cur.fetchone()


def _qn(conn, sql, params=()):
    with conn.cursor() as cur:
        cur.execute(sql, params)
        return cur.fetchall()


def _overview(conn, start, end) -> dict:
    zones = _q1(conn, "SELECT COUNT(*)::int AS n FROM mmwss.zones WHERE status = 'active'")["n"]
    open_inc = _q1(conn, "SELECT COUNT(*)::int AS n FROM mmwss.incidents WHERE ended_at IS NULL")["n"]
    t = _q1(
        conn,
        """
        SELECT COALESCE(SUM(requests), 0)::bigint AS req,
               COALESCE(SUM(cached_requests), 0)::bigint AS cached,
               COALESCE(SUM(bytes), 0)::bigint AS bytes,
               COALESCE(SUM(threats), 0)::bigint AS threats
        FROM mmwss.analytics_hourly
        WHERE hour >= %s AND hour < %s
        """,
        (start, end),
    )
    req = int(t["req"])
    cached = int(t["cached"])
    return {
        "zones": zones,
        "incidents_open": open_inc,
        "requests": req,
        "cached": cached,
        "bytes": int(t["bytes"]),
        "threats": int(t["threats"]),
        "hit_ratio": (cached / req * 100) if req else 0.0,
    }


def _sites(conn, start, end) -> list[dict]:
    rows = _qn(
        conn,
        """
        WITH traffic AS (
            SELECT zone_id,
                   COALESCE(SUM(requests), 0)::bigint AS requests,
                   COALESCE(SUM(cached_requests), 0)::bigint AS cached,
                   COALESCE(SUM(threats), 0)::bigint AS threats,
                   COALESCE(SUM(bytes), 0)::bigint AS bytes
            FROM mmwss.analytics_hourly
            WHERE hour >= %s AND hour < %s
            GROUP BY zone_id
        ),
        uptime AS (
            SELECT zone_id,
                   COUNT(*)::int AS total,
                   COUNT(*) FILTER (WHERE ok)::int AS ok
            FROM mmwss.uptime_checks
            WHERE checked_at >= %s AND checked_at < %s
            GROUP BY zone_id
        ),
        latest_snap AS (
            SELECT DISTINCT ON (zone_id) zone_id, settings_json, ssl_expiry,
                                         fw_rules_enabled, fw_rules_total
            FROM mmwss.zone_snapshots
            ORDER BY zone_id, captured_at DESC
        )
        SELECT z.id, z.name, z.plan,
               COALESCE(t.requests, 0)::bigint AS requests,
               COALESCE(t.cached, 0)::bigint   AS cached,
               COALESCE(t.threats, 0)::bigint  AS threats,
               COALESCE(t.bytes, 0)::bigint    AS bytes,
               u.total AS uptime_total,
               u.ok    AS uptime_ok,
               s.settings_json, s.ssl_expiry,
               s.fw_rules_enabled, s.fw_rules_total
        FROM mmwss.zones z
        LEFT JOIN traffic     t ON t.zone_id = z.id
        LEFT JOIN uptime      u ON u.zone_id = z.id
        LEFT JOIN latest_snap s ON s.zone_id = z.id
        WHERE z.status = 'active'
        ORDER BY z.name
        """,
        (start, end, start, end),
    )
    out: list[dict] = []
    for r in rows:
        req = int(r["requests"])
        cached = int(r["cached"])
        out.append({
            "id": r["id"],
            "name": r["name"],
            "plan": r["plan"],
            "requests": req,
            "cached": cached,
            "threats": int(r["threats"]),
            "bytes": int(r["bytes"]),
            "hit_ratio": (cached / req * 100) if req else None,
            "uptime_pct": (r["uptime_ok"] / r["uptime_total"] * 100) if r["uptime_total"] else None,
            "settings": r["settings_json"] or {},
            "ssl_expiry": r["ssl_expiry"],
            "ssl_expiry_date": r["ssl_expiry"].strftime("%Y-%m-%d") if r["ssl_expiry"] else None,
            "fw_rules_enabled": r["fw_rules_enabled"] or 0,
            "fw_rules_total": r["fw_rules_total"] or 0,
        })
    return out


def _incidents(conn, start, end) -> list[dict]:
    rows = _qn(
        conn,
        """
        SELECT i.id, i.zone_id, z.name AS zone_name, i.type, i.severity,
               i.started_at, i.ended_at, i.summary
        FROM mmwss.incidents i
        JOIN mmwss.zones z ON z.id = i.zone_id
        WHERE (i.started_at >= %s AND i.started_at < %s)
           OR (i.ended_at IS NULL AND i.started_at < %s)
        ORDER BY i.severity DESC, i.started_at DESC
        """,
        (start, end, end),
    )
    out = []
    for r in rows:
        end_dt = r["ended_at"] or datetime.now(timezone.utc)
        delta = end_dt - r["started_at"]
        seconds = int(delta.total_seconds())
        if seconds < 60:
            dur = f"{seconds}s"
        elif seconds < 3600:
            dur = f"{seconds // 60}m"
        elif seconds < 86400:
            dur = f"{seconds // 3600}h{(seconds % 3600) // 60}m"
        else:
            dur = f"{seconds // 86400}d{(seconds % 86400) // 3600}h"
        if r["ended_at"] is None:
            dur = f"{dur} (open)"
        out.append({
            "id": r["id"],
            "zone_id": r["zone_id"],
            "zone_name": r["zone_name"],
            "type": r["type"],
            "severity": r["severity"],
            "started_at_str": r["started_at"].strftime("%Y-%m-%d %H:%M UTC"),
            "summary": r["summary"],
            "duration": dur,
        })
    return out


# ───────── recommendations ─────────


@dataclass
class Recommendation:
    site: str
    severity: str  # 'critical' (red) | 'warn' (amber) | 'info' (blue)
    title: str
    body: str


def _recommend(sites: list[dict]) -> list[Recommendation]:
    """Generate actionable recommendations from latest snapshot settings."""
    out: list[Recommendation] = []
    for s in sites:
        st = s["settings"]
        name = s["name"]
        ssl_mode = (st.get("ssl") or "").lower()
        if ssl_mode in ("off", "flexible"):
            out.append(Recommendation(
                site=name, severity="critical",
                title="SSL mode is unsafe",
                body=f"Origin certificate is not being validated (mode = '{ssl_mode}'). "
                     f"An attacker between Cloudflare and the origin could intercept traffic. "
                     f"Switch to 'strict' (or 'full' if origin cert is self-signed)."
            ))
        elif ssl_mode == "full":
            out.append(Recommendation(
                site=name, severity="warn",
                title="SSL mode is 'full' — consider 'strict'",
                body="'Full' accepts any cert at the origin, including expired or self-signed. "
                     "'Strict' validates the origin certificate against a trusted CA."
            ))
        if (st.get("always_use_https") or "").lower() == "off":
            out.append(Recommendation(
                site=name, severity="critical",
                title="Always Use HTTPS is OFF",
                body="HTTP requests reach the origin in plaintext. Turn on Always Use HTTPS "
                     "in Cloudflare → SSL/TLS → Edge Certificates."
            ))
        sec = (st.get("security_level") or "").lower()
        if sec in ("off", "essentially_off"):
            out.append(Recommendation(
                site=name, severity="critical",
                title="Security level is essentially off",
                body="Cloudflare's basic bot/DDoS protection is disabled. Raise to 'Medium' minimum."
            ))
        tls = str(st.get("min_tls_version") or "")
        if tls in ("1.0", "1.1"):
            out.append(Recommendation(
                site=name, severity="warn",
                title=f"Minimum TLS version is {tls}",
                body="TLS 1.0/1.1 are deprecated and below PCI-DSS baseline. Set minimum to 1.2."
            ))
        if (st.get("brotli") or "").lower() == "off":
            out.append(Recommendation(
                site=name, severity="info",
                title="Brotli compression disabled",
                body="Enabling Brotli reduces bandwidth by ~15–25% over Gzip for the same content. Zero-risk change."
            ))
        if (s["fw_rules_total"] or 0) == 0:
            out.append(Recommendation(
                site=name, severity="info",
                title="No custom firewall rules",
                body="Only default Cloudflare protection is active. Adding a few targeted rules "
                     "(e.g. block country X, rate-limit /wp-login) makes a real difference for WordPress sites."
            ))
        if s["ssl_expiry"]:
            days = (s["ssl_expiry"] - datetime.now(timezone.utc)).days
            if 0 <= days <= 30:
                out.append(Recommendation(
                    site=name,
                    severity="warn" if days >= 7 else "critical",
                    title=f"SSL certificate expires in {days} days",
                    body=f"Cert expires {s['ssl_expiry_date']}. Cloudflare auto-renews, but verify in the dashboard."
                ))
    return out


# ───────── main entry point ─────────


# ───────── SLA / tickets / change-log / VAPT (read from schemas added by
#           migrations 005-007) ─────────


def _sla_summary(conn, start, end) -> dict:
    """SLA compliance per priority for the period.
    Returns {p1: {target_response, target_resolution, total, response_met,
                  response_breached, resolution_met, resolution_breached,
                  still_open}, ...}
    """
    out = {}
    targets = {
        "p1": (2 * 3600,        8 * 3600),
        "p2": (4 * 3600,       24 * 3600),
        "p3": (1 * 24 * 3600,  3 * 24 * 3600),
        "p4": (3 * 24 * 3600,  7 * 24 * 3600),
    }
    for p, (resp, resol) in targets.items():
        out[p] = {
            "target_response_secs": resp,
            "target_resolution_secs": resol,
            "total": 0, "response_met": 0, "response_breached": 0,
            "resolution_met": 0, "resolution_breached": 0, "still_open": 0,
        }
    rows = _qn(
        conn,
        """
        SELECT priority, sla_response_secs, sla_resolution_secs,
               opened_at, response_at, resolved_at
        FROM mmwss.tickets
        WHERE opened_at >= %s AND opened_at < %s
        """,
        (start, end),
    )
    for r in rows:
        p = r["priority"]
        if p not in out:
            continue
        out[p]["total"] += 1
        if r["response_at"]:
            elapsed = (r["response_at"] - r["opened_at"]).total_seconds()
            if elapsed <= r["sla_response_secs"]:
                out[p]["response_met"] += 1
            else:
                out[p]["response_breached"] += 1
        if r["resolved_at"]:
            elapsed = (r["resolved_at"] - r["opened_at"]).total_seconds()
            if elapsed <= r["sla_resolution_secs"]:
                out[p]["resolution_met"] += 1
            else:
                out[p]["resolution_breached"] += 1
        else:
            out[p]["still_open"] += 1
    return out


def _change_log_in_period(conn, start, end) -> list[dict]:
    return _qn(
        conn,
        """
        SELECT c.id, c.category, c.title, c.before_state, c.after_state,
               c.test_result, c.rolled_back, c.executed_at, c.source,
               z.name AS zone_name, u.email AS engineer_email
        FROM mmwss.change_log c
        LEFT JOIN mmwss.zones z ON z.id = c.zone_id
        LEFT JOIN mmwss.users u ON u.id = c.engineer_user_id
        WHERE c.executed_at >= %s AND c.executed_at < %s
        ORDER BY c.executed_at DESC
        """,
        (start, end),
    )


def _change_log_by_category(entries: list[dict]) -> dict[str, dict]:
    """Group change-log rows by category for the summary block."""
    label = {
        "plugin_update": "Plugin updates", "core_update": "WordPress core",
        "theme_update": "Theme updates", "cf_setting": "Cloudflare settings",
        "cf_firewall_rule": "CF firewall rules", "cf_dns": "DNS changes",
        "ssl_renewal": "SSL renewals", "server_config": "Server config",
        "database_change": "Database changes", "custom_code": "Custom code",
        "vapt_remediation": "VAPT remediations", "other": "Other",
    }
    out: dict[str, dict] = {}
    for e in entries:
        cat = e["category"]
        bucket = out.setdefault(cat, {
            "label": label.get(cat, cat), "count": 0,
            "tested_pass": 0, "tested_fail": 0, "untested": 0, "rolled_back": 0,
            "samples": [],
        })
        bucket["count"] += 1
        if e["test_result"] == "passed":
            bucket["tested_pass"] += 1
        elif e["test_result"] == "failed":
            bucket["tested_fail"] += 1
        else:
            bucket["untested"] += 1
        if e["rolled_back"]:
            bucket["rolled_back"] += 1
        if len(bucket["samples"]) < 3:
            bucket["samples"].append(e["title"])
    # Stable ordering: critical maintenance categories first
    order = ["plugin_update", "core_update", "theme_update",
             "cf_setting", "cf_firewall_rule", "cf_dns", "ssl_renewal",
             "server_config", "database_change", "custom_code",
             "vapt_remediation", "other"]
    return {k: out[k] for k in order if k in out}


def _vapt_status_summary(conn, start, end) -> dict:
    """Current VAPT posture + remediations completed in period."""
    by_severity: dict[str, dict[str, int]] = {}
    for sev in ("critical", "high", "medium", "low", "info"):
        by_severity[sev] = {
            "total": 0, "open": 0, "in_progress": 0, "remediated": 0,
            "verified": 0, "accepted_risk": 0, "false_positive": 0,
        }
    rows = _qn(
        conn,
        "SELECT severity, status, COUNT(*)::int AS n FROM mmwss.vapt_findings GROUP BY severity, status",
    )
    for r in rows:
        sev = r["severity"]
        st = r["status"]
        if sev in by_severity:
            by_severity[sev]["total"] += r["n"]
            if st in by_severity[sev]:
                by_severity[sev][st] += r["n"]

    in_period = _q1(
        conn,
        """
        SELECT
            COUNT(*) FILTER (WHERE remediated_at >= %s AND remediated_at < %s)::int AS remediated,
            COUNT(*) FILTER (WHERE verified_at >= %s AND verified_at < %s)::int AS verified,
            COUNT(*) FILTER (WHERE discovered_at >= %s AND discovered_at < %s)::int AS discovered
        FROM mmwss.vapt_findings
        """,
        (start, end, start, end, start, end),
    )
    overall_total = sum(b["total"] for b in by_severity.values())
    overall_closed = sum((b["remediated"] + b["verified"] + b["accepted_risk"] + b["false_positive"])
                        for b in by_severity.values())
    return {
        "by_severity": by_severity,
        "remediated_in_period": in_period["remediated"] if in_period else 0,
        "verified_in_period": in_period["verified"] if in_period else 0,
        "discovered_in_period": in_period["discovered"] if in_period else 0,
        "overall_total": overall_total,
        "overall_closed": overall_closed,
        "completion_pct": (overall_closed / overall_total * 100) if overall_total else None,
    }


def _uptime_per_site(conn, start, end) -> list[dict]:
    rows = _qn(
        conn,
        """
        SELECT z.id, z.name,
               COUNT(uc.id)::int AS total,
               COUNT(uc.id) FILTER (WHERE uc.ok)::int AS ok,
               AVG(uc.latency_ms) FILTER (WHERE uc.ok) AS avg_latency
        FROM mmwss.zones z
        LEFT JOIN mmwss.uptime_checks uc
            ON uc.zone_id = z.id AND uc.checked_at >= %s AND uc.checked_at < %s
        WHERE z.status = 'active'
        GROUP BY z.id, z.name
        ORDER BY z.name
        """,
        (start, end),
    )
    for r in rows:
        r["pct"] = (r["ok"] / r["total"] * 100) if r["total"] else None
    return rows


def _secs_to_human(s: int) -> str:
    if s < 60:   return f"{s}s"
    if s < 3600: return f"{s // 60}m"
    if s < 86400:return f"{s // 3600}h"
    return f"{s // 86400}d"


_WP_TITLES = {
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


def _wp_findings(conn) -> list[dict]:
    rows = _qn(
        conn,
        """
        WITH latest AS (
            SELECT DISTINCT ON (zone_id) zone_id, is_wordpress, wp_version, findings_json
            FROM mmwss.wp_checks ORDER BY zone_id, captured_at DESC
        )
        SELECT z.id AS zone_id, z.name, l.is_wordpress, l.wp_version, l.findings_json
        FROM mmwss.zones z
        JOIN latest l ON l.zone_id = z.id
        WHERE z.status = 'active'
        ORDER BY z.name
        """,
    )
    out: list[dict] = []
    for r in rows:
        for bucket in ("exposures", "config", "health", "info"):
            for f in (r["findings_json"] or {}).get(bucket, []):
                check = f.get("check", "")
                out.append({
                    "zone_name": r["name"],
                    "is_wordpress": r["is_wordpress"],
                    "wp_version": r["wp_version"],
                    "severity": f.get("severity", "info"),
                    "title": _WP_TITLES.get(check, check.replace("_", " ").title()),
                    "details": f.get("details", ""),
                })
    order = {"critical": 0, "warning": 1, "info": 2}
    out.sort(key=lambda x: (order.get(x["severity"], 9), x["zone_name"]))
    return out


def generate_report(settings: Settings, conn, kind: str) -> int:
    """Render + persist + announce a report. Returns mmwss.reports.id."""
    start, end, period_label = _period_for(kind)
    stats = _overview(conn, start, end)
    sites = _sites(conn, start, end)
    incidents = _incidents(conn, start, end)
    recommendations = _recommend(sites)
    wp_findings = _wp_findings(conn)

    # Contract-aligned sections (added in week 1 of maintenance build-out)
    sla_summary    = _sla_summary(conn, start, end)
    change_entries = _change_log_in_period(conn, start, end)
    change_by_cat  = _change_log_by_category(change_entries)
    vapt_summary   = _vapt_status_summary(conn, start, end)
    uptime_sites   = _uptime_per_site(conn, start, end)

    # Bar-chart data: only sites with >0 threats, scaled to max=100
    max_threats = max((s["threats"] for s in sites), default=0)
    sites_with_threats = [
        {**s, "threat_pct": (s["threats"] / max_threats * 100) if max_threats else 0}
        for s in sites if s["threats"] > 0
    ]

    title = {
        "daily":   f"Daily report — {period_label}",
        "weekly":  f"Weekly report — {period_label}",
        "monthly": f"Monthly report — {period_label}",
    }.get(kind, f"Report — {period_label}")

    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    ctx = {
        "company": "Redot Global",
        "product": "MMWSS",
        "report_type": kind,
        "title": title,
        "period_label": period_label,
        "generated_at": generated_at,
        "footer_left": f"MMWSS — {kind.title()} report · {period_label}",
        "stats": stats,
        "sites": sites,
        "sites_with_threats": sites_with_threats,
        "incidents": incidents,
        "recommendations": [{"site": r.site, "severity": r.severity, "title": r.title, "body": r.body}
                            for r in recommendations],
        "wp_findings": wp_findings,
        # Contract-aligned sections
        "sla_summary":    sla_summary,
        "uptime_sites":   uptime_sites,
        "change_entries": change_entries,
        "change_by_cat":  change_by_cat,
        "vapt_summary":   vapt_summary,
        "secs_to_human":  _secs_to_human,
    }

    tmpl = _env().get_template("report.html")
    html = tmpl.render(**ctx)

    # Write files
    subdir = REPORTS_DIR / kind
    subdir.mkdir(parents=True, exist_ok=True)
    stamp = start.strftime("%Y-%m-%d")
    html_path = subdir / f"{stamp}.html"
    pdf_path = subdir / f"{stamp}.pdf"

    html_path.write_text(html, encoding="utf-8")
    log.info("Wrote %s (%d bytes)", html_path, len(html))

    # PDF via WeasyPrint
    try:
        from weasyprint import HTML  # local import — heavy module
        HTML(string=html, base_url=str(REPORTS_DIR)).write_pdf(target=str(pdf_path))
        log.info("Wrote %s", pdf_path)
    except Exception:
        log.exception("PDF render failed — HTML report still available")
        pdf_path = None

    # DB row
    summary_json = {
        "zones": stats["zones"],
        "requests": stats["requests"],
        "cached": stats["cached"],
        "bytes": stats["bytes"],
        "threats": stats["threats"],
        "hit_ratio": stats["hit_ratio"],
        "incidents_open": stats["incidents_open"],
        "incidents_in_period": len(incidents),
        "recommendations": len(recommendations),
    }
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO mmwss.reports
                (type, period_start, period_end, html_path, pdf_path, summary_json)
            VALUES (%s, %s, %s, %s, %s, %s::jsonb)
            RETURNING id
            """,
            (kind, start, end, str(html_path), str(pdf_path) if pdf_path else None, json.dumps(summary_json)),
        )
        report_id = cur.fetchone()["id"]
    conn.commit()
    log.info("Inserted mmwss.reports id=%d (%s, %s)", report_id, kind, period_label)

    # Slack announcement
    if settings.slack_webhook_url:
        try:
            _announce_slack(settings, report_id, kind, period_label, stats, len(incidents), len(recommendations))
        except Exception:
            log.exception("Failed to post report announcement to Slack")

    return report_id


def _announce_slack(settings: Settings, report_id: int, kind: str, period_label: str,
                    stats: dict, n_incidents: int, n_recs: int) -> None:
    """Post a compact summary card to Slack when a report is generated."""
    dash_url = f"{settings.mmwss_public_url}/mmwss/reports"
    payload = {
        "text": f"MMWSS {kind} report ready for {period_label}",
        "attachments": [{
            "color": "#E11E27",
            "blocks": [
                {"type": "header", "text": {"type": "plain_text", "text": f":bar_chart:  MMWSS {kind.title()} Report"}},
                {"type": "section", "text": {"type": "mrkdwn",
                    "text": f"*{period_label}*\nGenerated on {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}"}},
                {"type": "section", "fields": [
                    {"type": "mrkdwn", "text": f"*Requests*\n{stats['requests']:,}"},
                    {"type": "mrkdwn", "text": f"*Threats blocked*\n{stats['threats']:,}"},
                    {"type": "mrkdwn", "text": f"*Cache hit*\n{stats['hit_ratio']:.1f}%"},
                    {"type": "mrkdwn", "text": f"*Incidents in period*\n{n_incidents}"},
                ]},
                {"type": "context", "elements": [
                    {"type": "mrkdwn", "text": f"_{n_recs} recommendation{'s' if n_recs != 1 else ''} · Open in MMWSS to download_"}
                ]},
                {"type": "actions", "elements": [
                    {"type": "button", "url": dash_url,
                     "text": {"type": "plain_text", "text": "View reports", "emoji": True}}
                ]},
            ],
        }],
    }
    alerts._post_slack(settings.slack_webhook_url, payload)
    log.info("Slack: announced report #%d", report_id)
