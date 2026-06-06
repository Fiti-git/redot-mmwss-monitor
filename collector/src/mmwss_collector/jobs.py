"""Scheduled jobs: uptime probes, analytics pull, full snapshots, incident management."""
from __future__ import annotations

import json
import logging
import time
from datetime import datetime, timezone

import requests

from . import alerts, db, wp_checks
from .cloudflare import CloudflareClient, CloudflareError
from .config import Settings

log = logging.getLogger(__name__)


# ───────── Uptime probe ─────────

def probe_uptime(settings: Settings, conn) -> int:
    """HTTPS GET each zone's apex, write uptime_checks row, open/close incidents.

    Returns count of zones probed.
    """
    with conn.cursor() as cur:
        cur.execute("SELECT id, name FROM mmwss.zones WHERE status = 'active'")
        zones = cur.fetchall()

    for z in zones:
        zid = z["id"]
        url = f"https://{z['name']}"
        start = time.monotonic()
        status_code = None
        error = None
        ok = False
        try:
            r = requests.get(url, timeout=settings.uptime_probe_timeout_s, allow_redirects=True,
                             headers={"User-Agent": settings.cf_user_agent})
            status_code = r.status_code
            ok = 200 <= status_code < 500   # 4xx still "site responding"; only 5xx/timeouts count as down
        except requests.RequestException as e:
            error = str(e)[:200]
        latency_ms = int((time.monotonic() - start) * 1000)

        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO mmwss.uptime_checks (zone_id, status_code, latency_ms, ok, error_message)
                VALUES (%s, %s, %s, %s, %s)
                """,
                (zid, status_code, latency_ms, ok, error),
            )
            # Incident logic: 2 consecutive failures opens; 2 consecutive successes closes.
            cur.execute(
                "SELECT ok FROM mmwss.uptime_checks WHERE zone_id = %s ORDER BY id DESC LIMIT 2",
                (zid,),
            )
            last_two = [r["ok"] for r in cur.fetchall()]
            cur.execute(
                "SELECT id FROM mmwss.incidents WHERE zone_id = %s AND type = 'site_down' AND ended_at IS NULL LIMIT 1",
                (zid,),
            )
            open_incident = cur.fetchone()
            if len(last_two) == 2 and not any(last_two) and not open_incident:
                summary = f"{z['name']} appears down (2 consecutive failed probes)"
                details = {"last_status": status_code, "last_error": error, "latency_ms": latency_ms}
                cur.execute(
                    """
                    INSERT INTO mmwss.incidents (zone_id, type, severity, summary, details_json)
                    VALUES (%s, 'site_down', 'critical', %s, %s::jsonb)
                    RETURNING id
                    """,
                    (zid, summary, json.dumps(details)),
                )
                new_id = cur.fetchone()["id"]
                # Auto-create a P1 ticket linked to this incident (uptime = SLA P1)
                cur.execute(
                    """
                    INSERT INTO mmwss.tickets
                        (title, description, priority, category, source, zone_id, incident_id,
                         sla_response_secs, sla_resolution_secs)
                    VALUES (%s, %s, 'p1', 'uptime', 'auto_incident', %s, %s, 7200, 28800)
                    RETURNING id
                    """,
                    (f"[P1] {z['name']} down", summary, zid, new_id),
                )
                new_ticket_id = cur.fetchone()["id"]
                cur.execute(
                    """
                    INSERT INTO mmwss.ticket_events (ticket_id, event_type, details_json)
                    VALUES (%s, 'created', %s::jsonb)
                    """,
                    (new_ticket_id, json.dumps({"source": "auto_incident", "incident_id": new_id})),
                )
                log.warning("Opened incident #%d + ticket #%d: %s down", new_id, new_ticket_id, z["name"])
                conn.commit()
                alerts.notify_incident_opened(
                    settings, conn,
                    zone_id=zid, zone_name=z["name"], incident_id=new_id,
                    severity="critical", summary=summary, details=details,
                )
            elif len(last_two) == 2 and all(last_two) and open_incident:
                cur.execute(
                    "UPDATE mmwss.incidents SET ended_at = now() WHERE id = %s",
                    (open_incident["id"],),
                )
                # Auto-resolve the linked ticket too (if any)
                cur.execute(
                    """
                    UPDATE mmwss.tickets
                    SET status = 'resolved',
                        resolved_at = COALESCE(resolved_at, now()),
                        response_at = COALESCE(response_at, opened_at),
                        resolution_notes = COALESCE(resolution_notes,
                          'Auto-resolved: site recovered (2 consecutive successful probes).')
                    WHERE incident_id = %s AND status IN ('open', 'in_progress')
                    RETURNING id
                    """,
                    (open_incident["id"],),
                )
                resolved_ticket = cur.fetchone()
                if resolved_ticket:
                    cur.execute(
                        "INSERT INTO mmwss.ticket_events (ticket_id, event_type, details_json) "
                        "VALUES (%s, 'resolved', %s::jsonb)",
                        (resolved_ticket["id"], json.dumps({"source": "auto_incident_recovery"})),
                    )
                conn.commit()
                log.info("Closed incident #%d: %s recovered", open_incident["id"], z["name"])
                alerts.notify_incident_resolved(
                    settings, conn,
                    zone_id=zid, zone_name=z["name"], incident_id=open_incident["id"],
                    summary=f"{z['name']} has been responding successfully for 2+ consecutive probes.",
                )
        conn.commit()
    return len(zones)


# ───────── Hourly analytics pull ─────────

def pull_analytics_hourly(settings: Settings, conn) -> int:
    """Pull last 24h hourly buckets from CF GraphQL into mmwss.analytics_hourly.

    Returns rows upserted.
    """
    tokens_by_id = {t["id"]: t for t in db.get_active_cf_tokens(conn, settings.mmwss_master_key)}
    if not tokens_by_id:
        log.warning("No CF tokens — skipping analytics pull")
        return 0

    with conn.cursor() as cur:
        cur.execute("SELECT id, cf_zone_id, cf_token_id, name FROM mmwss.zones WHERE status = 'active'")
        zones = cur.fetchall()

    upserts = 0
    for z in zones:
        tok = tokens_by_id.get(z["cf_token_id"])
        if not tok:
            log.warning("No token for zone %s — skip", z["name"])
            continue
        client = CloudflareClient(tok["token"], user_agent=settings.cf_user_agent)
        try:
            buckets = client.fetch_analytics_hourly(z["cf_zone_id"], hours_back=24)
        except CloudflareError as e:
            log.warning("Analytics pull failed for %s: %s", z["name"], e)
            continue
        if not buckets:
            continue
        with conn.cursor() as cur:
            for b in buckets:
                cur.execute(
                    """
                    INSERT INTO mmwss.analytics_hourly
                        (zone_id, hour, requests, cached_requests, bytes, cached_bytes, threats)
                    VALUES (%s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (zone_id, hour) DO UPDATE SET
                        requests = EXCLUDED.requests,
                        cached_requests = EXCLUDED.cached_requests,
                        bytes = EXCLUDED.bytes,
                        cached_bytes = EXCLUDED.cached_bytes,
                        threats = EXCLUDED.threats,
                        fetched_at = now()
                    """,
                    (z["id"], b["datetime"], b["requests"], b["cachedRequests"],
                     b["bytes"], b["cachedBytes"], b["threats"]),
                )
                upserts += 1
        conn.commit()
    return upserts


# ───────── Full snapshot (settings, SSL, FW, DNS) every 6h ─────────

def take_snapshot(settings: Settings, conn) -> int:
    """For each zone: fetch settings, SSL, FW, DNS — write to zone_snapshots + dns_records_snapshot."""
    from collections import Counter
    tokens_by_id = {t["id"]: t for t in db.get_active_cf_tokens(conn, settings.mmwss_master_key)}
    if not tokens_by_id:
        return 0

    with conn.cursor() as cur:
        cur.execute("SELECT id, cf_zone_id, cf_token_id, name FROM mmwss.zones WHERE status = 'active'")
        zones = cur.fetchall()

    snapshots_taken = 0
    for z in zones:
        tok = tokens_by_id.get(z["cf_token_id"])
        if not tok:
            continue
        client = CloudflareClient(tok["token"], user_agent=settings.cf_user_agent)
        try:
            setts = client.get_settings(z["cf_zone_id"])
            dns = client.get_dns_records(z["cf_zone_id"])
            ssl = client.get_ssl_certificate_packs(z["cf_zone_id"])
            fw = client.get_firewall_rules(z["cf_zone_id"])
        except CloudflareError as e:
            log.warning("Snapshot failed for %s: %s", z["name"], e)
            continue

        soonest_expiry = None
        active_packs = 0
        for p in ssl:
            if p.get("status") == "active":
                active_packs += 1
                for c in p.get("certificates", []) or []:
                    exp = c.get("expires_on")
                    if exp and (soonest_expiry is None or exp < soonest_expiry):
                        soonest_expiry = exp

        dns_by_type = dict(Counter(r["type"] for r in dns))
        dns_proxied = sum(1 for r in dns if r.get("proxied"))
        fw_enabled = sum(1 for r in fw if not r.get("paused"))

        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO mmwss.zone_snapshots
                    (zone_id, settings_json, ssl_expiry, ssl_packs_active,
                     fw_rules_total, fw_rules_enabled,
                     dns_count, dns_by_type_json, dns_proxied_count)
                VALUES (%s, %s::jsonb, %s, %s, %s, %s, %s, %s::jsonb, %s)
                RETURNING id
                """,
                (z["id"], json.dumps(setts), soonest_expiry, active_packs,
                 len(fw), fw_enabled, len(dns), json.dumps(dns_by_type), dns_proxied),
            )
            snapshot_id = cur.fetchone()["id"]
            for r in dns:
                cur.execute(
                    """
                    INSERT INTO mmwss.dns_records_snapshot
                        (zone_snapshot_id, type, name, content, proxied, ttl)
                    VALUES (%s, %s, %s, %s, %s, %s)
                    """,
                    (snapshot_id, r["type"], r["name"], r.get("content"),
                     r.get("proxied", False), r.get("ttl")),
                )
            # SSL incident detection
            if soonest_expiry:
                try:
                    exp_dt = datetime.strptime(soonest_expiry[:19], "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc)
                    days = (exp_dt - datetime.now(timezone.utc)).days
                    if days < 30:
                        cur.execute(
                            "SELECT id FROM mmwss.incidents WHERE zone_id = %s AND type = 'ssl_expiring' AND ended_at IS NULL LIMIT 1",
                            (z["id"],),
                        )
                        if not cur.fetchone():
                            severity = "warning" if days >= 7 else "critical"
                            summary = f"{z['name']} SSL expires in {days} days"
                            cur.execute(
                                """
                                INSERT INTO mmwss.incidents (zone_id, type, severity, summary, details_json)
                                VALUES (%s, 'ssl_expiring', %s, %s, %s::jsonb)
                                RETURNING id
                                """,
                                (z["id"], severity, summary,
                                 json.dumps({"expires_on": soonest_expiry, "days_remaining": days})),
                            )
                            ssl_inc_id = cur.fetchone()["id"]
                            conn.commit()
                            alerts.notify_incident_opened(
                                settings, conn,
                                zone_id=z["id"], zone_name=z["name"],
                                incident_id=ssl_inc_id, severity=severity, summary=summary,
                                details={"days_remaining": days, "expires_on": soonest_expiry},
                            )
                except ValueError:
                    pass
        conn.commit()
        snapshots_taken += 1
    return snapshots_taken


# ───────── WordPress synthetic checks ─────────


def run_wp_checks(settings: Settings, conn) -> int:
    """For each active zone, run the WP synthetic-check battery and store the result."""
    with conn.cursor() as cur:
        cur.execute("SELECT id, name FROM mmwss.zones WHERE status = 'active' ORDER BY name")
        zones = cur.fetchall()

    count = 0
    for z in zones:
        try:
            result = wp_checks.run_checks(z["name"])
        except Exception:
            log.exception("wp_checks crashed for %s — skipping", z["name"])
            continue
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO mmwss.wp_checks
                    (zone_id, is_wordpress, wp_version, home_status, home_latency_ms, findings_json)
                VALUES (%s, %s, %s, %s, %s, %s::jsonb)
                """,
                (z["id"], result["is_wordpress"], result["wp_version"],
                 result["home_status"], result["home_latency_ms"],
                 json.dumps(result["findings"])),
            )
        conn.commit()
        count += 1
        crit = sum(1 for f in result["findings"].get("exposures", []) if f.get("severity") == "critical")
        log.info("wp_checks %s: is_wp=%s status=%s crit_exposures=%d", z["name"], result["is_wordpress"], result["home_status"], crit)
    return count
