"""Scheduled jobs: uptime probes, analytics pull, full snapshots, incident management."""
from __future__ import annotations

import json
import logging
import time
from datetime import datetime, timezone

import requests

from . import db
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
                cur.execute(
                    """
                    INSERT INTO mmwss.incidents (zone_id, type, severity, summary, details_json)
                    VALUES (%s, 'site_down', 'critical', %s, %s::jsonb)
                    """,
                    (zid, f"{z['name']} appears down (2 consecutive failed probes)",
                     json.dumps({"last_status": status_code, "last_error": error, "latency_ms": latency_ms})),
                )
                log.warning("Opened incident: %s down", z["name"])
            elif len(last_two) == 2 and all(last_two) and open_incident:
                cur.execute(
                    "UPDATE mmwss.incidents SET ended_at = now() WHERE id = %s",
                    (open_incident["id"],),
                )
                log.info("Closed incident: %s recovered", z["name"])
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
                            cur.execute(
                                """
                                INSERT INTO mmwss.incidents (zone_id, type, severity, summary, details_json)
                                VALUES (%s, 'ssl_expiring', %s, %s, %s::jsonb)
                                """,
                                (z["id"],
                                 "warning" if days >= 7 else "critical",
                                 f"{z['name']} SSL expires in {days} days",
                                 json.dumps({"expires_on": soonest_expiry, "days_remaining": days})),
                            )
                except ValueError:
                    pass
        conn.commit()
        snapshots_taken += 1
    return snapshots_taken
