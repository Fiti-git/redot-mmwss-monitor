"""Alert dispatch — Slack incoming-webhook with 6h dedupe per (channel, dedupe_key).

Easy to extend: add notify_*_email / notify_*_telegram functions, set their
channel string differently in mmwss.alerts. Dedupe is per-channel so adding
a new transport doesn't affect existing ones.
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timedelta, timezone

import requests
from tenacity import retry, retry_if_exception_type, stop_after_attempt, wait_exponential

log = logging.getLogger(__name__)

DEDUPE_WINDOW = timedelta(hours=6)

# Redot brand + standard SaaS severity palette
SEVERITY_COLOR = {
    "critical": "#E11E27",  # brand red
    "warning":  "#F59E0B",
    "info":     "#3B82F6",
    "ok":       "#10B981",
}

SEVERITY_EMOJI = {
    "critical": ":rotating_light:",
    "warning":  ":warning:",
    "info":     ":information_source:",
    "ok":       ":white_check_mark:",
}


@retry(
    retry=retry_if_exception_type((requests.ConnectionError, requests.Timeout)),
    stop=stop_after_attempt(3),
    wait=wait_exponential(min=1, max=8),
    reraise=True,
)
def _post_slack(webhook_url: str, payload: dict) -> None:
    r = requests.post(webhook_url, json=payload, timeout=15)
    if r.status_code >= 300:
        raise RuntimeError(f"Slack returned {r.status_code}: {r.text[:200]}")


def _recently_sent(conn, *, channel: str, dedupe_key: str) -> bool:
    cutoff = datetime.now(timezone.utc) - DEDUPE_WINDOW
    with conn.cursor() as cur:
        cur.execute(
            "SELECT 1 FROM mmwss.alerts WHERE channel = %s AND dedupe_key = %s AND sent_at >= %s LIMIT 1",
            (channel, dedupe_key, cutoff),
        )
        return cur.fetchone() is not None


def _record(conn, *, zone_id, incident_id, channel, event_type, dedupe_key, payload):
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO mmwss.alerts
                (zone_id, incident_id, channel, event_type, dedupe_key, payload_json)
            VALUES (%s, %s, %s, %s, %s, %s::jsonb)
            """,
            (zone_id, incident_id, channel, event_type, dedupe_key, json.dumps(payload)),
        )
    conn.commit()


def _build_slack_payload(*, severity: str, zone_name: str, summary: str,
                         dashboard_url: str, footer: str) -> dict:
    emoji = SEVERITY_EMOJI.get(severity, ":bell:")
    color = SEVERITY_COLOR.get(severity, "#64748B")
    header_text = f"{emoji}  {zone_name}"
    fallback = f"[{severity.upper()}] {zone_name} — {summary}"
    return {
        "text": fallback,
        "attachments": [
            {
                "color": color,
                "blocks": [
                    {"type": "header", "text": {"type": "plain_text", "text": header_text, "emoji": True}},
                    {"type": "section", "text": {"type": "mrkdwn",
                        "text": f"*{severity.upper()}*\n{summary}"}},
                    {"type": "context", "elements": [
                        {"type": "mrkdwn", "text": footer}
                    ]},
                    {"type": "actions", "elements": [
                        {"type": "button", "url": dashboard_url,
                         "text": {"type": "plain_text", "text": "View in MMWSS", "emoji": True}}
                    ]},
                ],
            }
        ],
    }


# ───────── public functions ─────────


def notify_incident_opened(settings, conn, *, zone_id: int, zone_name: str,
                           incident_id: int, severity: str, summary: str,
                           details: dict | None = None) -> None:
    if not settings.slack_webhook_url:
        return
    dedupe_key = f"incident_opened:{incident_id}"
    if _recently_sent(conn, channel="slack", dedupe_key=dedupe_key):
        return
    dashboard_url = f"{settings.mmwss_public_url}/mmwss/zones/{zone_id}"
    payload = _build_slack_payload(
        severity=severity, zone_name=zone_name, summary=summary,
        dashboard_url=dashboard_url,
        footer=f"_Incident #{incident_id} · opened {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}_",
    )
    try:
        _post_slack(settings.slack_webhook_url, payload)
        _record(conn, zone_id=zone_id, incident_id=incident_id, channel="slack",
                event_type="opened", dedupe_key=dedupe_key, payload=payload)
        log.info("Slack alert sent: incident #%d opened (%s)", incident_id, zone_name)
    except Exception:
        log.exception("Slack alert failed: incident #%d", incident_id)


def notify_incident_resolved(settings, conn, *, zone_id: int, zone_name: str,
                             incident_id: int, summary: str) -> None:
    if not settings.slack_webhook_url:
        return
    dedupe_key = f"incident_resolved:{incident_id}"
    if _recently_sent(conn, channel="slack", dedupe_key=dedupe_key):
        return
    dashboard_url = f"{settings.mmwss_public_url}/mmwss/zones/{zone_id}"
    payload = _build_slack_payload(
        severity="ok", zone_name=f"{zone_name} — RESOLVED", summary=summary,
        dashboard_url=dashboard_url,
        footer=f"_Incident #{incident_id} · resolved {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}_",
    )
    try:
        _post_slack(settings.slack_webhook_url, payload)
        _record(conn, zone_id=zone_id, incident_id=incident_id, channel="slack",
                event_type="resolved", dedupe_key=dedupe_key, payload=payload)
        log.info("Slack resolve sent: incident #%d (%s)", incident_id, zone_name)
    except Exception:
        log.exception("Slack resolve failed: incident #%d", incident_id)


def notify_test(settings, conn) -> bool:
    """Manual test fire — invoked from `python -m mmwss_collector test_alert`."""
    if not settings.slack_webhook_url:
        log.warning("SLACK_WEBHOOK_URL not set — nothing to test")
        return False
    payload = _build_slack_payload(
        severity="info", zone_name="MMWSS",
        summary="This is a test alert from the collector. If you see this, Slack alerts are wired up correctly.",
        dashboard_url=f"{settings.mmwss_public_url}/mmwss/dashboard",
        footer=f"_Test fired {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}_",
    )
    try:
        _post_slack(settings.slack_webhook_url, payload)
        _record(conn, zone_id=None, incident_id=None, channel="slack",
                event_type="test", dedupe_key=f"test:{datetime.now(timezone.utc).isoformat()}",
                payload=payload)
        log.info("Test alert sent to Slack")
        return True
    except Exception:
        log.exception("Test alert failed")
        return False
