"""Honeytoken tripwires — earliest-possible breach detection.

We seed FAKE credentials into mmwss.credentials with is_honeytoken=TRUE. These
fake values look indistinguishable from real ones (AKIA-prefixed AWS keys,
hooks.slack.com URLs, CF-style tokens, etc.) — but no code path ever requests
them by their kind/label. If they're EVER used, that's proof someone copied
them out of the encrypted DB and tried them.

Why this matters:
- Average breach detection time across industry is ~200 days
- Honeytokens cut this to "first attempted use" — minutes, not months
- Zero false positives by definition (legit code never touches them)

Lifecycle:
1. `seed()` inserts the standard set of honeytokens (idempotent)
2. `check()` runs every 15 minutes via APScheduler
3. If any honeytoken has last_used_at != NULL → CRITICAL alarm:
     - Slack page (red, deduped 1h so we don't spam)
     - Logged at CRITICAL level
     - Marked in mmwss.alerts for audit
4. Operator investigates: where was DB accessed from? Who has the master key?
"""
from __future__ import annotations

import logging
import secrets

from . import alerts, credentials

log = logging.getLogger(__name__)


# Standard honeytoken seeds.
# Each value is generated fresh per seed call so two installs don't share them.
# The format mimics real credentials so an attacker can't tell them apart.
def _generate_seeds() -> list[tuple[str, str, str, dict | None]]:
    """Return (kind, label, fake_value, metadata) tuples to seed."""
    # AWS access key — format: AKIA + 16 chars (real ones are AKIA + 16 uppercase alphanum)
    fake_aws_id = "AKIA" + "".join(secrets.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567") for _ in range(16))
    fake_aws_secret = secrets.token_urlsafe(30)[:40]

    # CF API token — format: ~40 base64-ish chars
    fake_cf_token = secrets.token_urlsafe(30)

    # Slack webhook — looks like real one
    fake_slack = (
        "https://hooks.slack.com/services/T"
        + "".join(secrets.choice("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ") for _ in range(10))
        + "/B"
        + "".join(secrets.choice("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ") for _ in range(10))
        + "/"
        + secrets.token_urlsafe(18)
    )

    # WPMU DEV API key — format: 40 hex chars
    fake_wpmu = secrets.token_hex(20)

    # WP App Password — format: 24 chars in groups of 4
    fake_wp_app = " ".join(secrets.token_hex(2) for _ in range(6))

    return [
        ("aws_access_key_id",   "honeytoken_legacy",   fake_aws_id,
         {"hint": "If this key is ever seen in AWS CloudTrail, we have a breach."}),
        ("aws_secret_access_key", "honeytoken_legacy", fake_aws_secret,
         {"pair_with": "honeytoken_legacy aws_access_key_id"}),
        ("cf_api_token",         "honeytoken_backup",  fake_cf_token,
         {"hint": "If this CF token is ever used, we have a DB exfiltration."}),
        ("slack_webhook",        "honeytoken_old",     fake_slack,
         {"hint": "Fake Slack webhook — posting to it would just 404, but the attempt is the signal."}),
        ("wpmudev_api_key",      "honeytoken_archive", fake_wpmu,
         {"hint": "Fake WPMU DEV key. Used = breach."}),
        ("wp_app_password",      "honeytoken_mosques", fake_wp_app,
         {"hint": "Fake WordPress App Password. Used = WP-credential exfiltration."}),
    ]


def seed(conn, settings, *, force: bool = False) -> int:
    """Insert honeytokens if not present. Idempotent unless force=True.

    Returns count of new honeytokens seeded.
    """
    seeded = 0
    for kind, label, value, metadata in _generate_seeds():
        # Skip if already exists (unless force)
        with conn.cursor() as cur:
            cur.execute(
                "SELECT id FROM mmwss.credentials WHERE kind = %s AND label = %s AND is_active = TRUE",
                (kind, label),
            )
            existing = cur.fetchone()
        if existing and not force:
            log.info("seed: %s/%s already exists, skipping", kind, label)
            continue

        credentials.set(
            conn, kind, label, value,
            settings=settings,
            metadata=metadata,
            is_honeytoken=True,
        )
        seeded += 1
        log.info("seed: planted honeytoken %s/%s", kind, label)

    log.info("Seeded %d honeytokens (%d total tripwires now active)", seeded, _count(conn))
    return seeded


def _count(conn) -> int:
    with conn.cursor() as cur:
        cur.execute(
            "SELECT COUNT(*)::int AS n FROM mmwss.credentials WHERE is_honeytoken = TRUE AND is_active = TRUE"
        )
        return cur.fetchone()["n"]


def check(settings, conn) -> int:
    """APScheduler-callable: check for any honeytoken hits, fire alarm if any.

    Returns count of triggered honeytokens.
    """
    hits = credentials.honeytoken_alerts(conn)
    if not hits:
        return 0

    for h in hits:
        log.critical(
            "🚨 HONEYTOKEN BREACH SIGNAL — id=%d kind=%s label=%s "
            "use_count=%d last_used_at=%s. SOMEONE OUTSIDE OUR CODE HAS USED A FAKE CREDENTIAL.",
            h["id"], h["kind"], h["label"], h["use_count"], h["last_used_at"],
        )

    # Slack alarm — one combined message
    try:
        _fire_alarm(settings, conn, hits)
    except Exception:
        log.exception("Failed to fire Slack alarm for honeytoken — STILL A BREACH SIGNAL")

    return len(hits)


def _fire_alarm(settings, conn, hits: list[dict]) -> None:
    """Send a single Slack alert summarising all tripped honeytokens.
    Dedupe key includes hit IDs so the same set of trips won't re-alert
    every 15 min — but a NEW trip will."""
    # Slack webhook moved to encrypted DB in Day 2; fall back to env for dev.
    webhook = (
        credentials.get(conn, "slack_webhook", settings=settings)
        or getattr(settings, "slack_webhook_url", None)
    )
    if not webhook:
        log.warning("No Slack webhook configured — honeytoken alarm logged only")
        return

    ids_key = ",".join(str(h["id"]) for h in hits)
    summary_lines = [
        f"*{len(hits)} honeytoken{'s' if len(hits) > 1 else ''} tripped.* "
        f"This means someone has access to credentials outside our normal code path.",
        "",
    ]
    for h in hits:
        summary_lines.append(
            f"• `{h['kind']}/{h['label']}` — used {h['use_count']}× · last at {h['last_used_at']}"
        )
    summary_lines.extend([
        "",
        "Investigate immediately:",
        "1. Was the encrypted DB exfiltrated?",
        "2. Was the master key / age key compromised?",
        "3. Check audit log: `mmwss.audit_log` for unusual activity",
        "4. Rotate ALL real credentials now",
    ])
    summary = "\n".join(summary_lines)

    dedupe_key = f"honeytoken_breach:{ids_key}"
    # Use existing alert dedupe to avoid spam — but breach signal is so severe
    # we want to know if it persists, so use a short 1h window not 6h.
    if alerts._recently_sent(conn, channel="slack", dedupe_key=dedupe_key):
        return
    dashboard_url = f"{settings.mmwss_public_url}/mmwss/dashboard"
    payload = alerts._build_slack_payload(
        severity="critical",
        zone_name="🚨 HONEYTOKEN BREACH",
        summary=summary,
        dashboard_url=dashboard_url,
        footer="_HONEYTOKEN tripwire — investigate before rotating._",
    )
    try:
        alerts._post_slack(webhook, payload)
        alerts._record(
            conn, zone_id=None, incident_id=None, channel="slack",
            event_type="honeytoken_breach", dedupe_key=dedupe_key, payload=payload,
        )
        log.critical("Slack honeytoken alarm dispatched")
    except Exception:
        log.exception("Slack honeytoken alarm POST failed")
