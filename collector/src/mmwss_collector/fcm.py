"""FCM push notification sender.

Uses the Firebase Admin SDK with the service account JSON stored encrypted
in mmwss.credentials (kind='fcm_service_account', label='primary').

Public API:
    send_to_user(conn, user_id, *, kind, title, body, data=None, deep_link=None)
        Sends a push to every active subscription for the given user that
        has notify_<kind> enabled. Records each attempt to mmwss.push_deliveries.

    send_to_admins(conn, *, kind, title, body, data=None, deep_link=None)
        Convenience for broadcasting to all admin users.

    send_test(conn, user_id) — for the /push/test endpoint.

Initialization is lazy and cached — the Firebase app is initialized once
per process from the credentials store.
"""
from __future__ import annotations

import json
import logging
import threading
from typing import Any

from . import credentials

log = logging.getLogger(__name__)

_firebase_app = None
_init_lock = threading.Lock()


def _ensure_initialized(conn, settings):
    """Lazy-init the Firebase Admin SDK from the credentials store."""
    global _firebase_app
    if _firebase_app is not None:
        return _firebase_app
    with _init_lock:
        if _firebase_app is not None:
            return _firebase_app
        try:
            import firebase_admin
            from firebase_admin import credentials as fb_credentials
        except ImportError:
            log.error("firebase-admin not installed; add to requirements")
            raise

        sa_json = credentials.get(conn, "fcm_service_account", settings=settings)
        if not sa_json:
            raise RuntimeError(
                "FCM service account not in encrypted credentials store. "
                "Run: collector credentials set fcm_service_account primary "
                "'<service account JSON>'"
            )
        sa_dict = json.loads(sa_json)
        cred = fb_credentials.Certificate(sa_dict)
        _firebase_app = firebase_admin.initialize_app(cred, name="mmwss-fcm")
        log.info("FCM initialized for project %s", sa_dict.get("project_id"))
    return _firebase_app


# ───── Subscription discovery ─────


_KIND_TO_PREF_COL = {
    "p1_ticket":         "notify_p1",
    "scanner_critical":  "notify_scanner_critical",
    "honeytoken":        "notify_honeytoken",
    "report_ready":      "notify_report_ready",
    "sla_warning":       "notify_sla_warning",
}


def _active_tokens_for_user(conn, user_id: int, kind: str) -> list[dict]:
    pref_col = _KIND_TO_PREF_COL.get(kind)
    if not pref_col:
        # Unknown kind — send anyway (defensive default)
        pref_filter = "TRUE"
    else:
        pref_filter = f"{pref_col} = TRUE"
    with conn.cursor() as cur:
        cur.execute(
            f"""
            SELECT id, fcm_token, device_label
              FROM mmwss.push_subscriptions
             WHERE user_id = %s
               AND is_active = TRUE
               AND {pref_filter}
            """,
            (user_id,),
        )
        return cur.fetchall()


def _active_admin_user_ids(conn) -> list[int]:
    with conn.cursor() as cur:
        cur.execute(
            "SELECT id FROM mmwss.users WHERE role = 'admin' AND is_active = TRUE"
        )
        return [r["id"] for r in cur.fetchall()]


# ───── Public send functions ─────


def send_to_user(
    conn,
    settings,
    user_id: int,
    *,
    kind: str,
    title: str,
    body: str,
    data: dict[str, Any] | None = None,
    deep_link: str | None = None,
) -> int:
    """Send a push to all the user's active subscriptions for this kind.
    Returns count of attempts (NOT successful deliveries — see push_deliveries
    for delivery audit)."""
    tokens = _active_tokens_for_user(conn, user_id, kind)
    if not tokens:
        log.debug("No active push tokens for user %d (kind=%s)", user_id, kind)
        return 0

    _ensure_initialized(conn, settings)
    from firebase_admin import messaging

    payload = dict(data or {})
    if deep_link:
        payload["deep_link"] = deep_link
    payload["kind"] = kind
    # FCM requires all data values to be strings
    payload_str = {k: str(v) for k, v in payload.items()}

    sent = 0
    for tok in tokens:
        msg = messaging.Message(
            token=tok["fcm_token"],
            notification=messaging.Notification(title=title, body=body),
            data=payload_str,
            android=messaging.AndroidConfig(
                priority="high",
                notification=messaging.AndroidNotification(
                    channel_id="redot_sentinel_alerts",
                    color="#E11B22",
                    sound="default",
                ),
            ),
        )
        delivered = False
        err = None
        msg_id = None
        try:
            msg_id = messaging.send(msg, app=_firebase_app)
            delivered = True
        except messaging.UnregisteredError:
            err = "token unregistered (app uninstalled / token rotated)"
            _disable_subscription(conn, tok["id"], err)
        except Exception as e:
            err = str(e)[:300]
        finally:
            _record_delivery(
                conn,
                subscription_id=tok["id"],
                user_id=user_id,
                kind=kind,
                title=title,
                body=body,
                data=payload,
                delivered=delivered,
                error=err,
                fcm_message_id=msg_id,
            )
            sent += 1
    return sent


def send_to_admins(
    conn,
    settings,
    *,
    kind: str,
    title: str,
    body: str,
    data: dict[str, Any] | None = None,
    deep_link: str | None = None,
) -> int:
    user_ids = _active_admin_user_ids(conn)
    total = 0
    for uid in user_ids:
        total += send_to_user(
            conn, settings, uid,
            kind=kind, title=title, body=body, data=data, deep_link=deep_link,
        )
    return total


def send_test(conn, settings, user_id: int) -> int:
    return send_to_user(
        conn, settings, user_id,
        kind="test",
        title="Redot Sentinel test",
        body="If you see this, push notifications are working ✓",
        data={"test": "1"},
        deep_link="/dashboard",
    )


# ───── Helpers ─────


def _record_delivery(conn, *, subscription_id, user_id, kind, title, body,
                     data, delivered, error, fcm_message_id) -> None:
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO mmwss.push_deliveries
                (subscription_id, user_id, kind, title, body,
                 data_json, delivered, error_message, fcm_message_id)
            VALUES (%s, %s, %s, %s, %s, %s::jsonb, %s, %s, %s)
            """,
            (subscription_id, user_id, kind, title, body,
             json.dumps(data) if data else None,
             delivered, error, fcm_message_id),
        )
    conn.commit()


def _disable_subscription(conn, sub_id: int, reason: str) -> None:
    log.info("Disabling push subscription %d: %s", sub_id, reason)
    with conn.cursor() as cur:
        cur.execute(
            """
            UPDATE mmwss.push_subscriptions
               SET is_active = FALSE, deactivated_at = now(),
                   deactivated_reason = %s
             WHERE id = %s
            """,
            (reason[:200], sub_id),
        )
    conn.commit()
