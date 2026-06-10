"""FCM push sender for the FastAPI app process.

Mirrors collector/fcm.py but uses app-side db helpers. Used for:
  - test pushes from /api/v1/push/test
  - ticket-creation push fan-out
  - any UI-initiated push

Background sends (scanner findings, scheduled honeytoken alerts, monthly
report-ready) stay in the collector — those run on APScheduler timers.
"""
from __future__ import annotations

import json
import logging
import threading
from typing import Any

from . import app_credentials, db

log = logging.getLogger(__name__)

_firebase_app = None
_init_lock = threading.Lock()


def _ensure_initialized():
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

        sa_json = app_credentials.get("fcm_service_account", "primary")
        if not sa_json:
            raise RuntimeError(
                "FCM service account not in encrypted credentials store. "
                "Run on collector: collector credentials set fcm_service_account primary '<json>'"
            )
        sa_dict = json.loads(sa_json)
        cred = fb_credentials.Certificate(sa_dict)
        _firebase_app = firebase_admin.initialize_app(cred, name="mmwss-fcm-app")
        log.info("FCM initialized in app process for project %s", sa_dict.get("project_id"))
    return _firebase_app


_KIND_TO_PREF_COL = {
    "p1_ticket":         "notify_p1",
    "scanner_critical":  "notify_scanner_critical",
    "honeytoken":        "notify_honeytoken",
    "report_ready":      "notify_report_ready",
    "sla_warning":       "notify_sla_warning",
}


def _active_tokens_for_user(user_id: int, kind: str) -> list[dict]:
    pref_col = _KIND_TO_PREF_COL.get(kind)
    pref_filter = f"{pref_col} = TRUE" if pref_col else "TRUE"
    return db.fetch_all(
        f"""
        SELECT id, fcm_token, device_label
          FROM mmwss.push_subscriptions
         WHERE user_id = %s AND is_active = TRUE AND {pref_filter}
        """,
        (user_id,),
    )


def _active_admin_user_ids() -> list[int]:
    rows = db.fetch_all(
        "SELECT id FROM mmwss.users WHERE role = 'admin' AND is_active = TRUE"
    )
    return [r["id"] for r in rows]


def send_to_user(
    user_id: int,
    *,
    kind: str,
    title: str,
    body: str,
    data: dict[str, Any] | None = None,
    deep_link: str | None = None,
) -> int:
    tokens = _active_tokens_for_user(user_id, kind)
    if not tokens:
        log.debug("No active push tokens for user %d kind=%s", user_id, kind)
        return 0

    _ensure_initialized()
    from firebase_admin import messaging

    payload = dict(data or {})
    if deep_link:
        payload["deep_link"] = deep_link
    payload["kind"] = kind
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
            _disable_subscription(tok["id"], err)
        except Exception as e:
            err = str(e)[:300]
        finally:
            _record_delivery(
                subscription_id=tok["id"], user_id=user_id, kind=kind,
                title=title, body=body, data=payload,
                delivered=delivered, error=err, fcm_message_id=msg_id,
            )
            sent += 1
    return sent


def send_to_admins(
    *,
    kind: str,
    title: str,
    body: str,
    data: dict[str, Any] | None = None,
    deep_link: str | None = None,
) -> int:
    total = 0
    for uid in _active_admin_user_ids():
        total += send_to_user(uid, kind=kind, title=title, body=body,
                              data=data, deep_link=deep_link)
    return total


def send_test(user_id: int) -> int:
    return send_to_user(
        user_id,
        kind="test",
        title="Redot Sentinel test",
        body="If you see this, push notifications are working.",
        data={"test": "1"},
        deep_link="/dashboard",
    )


def _record_delivery(*, subscription_id, user_id, kind, title, body,
                     data, delivered, error, fcm_message_id) -> None:
    db.execute(
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


def _disable_subscription(sub_id: int, reason: str) -> None:
    log.info("Disabling push subscription %d: %s", sub_id, reason)
    db.execute(
        """
        UPDATE mmwss.push_subscriptions
           SET is_active = FALSE, deactivated_at = now(), deactivated_reason = %s
         WHERE id = %s
        """,
        (reason[:200], sub_id),
    )
