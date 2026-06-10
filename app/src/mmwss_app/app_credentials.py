"""Read-only view onto the encrypted credentials store (collector owns writes).

The full credentials.py lives in the collector; the FastAPI app only needs
to READ secrets (Slack webhook for ticket notifs, FCM service account JSON
for push). We mirror the same env-override > DB resolution order so dev
overrides keep working.

WHY duplicated: the app and collector are separate Python processes /
Docker images. Cross-importing the collector package would bloat the app
image. Reads only — writes/rotations stay in the collector CLI.
"""
from __future__ import annotations

import logging
import os

from . import db
from .config import get_settings

log = logging.getLogger(__name__)


_ENV_NAME_MAP = {
    "aws_access_key_id":     "MMWSS_AWS_ACCESS_KEY_ID",
    "aws_secret_access_key": "MMWSS_AWS_SECRET_ACCESS_KEY",
    "aws_region":            "MMWSS_AWS_DEFAULT_REGION",
    "slack_webhook":         "SLACK_WEBHOOK_URL",
    "teams_webhook":         "TEAMS_WEBHOOK_URL",
    "wpmudev_api_key":       "WPMUDEV_USER_API_KEY",
    "zap_api_key":           "ZAP_API_KEY",
    "smtp_password":         "SMTP_PASSWORD",
}


def _master_key() -> str:
    key = get_settings().mmwss_master_key
    if not key or len(key) != 64:
        raise RuntimeError("MMWSS_MASTER_KEY missing or wrong length (need 64 hex chars)")
    return key


def get(kind: str, label: str = "primary") -> str | None:
    """Env override > encrypted DB > None. Touches use_count + last_used_at."""
    if label == "primary":
        env_name = _ENV_NAME_MAP.get(kind)
        if env_name and os.environ.get(env_name):
            return os.environ[env_name]

    with db.conn() as c:
        with c.cursor() as cur:
            cur.execute(
                """
                UPDATE mmwss.credentials
                   SET last_used_at = now(),
                       use_count = use_count + 1
                 WHERE kind = %s AND label = %s AND is_active = TRUE
                RETURNING pgp_sym_decrypt(encrypted_value, %s) AS plaintext,
                          is_honeytoken,
                          id
                """,
                (kind, label, _master_key()),
            )
            row = cur.fetchone()
        c.commit()

    if not row:
        return None
    if row["is_honeytoken"]:
        log.critical(
            "HONEYTOKEN USED in app process — credential id=%d kind=%s label=%s. "
            "Investigate immediately.",
            row["id"], kind, label,
        )
    return row["plaintext"]
