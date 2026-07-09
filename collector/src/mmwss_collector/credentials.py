"""Encrypted credential store — pgcrypto-backed, master-key-protected.

Every secret stored here is encrypted at rest with the platform's master key.
Even if the DB is dumped, secrets are unreadable without the master key
(which itself is delivered by SOPS-decrypted env at container startup).

Pattern: env > DB. Each get() checks env first (for explicit override / dev
convenience), then falls back to the encrypted DB row. Once an env value is
imported into DB, the env entry can be removed from SOPS without breaking.

KINDS — agreed taxonomy across the codebase:
    aws_access_key_id
    aws_secret_access_key
    aws_region
    cf_api_token            (legacy, lives in mmwss.cf_tokens — separate)
    slack_webhook
    teams_webhook
    wpmudev_api_key
    wp_app_password         (per-site; label = zone domain)
    zap_api_key
    smtp_password
"""
from __future__ import annotations

import json
import logging
import os
from typing import Any

log = logging.getLogger(__name__)


def _master_key(settings) -> str:
    key = settings.mmwss_master_key
    if not key or len(key) != 64:
        raise RuntimeError("MMWSS_MASTER_KEY missing or wrong length (need 64 hex chars)")
    return key


# ───────── Public API ─────────


def get(conn, kind: str, label: str = "primary", *, settings) -> str | None:
    """Return the plaintext secret. Env override > encrypted DB > None.

    Side effect: increments use_count + last_used_at on DB read.

    Honeytokens are NEVER returned in plaintext — the tripwire fires and
    the caller gets None. This prevents an attacker who lands on the host
    from probing which credentials are fake by observing which ones work.
    """
    env_name = _env_name_for(kind, label)
    if env_name and os.environ.get(env_name):
        return os.environ[env_name]

    with conn.cursor() as cur:
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
            (kind, label, _master_key(settings)),
        )
        row = cur.fetchone()
    conn.commit()

    if not row:
        return None

    if row["is_honeytoken"]:
        log.critical(
            "HONEYTOKEN USED — credential id=%d kind=%s label=%s. "
            "This indicates a SECURITY BREACH. Investigate immediately.",
            row["id"], kind, label,
        )
        try:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO mmwss.audit_log (action, target_type, target_id, details_json)
                    VALUES ('honeytoken_read', 'credential', %s, %s::jsonb)
                    """,
                    (str(row["id"]),
                     json.dumps({"kind": kind, "label": label,
                                 "caller": _caller_hint()})),
                )
            conn.commit()
        except Exception:
            log.exception("Failed to write honeytoken_read audit entry")
        return None

    return row["plaintext"]


def _caller_hint() -> str:
    """Best-effort caller identification for audit trail."""
    import traceback
    frames = traceback.extract_stack()[:-2]
    for frame in reversed(frames):
        if "credentials.py" not in frame.filename:
            return f"{frame.filename}:{frame.lineno} in {frame.name}"
    return "unknown"


def set(conn, kind: str, label: str, value: str, *, settings,
        metadata: dict | None = None, is_honeytoken: bool = False) -> int:
    """Insert or replace a credential. Returns the row id.

    Replacing creates a NEW row (history retained); the previous one is
    marked is_active=FALSE and `rotated_from_id` points back to it.
    """
    last_4 = (value or "")[-4:] if value else None

    with conn.cursor() as cur:
        # Look up the previous active row (if any)
        cur.execute(
            "SELECT id FROM mmwss.credentials WHERE kind = %s AND label = %s AND is_active = TRUE",
            (kind, label),
        )
        prev = cur.fetchone()
        prev_id = prev["id"] if prev else None

        if prev_id is not None:
            cur.execute(
                "UPDATE mmwss.credentials SET is_active = FALSE WHERE id = %s",
                (prev_id,),
            )

        cur.execute(
            """
            INSERT INTO mmwss.credentials
                (kind, label, encrypted_value, last_4,
                 metadata_json, is_honeytoken, rotated_from_id)
            VALUES (%s, %s,
                    pgp_sym_encrypt(%s, %s),
                    %s, %s::jsonb, %s, %s)
            RETURNING id
            """,
            (kind, label, value, _master_key(settings),
             last_4, json.dumps(metadata) if metadata else None,
             is_honeytoken, prev_id),
        )
        new_id = cur.fetchone()["id"]
    conn.commit()
    log.info("Credential stored: kind=%s label=%s last4=%s id=%d",
             kind, label, last_4, new_id)
    return new_id


def deactivate(conn, kind: str, label: str = "primary") -> None:
    with conn.cursor() as cur:
        cur.execute(
            "UPDATE mmwss.credentials SET is_active = FALSE WHERE kind = %s AND label = %s",
            (kind, label),
        )
    conn.commit()


def list_all(conn) -> list[dict]:
    """For UI display — never returns plaintext."""
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT id, kind, label, last_4, metadata_json,
                   is_active, is_honeytoken,
                   created_at, last_used_at, use_count,
                   rotated_from_id
              FROM mmwss.credentials
             ORDER BY kind, label, id DESC
            """
        )
        return cur.fetchall()


def honeytoken_alerts(conn) -> list[dict]:
    """Return any honeytoken that has been used (i.e., a breach signal)."""
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT id, kind, label, last_used_at, use_count
              FROM mmwss.credentials
             WHERE is_honeytoken = TRUE AND last_used_at IS NOT NULL
             ORDER BY last_used_at DESC
            """
        )
        return cur.fetchall()


# ───────── Env-name convention ─────────
# We keep env-var overrides for development convenience (e.g., setting
# MMWSS_AWS_ACCESS_KEY_ID at the shell beats fiddling with the DB).
# The convention maps kind → env var name; label is ignored for env lookup
# (env can only hold one of each — DB is where multiples live).

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


def _env_name_for(kind: str, label: str) -> str | None:
    # Only "primary" labelled creds have an env override; everything else
    # (per-site WP App Passwords, multiple AWS profiles) is DB-only.
    if label != "primary":
        return None
    return _ENV_NAME_MAP.get(kind)


# ───────── Bootstrap: import env values into encrypted DB ─────────


_BOOTSTRAP_KINDS = [
    "aws_access_key_id",
    "aws_secret_access_key",
    "aws_region",
    "slack_webhook",
    "wpmudev_api_key",
    "zap_api_key",
]


def import_from_env(conn, settings) -> int:
    """One-shot migration: for each known kind, if the env var is set AND
    the DB doesn't already have an active row, store it.

    Idempotent — running twice does nothing on the second run.
    Returns the number of new credentials imported.
    """
    imported = 0
    for kind in _BOOTSTRAP_KINDS:
        env_name = _ENV_NAME_MAP.get(kind)
        if not env_name:
            continue
        value = os.environ.get(env_name)
        if not value:
            log.info("import_from_env: %s not set in env, skipping", env_name)
            continue

        # Skip if DB already has an active row
        with conn.cursor() as cur:
            cur.execute(
                "SELECT id FROM mmwss.credentials WHERE kind = %s AND label = 'primary' AND is_active = TRUE",
                (kind,),
            )
            if cur.fetchone():
                log.info("import_from_env: %s already in DB, skipping", kind)
                continue

        set(conn, kind, "primary", value, settings=settings)
        imported += 1
        log.info("import_from_env: imported %s (%s)", kind, env_name)

    log.info("import_from_env: %d new credentials encrypted into DB", imported)
    return imported
