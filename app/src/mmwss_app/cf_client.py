"""Tiny Cloudflare API client used by the Fix endpoint to apply changes.

Pulls the CF token from mmwss.cf_tokens (decrypts with mmwss_master_key)
on each call — avoids holding it in memory. Token never logged.
"""
from __future__ import annotations

import logging

import requests

from . import db
from .config import get_settings

log = logging.getLogger(__name__)

_CF_BASE = "https://api.cloudflare.com/client/v4"
_TIMEOUT = 20


class CloudflareApiError(RuntimeError):
    pass


def _active_token() -> str:
    """Return the plaintext token of the first (oldest) cf_tokens row,
    decrypted with the configured master key. Raises if none configured."""
    s = get_settings()
    r = db.fetch_one(
        "SELECT pgp_sym_decrypt(encrypted_token, %s) AS token FROM mmwss.cf_tokens ORDER BY id LIMIT 1",
        (s.mmwss_master_key,),
    )
    if not r or not r["token"]:
        raise CloudflareApiError("No Cloudflare token configured")
    return r["token"]


def patch_zone_setting(cf_zone_id: str, setting_id: str, value) -> dict:
    """PATCH /zones/{cf_zone_id}/settings/{setting_id} with {"value": value}.

    Raises CloudflareApiError on any non-success response. On success,
    returns CF's `result` payload (current setting state after the change).
    """
    token = _active_token()
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "User-Agent": "MMWSS-Fix/0.1",
    }
    url = f"{_CF_BASE}/zones/{cf_zone_id}/settings/{setting_id}"
    try:
        r = requests.patch(url, json={"value": value}, headers=headers, timeout=_TIMEOUT)
    except requests.RequestException as e:
        raise CloudflareApiError(f"network error: {e}")
    try:
        data = r.json()
    except ValueError:
        raise CloudflareApiError(f"non-JSON response (HTTP {r.status_code})")
    if not data.get("success"):
        errs = data.get("errors") or []
        msg = errs[0].get("message") if errs else f"HTTP {r.status_code}"
        raise CloudflareApiError(msg)
    # Touch last_used_at so we know the token is in active service
    db.execute("UPDATE mmwss.cf_tokens SET last_used_at = now() WHERE id = (SELECT MIN(id) FROM mmwss.cf_tokens)", ())
    return data.get("result", {})
