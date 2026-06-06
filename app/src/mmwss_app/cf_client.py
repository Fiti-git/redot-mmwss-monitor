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


def _headers(token: str) -> dict:
    return {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "User-Agent": "MMWSS-Fix/0.1",
    }


def _first_error(data: dict) -> str:
    errs = data.get("errors") or []
    return errs[0].get("message") if errs else "unknown error"


def _touch_token() -> None:
    db.execute(
        "UPDATE mmwss.cf_tokens SET last_used_at = now() WHERE id = (SELECT MIN(id) FROM mmwss.cf_tokens)",
        (),
    )


def patch_zone_setting(cf_zone_id: str, setting_id: str, value) -> dict:
    """PATCH /zones/{cf_zone_id}/settings/{setting_id} with {"value": value}.

    Raises CloudflareApiError on any non-success response. On success,
    returns CF's `result` payload (current setting state after the change).
    """
    token = _active_token()
    url = f"{_CF_BASE}/zones/{cf_zone_id}/settings/{setting_id}"
    try:
        r = requests.patch(url, json={"value": value}, headers=_headers(token), timeout=_TIMEOUT)
    except requests.RequestException as e:
        raise CloudflareApiError(f"network error: {e}")
    try:
        data = r.json()
    except ValueError:
        raise CloudflareApiError(f"non-JSON response (HTTP {r.status_code})")
    if not data.get("success"):
        raise CloudflareApiError(_first_error(data))
    _touch_token()
    return data.get("result", {})


# ───────── Custom firewall rules (Rulesets API) ─────────


_FW_PHASE = "http_request_firewall_custom"


def _get_or_create_custom_ruleset(cf_zone_id: str, token: str) -> tuple[str, list[dict]]:
    """Return (ruleset_id, existing_rules) for the custom-firewall entrypoint.
    If it doesn't exist yet, create an empty one and return its id."""
    headers = _headers(token)
    url = f"{_CF_BASE}/zones/{cf_zone_id}/rulesets/phases/{_FW_PHASE}/entrypoint"
    try:
        r = requests.get(url, headers=headers, timeout=_TIMEOUT)
    except requests.RequestException as e:
        raise CloudflareApiError(f"network error: {e}")
    if r.status_code == 200:
        try:
            data = r.json()
        except ValueError:
            raise CloudflareApiError("non-JSON entrypoint response")
        if data.get("success"):
            return data["result"]["id"], data["result"].get("rules", []) or []
        raise CloudflareApiError(_first_error(data))
    if r.status_code == 404:
        # Phase ruleset not yet created — PUT an empty one to materialize it.
        try:
            r2 = requests.put(url, json={"rules": []}, headers=headers, timeout=_TIMEOUT)
            data2 = r2.json()
        except (requests.RequestException, ValueError) as e:
            raise CloudflareApiError(f"creating entrypoint: {e}")
        if not data2.get("success"):
            raise CloudflareApiError(_first_error(data2))
        return data2["result"]["id"], []
    raise CloudflareApiError(f"HTTP {r.status_code} fetching entrypoint")


_HEADER_PHASE = "http_response_headers_transform"


def _get_or_create_header_ruleset(cf_zone_id: str, token: str) -> tuple[str, list[dict]]:
    """Return (ruleset_id, existing_rules) for the response-headers transform
    phase. Creates an empty entrypoint if it doesn't exist yet."""
    headers = _headers(token)
    url = f"{_CF_BASE}/zones/{cf_zone_id}/rulesets/phases/{_HEADER_PHASE}/entrypoint"
    try:
        r = requests.get(url, headers=headers, timeout=_TIMEOUT)
    except requests.RequestException as e:
        raise CloudflareApiError(f"network error: {e}")
    if r.status_code == 200:
        try:
            data = r.json()
        except ValueError:
            raise CloudflareApiError("non-JSON entrypoint response")
        if data.get("success"):
            return data["result"]["id"], data["result"].get("rules", []) or []
        raise CloudflareApiError(_first_error(data))
    if r.status_code == 404:
        try:
            r2 = requests.put(url, json={"rules": []}, headers=headers, timeout=_TIMEOUT)
            data2 = r2.json()
        except (requests.RequestException, ValueError) as e:
            raise CloudflareApiError(f"creating header entrypoint: {e}")
        if not data2.get("success"):
            raise CloudflareApiError(_first_error(data2))
        return data2["result"]["id"], []
    raise CloudflareApiError(f"HTTP {r.status_code} fetching header entrypoint")


def add_response_header_rule(cf_zone_id: str, header_name: str,
                              header_value: str, description: str) -> dict:
    """Add (or replace, if same header) a Transform Rule that sets a response
    header on every response from this zone. Idempotent: if a rule already
    sets this header, update it instead of creating a duplicate.

    Returns CF's rule payload (or {'updated': True, 'rule_id': ...} on update).
    """
    token = _active_token()
    ruleset_id, existing_rules = _get_or_create_header_ruleset(cf_zone_id, token)

    # Find an existing rule that sets this header
    existing_rule_id = None
    for r in existing_rules:
        params = r.get("action_parameters") or {}
        hdrs = params.get("headers") or {}
        if header_name in hdrs:
            existing_rule_id = r.get("id")
            break

    payload = {
        "expression": "true",         # all responses
        "action": "rewrite",
        "action_parameters": {
            "headers": {
                header_name: {
                    "operation": "set",
                    "value": header_value,
                }
            }
        },
        "description": description[:255],
        "enabled": True,
    }

    if existing_rule_id:
        url = f"{_CF_BASE}/zones/{cf_zone_id}/rulesets/{ruleset_id}/rules/{existing_rule_id}"
        method = requests.patch
    else:
        url = f"{_CF_BASE}/zones/{cf_zone_id}/rulesets/{ruleset_id}/rules"
        method = requests.post

    try:
        r = method(url, json=payload, headers=_headers(token), timeout=_TIMEOUT)
    except requests.RequestException as e:
        raise CloudflareApiError(f"network error: {e}")
    try:
        data = r.json()
    except ValueError:
        raise CloudflareApiError(f"non-JSON response (HTTP {r.status_code})")
    if not data.get("success"):
        raise CloudflareApiError(_first_error(data))
    _touch_token()
    out = data.get("result", {})
    if existing_rule_id:
        out["updated"] = True
        out["rule_id"] = existing_rule_id
    return out


def add_block_path_rule(cf_zone_id: str, path: str, description: str) -> dict:
    """Block all requests whose URI path exactly matches `path` by appending
    a rule to the zone's custom firewall ruleset. Idempotent: if an equivalent
    rule already exists, returns that rule unchanged."""
    token = _active_token()
    ruleset_id, existing_rules = _get_or_create_custom_ruleset(cf_zone_id, token)

    expression = f'(http.request.uri.path eq "{path}")'

    # Idempotency: don't add the same rule twice
    for r in existing_rules:
        if (r.get("expression") == expression
                and r.get("action") == "block"
                and not r.get("paused", False)):
            return {"already_exists": True, "rule_id": r.get("id"), "expression": expression}

    payload = {
        "expression": expression,
        "action": "block",
        "description": description[:255],
        "enabled": True,
    }
    url = f"{_CF_BASE}/zones/{cf_zone_id}/rulesets/{ruleset_id}/rules"
    try:
        r = requests.post(url, json=payload, headers=_headers(token), timeout=_TIMEOUT)
    except requests.RequestException as e:
        raise CloudflareApiError(f"network error: {e}")
    try:
        data = r.json()
    except ValueError:
        raise CloudflareApiError(f"non-JSON response (HTTP {r.status_code})")
    if not data.get("success"):
        raise CloudflareApiError(_first_error(data))
    _touch_token()
    return data.get("result", {})
