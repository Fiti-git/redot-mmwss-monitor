"""Thin Cloudflare API client. Uses bearer auth (not the legacy 'no Bearer' WPMUDEV quirk)."""
from __future__ import annotations

import logging
from typing import Any

import requests
from tenacity import retry, retry_if_exception_type, stop_after_attempt, wait_exponential

log = logging.getLogger(__name__)

BASE = "https://api.cloudflare.com/client/v4"
GRAPHQL = "https://api.cloudflare.com/client/v4/graphql"


class CloudflareError(RuntimeError):
    pass


class CloudflareClient:
    def __init__(self, token: str, user_agent: str = "mmwss-collector/0.1"):
        self._headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "User-Agent": user_agent,
        }

    @retry(
        retry=retry_if_exception_type((requests.ConnectionError, requests.Timeout)),
        stop=stop_after_attempt(3),
        wait=wait_exponential(min=1, max=10),
        reraise=True,
    )
    def _get(self, path: str, params: dict | None = None) -> dict:
        r = requests.get(f"{BASE}{path}", headers=self._headers, params=params, timeout=30)
        try:
            data = r.json()
        except ValueError as e:
            raise CloudflareError(f"{path}: non-JSON response ({r.status_code})") from e
        if not data.get("success"):
            errs = data.get("errors") or []
            msg = errs[0].get("message") if errs else f"HTTP {r.status_code}"
            raise CloudflareError(f"{path}: {msg}")
        return data

    def list_zones(self) -> list[dict[str, Any]]:
        """Return all zones the token can see (handles pagination)."""
        results: list[dict] = []
        page = 1
        while True:
            data = self._get("/zones", params={"page": page, "per_page": 50})
            results.extend(data.get("result", []))
            info = data.get("result_info", {})
            if page >= (info.get("total_pages") or 1):
                break
            page += 1
        return results

    def verify_token(self) -> dict:
        """Confirm the token is valid and check scope. Raises CloudflareError if not."""
        return self._get("/user/tokens/verify").get("result", {})
