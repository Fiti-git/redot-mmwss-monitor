"""Cloudflare API client — REST + GraphQL."""
from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any

import requests
from tenacity import retry, retry_if_exception_type, stop_after_attempt, wait_exponential

log = logging.getLogger(__name__)

BASE = "https://api.cloudflare.com/client/v4"
GRAPHQL = "https://api.cloudflare.com/client/v4/graphql"

GRAPHQL_HOURLY = """
query ($zoneTag: String!, $from: Time!, $to: Time!) {
  viewer {
    zones(filter: {zoneTag: $zoneTag}) {
      httpRequests1hGroups(
        limit: 168,
        filter: {datetime_geq: $from, datetime_leq: $to},
        orderBy: [datetime_ASC]
      ) {
        dimensions { datetime }
        sum {
          requests
          cachedRequests
          bytes
          cachedBytes
          threats
        }
      }
    }
  }
}
"""


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

    @retry(
        retry=retry_if_exception_type((requests.ConnectionError, requests.Timeout)),
        stop=stop_after_attempt(3),
        wait=wait_exponential(min=1, max=10),
        reraise=True,
    )
    def _graphql(self, query: str, variables: dict) -> dict:
        r = requests.post(GRAPHQL, headers=self._headers, json={"query": query, "variables": variables}, timeout=30)
        try:
            data = r.json()
        except ValueError as e:
            raise CloudflareError(f"graphql: non-JSON response ({r.status_code})") from e
        if data.get("errors"):
            raise CloudflareError(f"graphql: {data['errors'][0].get('message', '?')}")
        return data

    def list_zones(self) -> list[dict[str, Any]]:
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

    def get_settings(self, zone_id: str) -> dict[str, Any]:
        """Return {setting_id: value} dict for the zone."""
        data = self._get(f"/zones/{zone_id}/settings")
        return {item["id"]: item.get("value") for item in data.get("result", [])}

    def get_dns_records(self, zone_id: str) -> list[dict[str, Any]]:
        results: list[dict] = []
        page = 1
        while True:
            data = self._get(f"/zones/{zone_id}/dns_records", params={"page": page, "per_page": 200})
            results.extend(data.get("result", []))
            info = data.get("result_info", {})
            if page >= (info.get("total_pages") or 1):
                break
            page += 1
        return results

    def get_ssl_certificate_packs(self, zone_id: str) -> list[dict[str, Any]]:
        data = self._get(f"/zones/{zone_id}/ssl/certificate_packs", params={"status": "all"})
        return data.get("result", []) or []

    def get_firewall_rules(self, zone_id: str) -> list[dict[str, Any]]:
        try:
            data = self._get(f"/zones/{zone_id}/firewall/rules")
            return data.get("result", []) or []
        except CloudflareError:
            # Some accounts/plans return errors for legacy firewall — treat as 0
            return []

    def fetch_analytics_hourly(self, zone_id: str, hours_back: int = 24) -> list[dict[str, Any]]:
        """Returns list of {datetime, requests, cachedRequests, bytes, cachedBytes, threats}."""
        now = datetime.now(timezone.utc).replace(minute=0, second=0, microsecond=0)
        frm = (now - timedelta(hours=hours_back)).strftime("%Y-%m-%dT%H:%M:%SZ")
        to = now.strftime("%Y-%m-%dT%H:%M:%SZ")
        data = self._graphql(GRAPHQL_HOURLY, {"zoneTag": zone_id, "from": frm, "to": to})
        try:
            groups = data["data"]["viewer"]["zones"][0]["httpRequests1hGroups"]
        except (KeyError, IndexError, TypeError):
            return []
        out = []
        for g in groups:
            s = g.get("sum", {}) or {}
            out.append({
                "datetime": g.get("dimensions", {}).get("datetime"),
                "requests": s.get("requests", 0) or 0,
                "cachedRequests": s.get("cachedRequests", 0) or 0,
                "bytes": s.get("bytes", 0) or 0,
                "cachedBytes": s.get("cachedBytes", 0) or 0,
                "threats": s.get("threats", 0) or 0,
            })
        return out
