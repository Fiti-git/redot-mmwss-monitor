"""OWASP ZAP integration via the REST API of the mmwss-zap daemon container.

Architecture:
    collector ──HTTP──> http://zap:8090 (ZAP daemon)
                        - /JSON/spider/...    crawl
                        - /JSON/pscan/...     passive scan progress
                        - /JSON/ascan/...     active scan (gated)
                        - /JSON/alert/...     findings

Two scan modes:
    'passive' — spider crawl + passive scanners only. Safe. No payload
                injection. No legal/contract risk. Default for all sites.
    'active'  — spider + passive + active scanners (XSS/SQLi/etc payloads).
                Requires written test authorization. Set per-zone via
                config_json or per-run via env override.

Authentication for the ZAP API is via the X-ZAP-API-Key header. The key is
shared between the daemon and the collector via the ZAP_API_KEY env var.
"""
from __future__ import annotations

import logging
import os
import time
from urllib.parse import quote

import requests

from .base import RawFinding, ScanTarget

log = logging.getLogger(__name__)

# Default ZAP daemon URL — overridable via env or scanner config.
DEFAULT_ZAP_URL = os.environ.get("ZAP_URL", "http://zap:8090")
DEFAULT_API_KEY = os.environ.get("ZAP_API_KEY", "")
HTTP_TIMEOUT = 30

# ZAP "risk" levels → our severities
_RISK_TO_SEVERITY = {
    "Informational": "info",
    "Low":           "low",
    "Medium":        "medium",
    "High":          "high",
    # ZAP doesn't have "critical"; treat very-high-confidence High as critical
    # only if explicitly indicated by the alert metadata.
}


class ZAPScanner:
    name = "zap"
    kind = "dast"

    def run(self, target: ScanTarget, config: dict) -> list[RawFinding]:
        zap_url = config.get("zap_url") or DEFAULT_ZAP_URL
        api_key = config.get("zap_api_key") or DEFAULT_API_KEY
        mode = config.get("scan_mode", "passive")
        if mode not in ("passive", "active"):
            log.warning("ZAP scan_mode=%r invalid; defaulting to 'passive'", mode)
            mode = "passive"
        spider_max_min = int(config.get("spider_max_duration_mins", 5))
        spider_max_depth = int(config.get("spider_max_depth", 5))
        passive_wait = int(config.get("passive_wait_secs", 60))
        ascan_max_min = int(config.get("ascan_max_duration_mins", 30))
        sev_floor = (config.get("include_alerts_at_or_above") or "low").lower()
        total_timeout = int(config.get("timeout_secs", 1800))

        if not self._ping(zap_url, api_key):
            log.warning("ZAP daemon not reachable at %s — skipping scan", zap_url)
            return []

        deadline = time.monotonic() + total_timeout

        # ─── 1. Clear context (avoid cross-zone pollution from prior runs) ───
        self._new_session(zap_url, api_key, name=f"mmwss-{target.zone_id}-{int(time.time())}")

        # ─── 2. Spider crawl ───
        log.info("ZAP spider start: %s (max %d min, depth %d)", target.base_url, spider_max_min, spider_max_depth)
        spider_id = self._spider_start(zap_url, api_key, target.base_url, spider_max_min, spider_max_depth)
        if spider_id is None:
            log.warning("ZAP spider failed to start for %s", target.base_url)
            return []
        if not self._wait_spider(zap_url, api_key, spider_id, deadline):
            log.warning("ZAP spider timed out for %s", target.base_url)
            # don't bail — collect whatever passive alerts already exist

        # ─── 3. Wait for passive scan queue to drain ───
        log.info("ZAP passive-scan drain (up to %ds)", passive_wait)
        self._wait_passive(zap_url, api_key, deadline, max_extra_wait=passive_wait)

        # ─── 4. Optional active scan ───
        if mode == "active" and time.monotonic() < deadline:
            log.info("ZAP active scan start: %s (max %d min)", target.base_url, ascan_max_min)
            ascan_id = self._ascan_start(zap_url, api_key, target.base_url, ascan_max_min)
            if ascan_id is not None:
                self._wait_ascan(zap_url, api_key, ascan_id, deadline)

        # ─── 5. Pull alerts ───
        alerts = self._get_alerts(zap_url, api_key, target.base_url)
        log.info("ZAP %s yielded %d raw alerts for %s", mode, len(alerts), target.base_url)

        sev_min = ("info", "low", "medium", "high").index(sev_floor) if sev_floor in ("info", "low", "medium", "high") else 1
        findings: list[RawFinding] = []
        for a in alerts:
            try:
                rf = self._alert_to_finding(a, target)
                if rf is None:
                    continue
                if ("info", "low", "medium", "high", "critical").index(rf.severity) < sev_min:
                    continue
                findings.append(rf)
            except Exception:
                log.exception("ZAP map error for alert %s", a.get("pluginId"))
        return findings

    # ───── ZAP REST helpers ─────

    @staticmethod
    def _params(api_key: str, **extra) -> dict:
        p = {"apikey": api_key} if api_key else {}
        p.update(extra)
        return p

    def _ping(self, zap_url: str, api_key: str) -> bool:
        try:
            r = requests.get(f"{zap_url}/JSON/core/view/version/",
                             params=self._params(api_key), timeout=HTTP_TIMEOUT)
            return r.status_code == 200 and "version" in r.json()
        except requests.RequestException:
            return False

    def _new_session(self, zap_url: str, api_key: str, *, name: str) -> None:
        try:
            requests.get(f"{zap_url}/JSON/core/action/newSession/",
                         params=self._params(api_key, name=name, overwrite="true"),
                         timeout=HTTP_TIMEOUT)
        except requests.RequestException:
            log.warning("ZAP newSession failed; continuing with existing session")

    def _spider_start(self, zap_url: str, api_key: str, url: str,
                       max_minutes: int, max_depth: int) -> str | None:
        try:
            # First, set the spider options
            requests.get(f"{zap_url}/JSON/spider/action/setOptionMaxDuration/",
                         params=self._params(api_key, Integer=str(max_minutes)),
                         timeout=HTTP_TIMEOUT)
            requests.get(f"{zap_url}/JSON/spider/action/setOptionMaxDepth/",
                         params=self._params(api_key, Integer=str(max_depth)),
                         timeout=HTTP_TIMEOUT)
            r = requests.get(f"{zap_url}/JSON/spider/action/scan/",
                             params=self._params(api_key, url=url,
                                                 recurse="true", subtreeOnly="true"),
                             timeout=HTTP_TIMEOUT)
            return r.json().get("scan")
        except (requests.RequestException, ValueError):
            log.exception("ZAP spider start failed")
            return None

    def _wait_spider(self, zap_url: str, api_key: str, scan_id: str,
                      deadline: float) -> bool:
        while time.monotonic() < deadline:
            try:
                r = requests.get(f"{zap_url}/JSON/spider/view/status/",
                                 params=self._params(api_key, scanId=scan_id),
                                 timeout=HTTP_TIMEOUT)
                progress = int(r.json().get("status", "0"))
                if progress >= 100:
                    return True
            except (requests.RequestException, ValueError):
                pass
            time.sleep(5)
        return False

    def _wait_passive(self, zap_url: str, api_key: str, deadline: float,
                       max_extra_wait: int) -> None:
        end = min(deadline, time.monotonic() + max_extra_wait)
        while time.monotonic() < end:
            try:
                r = requests.get(f"{zap_url}/JSON/pscan/view/recordsToScan/",
                                 params=self._params(api_key),
                                 timeout=HTTP_TIMEOUT)
                remaining = int(r.json().get("recordsToScan", "0"))
                if remaining == 0:
                    return
            except (requests.RequestException, ValueError):
                pass
            time.sleep(3)

    def _ascan_start(self, zap_url: str, api_key: str, url: str,
                      max_minutes: int) -> str | None:
        try:
            requests.get(f"{zap_url}/JSON/ascan/action/setOptionMaxScanDurationInMins/",
                         params=self._params(api_key, Integer=str(max_minutes)),
                         timeout=HTTP_TIMEOUT)
            r = requests.get(f"{zap_url}/JSON/ascan/action/scan/",
                             params=self._params(api_key, url=url,
                                                 recurse="true", inScopeOnly="false"),
                             timeout=HTTP_TIMEOUT)
            return r.json().get("scan")
        except (requests.RequestException, ValueError):
            log.exception("ZAP ascan start failed")
            return None

    def _wait_ascan(self, zap_url: str, api_key: str, scan_id: str,
                     deadline: float) -> bool:
        while time.monotonic() < deadline:
            try:
                r = requests.get(f"{zap_url}/JSON/ascan/view/status/",
                                 params=self._params(api_key, scanId=scan_id),
                                 timeout=HTTP_TIMEOUT)
                progress = int(r.json().get("status", "0"))
                if progress >= 100:
                    return True
            except (requests.RequestException, ValueError):
                pass
            time.sleep(10)
        return False

    def _get_alerts(self, zap_url: str, api_key: str, base_url: str) -> list[dict]:
        out: list[dict] = []
        start = 0
        batch = 200
        while True:
            try:
                r = requests.get(f"{zap_url}/JSON/alert/view/alerts/",
                                 params=self._params(api_key, baseurl=base_url,
                                                     start=str(start), count=str(batch)),
                                 timeout=HTTP_TIMEOUT)
                rows = r.json().get("alerts", [])
            except (requests.RequestException, ValueError):
                log.exception("ZAP alerts fetch failed")
                break
            if not rows:
                break
            out.extend(rows)
            if len(rows) < batch:
                break
            start += batch
        return out

    @staticmethod
    def _alert_to_finding(alert: dict, target: ScanTarget) -> RawFinding | None:
        plugin_id = str(alert.get("pluginId") or alert.get("pluginid") or "")
        if not plugin_id:
            plugin_id = alert.get("alertRef") or "unknown"
        title = (alert.get("name") or alert.get("alert") or "ZAP alert").strip()
        risk = (alert.get("risk") or "Informational").strip()
        sev = _RISK_TO_SEVERITY.get(risk, "info")

        # Promote to 'critical' only if ZAP marked High risk AND High confidence
        # AND the alert is in our known-impactful set.
        confidence = (alert.get("confidence") or "").strip()
        if sev == "high" and confidence == "High":
            cwe = str(alert.get("cweid") or "")
            if cwe in {"89", "78", "94", "611", "918"}:   # SQLi, OS cmd, code inj, XXE, SSRF
                sev = "critical"

        target_url = alert.get("url") or target.base_url
        parameter = alert.get("param") or None
        evidence = alert.get("evidence") or None
        attack = alert.get("attack") or None
        cweid = alert.get("cweid")
        wascid = alert.get("wascid")
        solution = alert.get("solution") or ""
        reference = alert.get("reference") or ""
        description = alert.get("description") or ""

        proof_parts = []
        if attack:
            proof_parts.append(f"Attack: {attack}")
        if evidence:
            proof_parts.append(f"Evidence: {evidence}")
        if parameter:
            proof_parts.append(f"Parameter: {parameter}")
        proof_text = "\n".join(proof_parts) if proof_parts else None

        desc_parts = [description.strip()] if description else []
        if solution:
            desc_parts.append(f"\nZAP-recommended solution:\n{solution.strip()}")
        if reference:
            desc_parts.append(f"\nReferences:\n{reference.strip()}")
        full_desc = "\n".join(p for p in desc_parts if p).strip() or None

        return RawFinding(
            template_id=f"zap-{plugin_id}",
            title=title,
            severity=sev,
            target_url=target_url,
            parameter=parameter,
            description=full_desc,
            cve=None,
            cvss=None,
            owasp_category=f"CWE-{cweid}" if cweid else (f"WASC-{wascid}" if wascid else None),
            proof=proof_text,
            raw=alert,
        )
