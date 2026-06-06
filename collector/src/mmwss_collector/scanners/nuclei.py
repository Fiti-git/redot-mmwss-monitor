"""Nuclei scanner integration.

Invokes the `nuclei` binary in JSONL mode and maps each finding to RawFinding.
Templates ship inside the nuclei binary distribution — we rely on the in-image
nuclei-templates update done at container start.

CLI surface (Phase 1):
    nuclei -u <target> -j -silent -no-color
           -severity info,low,medium,high,critical
           -tags <tags from config>
           -timeout 10 -retries 1
           -rate-limit 50

We intentionally do NOT use -as (active scans / fuzzing) in Phase 1 because:
  - active scans need written test authorization from MMWSS
  - active scans risk tripping the customer's own CF WAF and being mistaken for
    an attack against them
  - template-based detection already covers 80% of real-world findings
Phase 2 will add the ZAP DAST scanner for actual active probing.
"""
from __future__ import annotations

import json
import logging
import shutil
import subprocess
from typing import Iterator

from .base import RawFinding, ScanTarget

log = logging.getLogger(__name__)

NUCLEI_BIN = "nuclei"

# Map nuclei's severity strings to ours (1:1 — both use the same vocabulary)
_SEV_MAP = {
    "critical": "critical",
    "high":     "high",
    "medium":   "medium",
    "low":      "low",
    "info":     "info",
    "unknown":  "info",
}


class NucleiScanner:
    name = "nuclei"
    kind = "dast"

    def run(self, target: ScanTarget, config: dict) -> list[RawFinding]:
        if not shutil.which(NUCLEI_BIN):
            log.warning("nuclei binary not found in PATH — skipping scan")
            return []

        sev_floor = config.get("severity_floor", "low")
        tags = config.get("tags", "cve,exposure,misconfig,default-login,exposed-panels")
        timeout = int(config.get("timeout_secs", 900))
        rate_limit = int(config.get("rate_limit", 50))

        severities = self._sevs_at_or_above(sev_floor)
        cmd = [
            NUCLEI_BIN,
            "-u", target.base_url,
            "-jsonl",        # nuclei v3+ flag (replaces -j)
            "-silent",
            "-no-color",
            "-severity", ",".join(severities),
            "-tags", tags,
            "-timeout", "10",
            "-retries", "1",
            "-rate-limit", str(rate_limit),
            "-stats-json",
            "-disable-update-check",
        ]
        log.info("nuclei cmd: %s", " ".join(cmd))
        try:
            proc = subprocess.run(
                cmd, capture_output=True, text=True, timeout=timeout, check=False,
            )
        except subprocess.TimeoutExpired:
            log.warning("nuclei timed out after %ds against %s", timeout, target.base_url)
            return []
        except Exception:
            log.exception("nuclei invocation failed")
            return []

        if proc.returncode not in (0, 1):  # 1 = findings present in some nuclei versions
            log.warning("nuclei exit=%d stderr=%s", proc.returncode, proc.stderr[:500])

        findings: list[RawFinding] = []
        for line in proc.stdout.splitlines():
            line = line.strip()
            if not line or not line.startswith("{"):
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            try:
                rf = self._map(rec, target)
                if rf:
                    findings.append(rf)
            except Exception:
                log.exception("Failed to map nuclei record")
        return findings

    @staticmethod
    def _sevs_at_or_above(floor: str) -> list[str]:
        order = ["info", "low", "medium", "high", "critical"]
        try:
            idx = order.index(floor.lower())
        except ValueError:
            idx = 1   # default 'low'
        return order[idx:]

    @staticmethod
    def _map(rec: dict, target: ScanTarget) -> RawFinding | None:
        info = rec.get("info") or {}
        template_id = rec.get("template-id") or rec.get("templateID") or ""
        if not template_id:
            return None
        sev_raw = (info.get("severity") or "info").lower()
        sev = _SEV_MAP.get(sev_raw, "info")
        title = info.get("name") or template_id

        classification = info.get("classification") or {}
        cves = classification.get("cve-id") or info.get("cve-id")
        if isinstance(cves, list):
            cve = cves[0] if cves else None
        else:
            cve = cves
        cvss = classification.get("cvss-score")
        try:
            cvss_f = float(cvss) if cvss not in (None, "", 0) else None
        except (TypeError, ValueError):
            cvss_f = None

        epss = info.get("epss")
        try:
            epss_f = float(epss) if epss not in (None, "") else None
        except (TypeError, ValueError):
            epss_f = None

        cwe = classification.get("cwe-id")
        owasp = None
        if isinstance(cwe, list) and cwe:
            owasp = f"CWE-{cwe[0]}" if not str(cwe[0]).startswith("CWE-") else cwe[0]

        matched_url = rec.get("matched-at") or rec.get("matched") or rec.get("host") or target.base_url
        description = info.get("description") or ""
        reference = info.get("reference") or []
        if reference:
            description += "\n\nReferences:\n" + "\n".join(f"- {r}" for r in (reference if isinstance(reference, list) else [reference]))

        return RawFinding(
            template_id=template_id,
            title=title,
            severity=sev,
            target_url=matched_url,
            parameter=None,
            description=description.strip() or None,
            cve=cve,
            cvss=cvss_f,
            epss=epss_f,
            owasp_category=owasp,
            proof=rec.get("extracted-results") and json.dumps(rec.get("extracted-results"))[:1000] or None,
            raw=rec,
        )
