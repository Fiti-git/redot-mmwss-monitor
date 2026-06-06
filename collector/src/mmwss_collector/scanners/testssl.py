"""testssl.sh integration (TLS configuration scanner).

Invokes testssl.sh with JSON output and maps each issue to a RawFinding.
testssl.sh assigns its own severity (INFO/LOW/MEDIUM/HIGH/CRITICAL); we map
1:1 to ours.

Notes:
  - testssl.sh is heavyweight — we run it weekly per zone, not daily.
  - --severity LOW skips chatty INFO records so output stays focused.
  - --jsonfile-pretty - sends pretty JSON to stdout instead of a file.
"""
from __future__ import annotations

import json
import logging
import shutil
import subprocess
from urllib.parse import urlparse

from .base import RawFinding, ScanTarget

log = logging.getLogger(__name__)

TESTSSL_BIN = "testssl.sh"

_SEV_MAP = {
    "CRITICAL": "critical",
    "HIGH":     "high",
    "MEDIUM":   "medium",
    "LOW":      "low",
    "WARN":     "low",
    "INFO":     "info",
    "OK":       "info",
    "DEBUG":    "info",
}


class TestsslScanner:
    name = "testssl"
    kind = "tls"

    def run(self, target: ScanTarget, config: dict) -> list[RawFinding]:
        if not shutil.which(TESTSSL_BIN):
            log.warning("testssl.sh not found in PATH — skipping scan")
            return []

        sev_floor = (config.get("severity_floor", "LOW") or "LOW").upper()
        timeout = int(config.get("timeout_secs", 600))

        host = urlparse(target.base_url).hostname or target.zone_name
        if not host:
            log.warning("testssl: cannot extract host from %s", target.base_url)
            return []

        cmd = [
            TESTSSL_BIN,
            "--jsonfile", "/dev/stdout",
            "--quiet",
            "--color", "0",
            "--severity", sev_floor,
            "--fast",                # skip ciphers-per-protocol (long, mostly redundant)
            "--sneaky",              # less detectable in CF logs
            "--connect-timeout", "10",
            "--openssl-timeout", "30",
            host,
        ]
        log.info("testssl cmd: %s", " ".join(cmd))
        try:
            proc = subprocess.run(
                cmd, capture_output=True, text=True, timeout=timeout, check=False,
            )
        except subprocess.TimeoutExpired:
            log.warning("testssl timed out after %ds against %s", timeout, host)
            return []
        except Exception:
            log.exception("testssl invocation failed")
            return []

        # testssl writes JSON to /dev/stdout; some versions also print plain text first.
        # Try to find the JSON document.
        stdout = proc.stdout or ""
        start = stdout.find("[")
        if start < 0:
            start = stdout.find("{")
        if start < 0:
            log.warning("testssl: no JSON found in output (stderr=%s)", proc.stderr[:300])
            return []
        try:
            data = json.loads(stdout[start:])
        except json.JSONDecodeError:
            log.warning("testssl: JSON decode failed (first 300 chars): %s", stdout[start:start+300])
            return []

        # testssl JSON shape is a flat list of records {id, severity, finding, ...}.
        # Some versions wrap in {"scanResult":[{...}]}.
        records = data if isinstance(data, list) else data.get("scanResult", []) or [data]
        if records and isinstance(records[0], dict) and "scanResult" in records[0]:
            inner = []
            for r in records:
                inner.extend(r.get("scanResult", []) or [])
            records = inner

        findings: list[RawFinding] = []
        for rec in records:
            if not isinstance(rec, dict):
                continue
            sev_raw = (rec.get("severity") or "INFO").upper()
            sev = _SEV_MAP.get(sev_raw, "info")
            if sev == "info":
                continue   # we already filtered with --severity, but defense in depth
            rid = rec.get("id") or "unknown"
            finding_text = rec.get("finding") or ""
            cve_field = rec.get("cve") or None
            cwe = rec.get("cwe") or None
            findings.append(RawFinding(
                template_id=self._categorize_template(rid, finding_text),
                title=f"TLS: {self._humanize(rid)} — {finding_text[:120]}",
                severity=sev,
                target_url=target.base_url,
                description=finding_text,
                cve=cve_field if isinstance(cve_field, str) else None,
                owasp_category=cwe if isinstance(cwe, str) else None,
                proof=rec.get("hint") or None,
                raw=rec,
            ))
        return findings

    @staticmethod
    def _categorize_template(rid: str, finding: str) -> str:
        """Bucket testssl's many IDs into the patterns our remediation library knows."""
        l = (rid + " " + finding).lower()
        if any(p in l for p in ("sslv3", "tls1", "tls 1.0", "tls 1.1", "tls_1_0", "tls_1_1")):
            return f"deprecated-protocol/{rid}"
        if any(p in l for p in ("cipher", "rc4", "des", "3des", "null", "export")):
            return f"weak-cipher/{rid}"
        if "hsts" in l:
            return f"hsts/{rid}"
        if "cert" in l and ("expir" in l or "valid" in l):
            return f"cert-expiring/{rid}"
        if "heartbleed" in l or "poodle" in l or "freak" in l or "logjam" in l or "drown" in l:
            return f"protocol-vuln/{rid}"
        return f"tls-other/{rid}"

    @staticmethod
    def _humanize(rid: str) -> str:
        return rid.replace("_", " ").replace("-", " ").title()
