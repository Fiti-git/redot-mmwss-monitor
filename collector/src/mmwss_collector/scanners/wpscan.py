"""WPScan integration (WordPress-specific scanner).

Invokes the `wpscan` ruby binary in JSON mode. Without a vulnerability-DB API
token (`WPSCAN_API_TOKEN`) we still get: WP core version, plugin/theme
enumeration, exposed configs, user enumeration, weak passwords (if requested).
With a token, vendor advisories enrich findings further (free tier: 25/day).

We DO NOT request --enumerate u  in Phase 1 because that triggers HEAD/GET
floods against /?author=N and gets noisy in CF logs. User enumeration via
/wp-json/wp/v2/users is detected by Nuclei templates instead.
"""
from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess

from .base import RawFinding, ScanTarget

log = logging.getLogger(__name__)

WPSCAN_BIN = "wpscan"


class WPScanScanner:
    name = "wpscan"
    kind = "cms"

    def run(self, target: ScanTarget, config: dict) -> list[RawFinding]:
        if not shutil.which(WPSCAN_BIN):
            log.warning("wpscan binary not found in PATH — skipping scan")
            return []

        enumerate_flags = config.get("enumerate", "vp,vt,cb,dbe")
        timeout = int(config.get("timeout_secs", 900))
        api_token = os.environ.get("WPSCAN_API_TOKEN", "").strip()

        cmd = [
            WPSCAN_BIN,
            "--url", target.base_url,
            "--format", "json",
            "--no-banner",
            "--random-user-agent",
            "--enumerate", enumerate_flags,
            "--disable-tls-checks",  # we use Cloudflare; some intermediate edges fail strict TLS
            "--request-timeout", "30",
            "--connect-timeout", "10",
        ]
        if api_token:
            cmd += ["--api-token", api_token]
        log.info("wpscan cmd: %s", " ".join(c if "api-token" not in c else "***" for c in cmd))

        try:
            proc = subprocess.run(
                cmd, capture_output=True, text=True, timeout=timeout, check=False,
            )
        except subprocess.TimeoutExpired:
            log.warning("wpscan timed out after %ds against %s", timeout, target.base_url)
            return []
        except Exception:
            log.exception("wpscan invocation failed")
            return []

        # wpscan exit codes: 0=clean, 4=vulns found, 5=interrupted, etc.
        if proc.returncode not in (0, 4, 5):
            log.warning("wpscan exit=%d stderr=%s", proc.returncode, proc.stderr[:500])

        try:
            data = json.loads(proc.stdout)
        except json.JSONDecodeError:
            log.warning("wpscan returned non-JSON output (first 500 chars): %s", proc.stdout[:500])
            return []

        if data.get("scan_aborted"):
            log.warning("wpscan aborted: %s", data["scan_aborted"])
            return []

        findings: list[RawFinding] = []
        findings.extend(self._extract_core(data, target))
        findings.extend(self._extract_plugins(data, target))
        findings.extend(self._extract_themes(data, target))
        findings.extend(self._extract_interesting(data, target))
        findings.extend(self._extract_config_backups(data, target))
        return findings

    # ───── core ─────
    def _extract_core(self, data: dict, target: ScanTarget) -> list[RawFinding]:
        out: list[RawFinding] = []
        ver = data.get("version") or {}
        if ver and ver.get("number"):
            status = (ver.get("status") or "").lower()
            if status == "outdated" or ver.get("outdated"):
                out.append(RawFinding(
                    template_id="wp-core-outdated/" + ver["number"],
                    title=f"WordPress core outdated: {ver['number']}",
                    severity="high",
                    target_url=target.base_url,
                    description=f"Running WordPress {ver['number']}. WPScan reports status={status or 'outdated'}. "
                                "Upgrade to the latest stable.",
                    cve=None,
                    raw=ver,
                ))
            for vuln in (ver.get("vulnerabilities") or []):
                out.append(self._vuln_to_finding(vuln, target, prefix="wp-core-vulnerable",
                                                  title_prefix=f"WP core {ver['number']}"))
        return out

    # ───── plugins ─────
    def _extract_plugins(self, data: dict, target: ScanTarget) -> list[RawFinding]:
        out: list[RawFinding] = []
        for slug, meta in (data.get("plugins") or {}).items():
            ver = meta.get("version", {}) or {}
            running_ver = ver.get("number") if isinstance(ver, dict) else None
            latest_ver = meta.get("latest_version")
            vulns = meta.get("vulnerabilities") or []
            outdated = bool(meta.get("outdated"))
            if outdated and not vulns:
                out.append(RawFinding(
                    template_id=f"wp-plugin-outdated/{slug}",
                    title=f"Plugin outdated: {slug} ({running_ver or '?'} → {latest_ver or 'latest'})",
                    severity="low",
                    target_url=target.base_url,
                    description=f"Plugin '{slug}' running version {running_ver}. Latest: {latest_ver}.",
                    raw=meta,
                ))
            for vuln in vulns:
                out.append(self._vuln_to_finding(
                    vuln, target, prefix=f"wp-plugin-vulnerable/{slug}",
                    title_prefix=f"Plugin {slug} {running_ver or ''}",
                    raw_extra={"plugin": slug, "running_version": running_ver, "latest": latest_ver},
                ))
        return out

    # ───── themes ─────
    def _extract_themes(self, data: dict, target: ScanTarget) -> list[RawFinding]:
        out: list[RawFinding] = []
        themes_section = data.get("themes") or {}
        main = data.get("main_theme") or {}
        if main:
            themes_section = dict(themes_section)
            themes_section[main.get("slug") or "main"] = main
        for slug, meta in themes_section.items():
            ver = meta.get("version", {}) or {}
            running_ver = ver.get("number") if isinstance(ver, dict) else None
            latest_ver = meta.get("latest_version")
            vulns = meta.get("vulnerabilities") or []
            outdated = bool(meta.get("outdated"))
            if outdated and not vulns:
                out.append(RawFinding(
                    template_id=f"wp-theme-outdated/{slug}",
                    title=f"Theme outdated: {slug} ({running_ver or '?'} → {latest_ver or 'latest'})",
                    severity="low",
                    target_url=target.base_url,
                    description=f"Theme '{slug}' running version {running_ver}. Latest: {latest_ver}.",
                    raw=meta,
                ))
            for vuln in vulns:
                out.append(self._vuln_to_finding(
                    vuln, target, prefix=f"wp-theme-vulnerable/{slug}",
                    title_prefix=f"Theme {slug} {running_ver or ''}",
                    raw_extra={"theme": slug, "running_version": running_ver},
                ))
        return out

    # ───── interesting findings (xmlrpc, readme, etc.) ─────
    def _extract_interesting(self, data: dict, target: ScanTarget) -> list[RawFinding]:
        out: list[RawFinding] = []
        for entry in (data.get("interesting_findings") or []):
            kind = entry.get("type", "interesting")
            to_check = entry.get("to_s") or entry.get("interesting_entries")
            url = entry.get("url") or target.base_url
            severity = "low"
            if kind in ("xmlrpc", "wp-cron"):
                severity = "low"
            elif kind in ("debug-log", "backup-db"):
                severity = "medium"
            out.append(RawFinding(
                template_id=f"wp-interesting/{kind}",
                title=f"WP interesting finding: {kind}",
                severity=severity,
                target_url=url,
                description=str(to_check)[:1000] if to_check else None,
                raw=entry,
            ))
        return out

    # ───── config backups ─────
    def _extract_config_backups(self, data: dict, target: ScanTarget) -> list[RawFinding]:
        out: list[RawFinding] = []
        for entry in (data.get("config_backups") or []):
            url = entry.get("url") or target.base_url
            out.append(RawFinding(
                template_id="wp-config-backup-exposed",
                title=f"Exposed wp-config backup: {url}",
                severity="critical",
                target_url=url,
                description="A wp-config backup file is publicly readable. "
                            "Delete immediately; rotate any credentials/keys/salts disclosed.",
                raw=entry,
            ))
        for entry in (data.get("db_exports") or []):
            url = entry.get("url") or target.base_url
            out.append(RawFinding(
                template_id="wp-db-export-exposed",
                title=f"Exposed DB export: {url}",
                severity="critical",
                target_url=url,
                description="A database dump is publicly readable. "
                            "Delete immediately; treat all user data as breached.",
                raw=entry,
            ))
        return out

    # ───── helper ─────
    @staticmethod
    def _vuln_to_finding(vuln: dict, target: ScanTarget, *, prefix: str,
                         title_prefix: str = "", raw_extra: dict | None = None) -> RawFinding:
        title_v = vuln.get("title", "Unknown vulnerability")
        ftitle = (f"{title_prefix}: {title_v}" if title_prefix else title_v).strip()
        refs = vuln.get("references") or {}
        cve_list = refs.get("cve") or []
        cve = f"CVE-{cve_list[0]}" if cve_list else None
        cvss_v = vuln.get("cvss") or {}
        cvss_score = None
        if isinstance(cvss_v, dict):
            score = cvss_v.get("score") or cvss_v.get("base_score")
            try:
                cvss_score = float(score) if score is not None else None
            except (TypeError, ValueError):
                cvss_score = None
        # Severity inference from CVSS
        if cvss_score is None:
            sev = "high"        # WPScan reports a CVE without score — assume high
        elif cvss_score >= 9.0:
            sev = "critical"
        elif cvss_score >= 7.0:
            sev = "high"
        elif cvss_score >= 4.0:
            sev = "medium"
        else:
            sev = "low"
        raw = {"vuln": vuln}
        if raw_extra:
            raw.update(raw_extra)
        return RawFinding(
            template_id=f"{prefix}/{vuln.get('id', cve or 'unknown')}",
            title=ftitle[:200],
            severity=sev,
            target_url=target.base_url,
            description="\n".join(filter(None, [
                f"Fixed in: {vuln['fixed_in']}" if vuln.get("fixed_in") else None,
                f"References: {', '.join(refs.get('url', []))}" if refs.get("url") else None,
            ])) or None,
            cve=cve,
            cvss=cvss_score,
            raw=raw,
        )
