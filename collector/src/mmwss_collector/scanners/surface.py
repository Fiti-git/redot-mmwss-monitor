"""Attack surface monitor (subfinder + httpx).

Discovers subdomains via `subfinder` (passive DNS sources), probes each via
`httpx` to confirm reachability, then writes results to mmwss.surface_hosts
keyed by (zone_id, host). New hosts (never seen before) generate findings;
hosts that stop responding flip to active=FALSE so the diff is visible in the
monthly report.

Subfinder uses passive sources only by default — no active brute-forcing
of DNS — so it stays well below any rate limits and won't trigger CF WAF.
"""
from __future__ import annotations

import json
import logging
import shutil
import subprocess

from .base import RawFinding, ScanTarget

log = logging.getLogger(__name__)

SUBFINDER_BIN = "subfinder"
HTTPX_BIN = "httpx"


class SurfaceScanner:
    name = "surface"
    kind = "surface"

    def run(self, target: ScanTarget, config: dict) -> list[RawFinding]:
        if not shutil.which(SUBFINDER_BIN):
            log.warning("subfinder not found in PATH — surface scan skipped")
            return []

        timeout = int(config.get("timeout_secs", 600))
        domain = target.zone_name

        # 1. enumerate subdomains
        try:
            sf = subprocess.run(
                [SUBFINDER_BIN, "-d", domain, "-silent", "-all", "-timeout", "30"],
                capture_output=True, text=True, timeout=timeout, check=False,
            )
        except subprocess.TimeoutExpired:
            log.warning("subfinder timed out on %s", domain)
            return []
        except Exception:
            log.exception("subfinder invocation failed")
            return []

        hosts = sorted({l.strip().lower() for l in sf.stdout.splitlines() if l.strip()})
        # Always include the apex so the diff includes it
        if domain not in hosts:
            hosts.append(domain)
        log.info("subfinder discovered %d hosts for %s", len(hosts), domain)

        # 2. probe with httpx (or fall back to requests if httpx not installed)
        probed = self._probe(hosts, timeout=min(120, timeout // 2))

        # 3. write to surface_hosts (caller will diff against DB, emit findings)
        # We can't write here because we don't own the connection / scan_run_id.
        # Instead we encode the probe results into raw= so the runner persists them.
        # But the runner expects RawFinding for vapt_findings — not great fit.
        # Compromise: emit findings only for NEWLY-DISCOVERED hosts. Persistence
        # of surface_hosts itself is handled by a small helper below that the
        # APScheduler job calls after run_scan().
        # For now: emit an informational RawFinding per discovered host so the
        # runner records the inventory in vapt_findings. The post-scan helper
        # below updates the surface_hosts table.
        return []   # we drive everything via the post-scan helper instead


# ───── Standalone helper invoked by the APScheduler job ─────


def probe_and_diff(conn, target: ScanTarget, config: dict) -> dict:
    """Discover + probe + diff against surface_hosts; return counts.

    Run inside an existing scan_runs row. The caller (jobs.run_surface_scan)
    handles scan_runs lifecycle and emits findings for NEW hosts via
    mmwss.vapt_findings directly.
    """
    if not shutil.which(SUBFINDER_BIN):
        return {"discovered": 0, "new": 0, "lost": 0, "skipped": True}

    timeout = int(config.get("timeout_secs", 600))
    domain = target.zone_name

    try:
        sf = subprocess.run(
            [SUBFINDER_BIN, "-d", domain, "-silent", "-all", "-timeout", "30"],
            capture_output=True, text=True, timeout=timeout, check=False,
        )
    except (subprocess.TimeoutExpired, Exception):
        log.exception("subfinder failed for %s", domain)
        return {"discovered": 0, "new": 0, "lost": 0, "error": True}

    hosts = sorted({l.strip().lower() for l in sf.stdout.splitlines() if l.strip()})
    if domain not in hosts:
        hosts.append(domain)

    probed = _probe(hosts, timeout=min(120, timeout // 2))
    # probed: {host: {status, server, title}}

    new_hosts: list[tuple[str, dict]] = []
    lost_hosts: list[str] = []

    with conn.cursor() as cur:
        cur.execute(
            "SELECT host, active FROM mmwss.surface_hosts WHERE zone_id = %s",
            (target.zone_id,),
        )
        existing = {r["host"]: r["active"] for r in cur.fetchall()}

    discovered_set = set(probed.keys())
    for host, meta in probed.items():
        if host not in existing:
            new_hosts.append((host, meta))
    for host, active in existing.items():
        if host not in discovered_set and active:
            lost_hosts.append(host)

    with conn.cursor() as cur:
        for host, meta in probed.items():
            cur.execute(
                """
                INSERT INTO mmwss.surface_hosts
                    (zone_id, host, last_status, last_server, last_title, active, last_seen_at)
                VALUES (%s, %s, %s, %s, %s, TRUE, now())
                ON CONFLICT (zone_id, host) DO UPDATE SET
                    last_status = EXCLUDED.last_status,
                    last_server = EXCLUDED.last_server,
                    last_title  = EXCLUDED.last_title,
                    active = TRUE,
                    last_seen_at = now()
                """,
                (target.zone_id, host, meta.get("status"),
                 meta.get("server"), meta.get("title")),
            )
        for host in lost_hosts:
            cur.execute(
                "UPDATE mmwss.surface_hosts SET active = FALSE WHERE zone_id = %s AND host = %s",
                (target.zone_id, host),
            )
    conn.commit()
    return {
        "discovered": len(probed),
        "new": len(new_hosts),
        "lost": len(lost_hosts),
        "new_hosts": new_hosts,
        "lost_hosts": lost_hosts,
    }


def _probe(hosts: list[str], *, timeout: int) -> dict[str, dict]:
    """Return {host: {status, server, title}} for reachable hosts. Uses httpx
    if available, else a Python requests fallback."""
    if shutil.which(HTTPX_BIN):
        return _probe_httpx(hosts, timeout=timeout)
    return _probe_requests(hosts, timeout=timeout)


def _probe_httpx(hosts: list[str], *, timeout: int) -> dict[str, dict]:
    cmd = [
        HTTPX_BIN, "-silent", "-json", "-no-color",
        "-status-code", "-title", "-server",
        "-timeout", "10", "-threads", "20",
    ]
    try:
        proc = subprocess.run(
            cmd, input="\n".join(hosts),
            capture_output=True, text=True, timeout=timeout, check=False,
        )
    except (subprocess.TimeoutExpired, Exception):
        log.exception("httpx failed; falling back to requests")
        return _probe_requests(hosts, timeout=timeout)

    out: dict[str, dict] = {}
    for line in proc.stdout.splitlines():
        line = line.strip()
        if not line or not line.startswith("{"):
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        host = rec.get("input") or rec.get("host") or ""
        host = host.lower().replace("https://", "").replace("http://", "").rstrip("/")
        if not host:
            continue
        out[host] = {
            "status": rec.get("status-code") or rec.get("status_code"),
            "server": rec.get("webserver") or rec.get("server"),
            "title": (rec.get("title") or "")[:200],
        }
    return out


def _probe_requests(hosts: list[str], *, timeout: int) -> dict[str, dict]:
    """Last-resort fallback if httpx isn't installed."""
    import requests
    out: dict[str, dict] = {}
    for host in hosts:
        for scheme in ("https://", "http://"):
            try:
                r = requests.get(scheme + host, timeout=10, allow_redirects=True,
                                 headers={"User-Agent": "mmwss-collector/0.1 (surface-probe)"})
                out[host] = {
                    "status": r.status_code,
                    "server": r.headers.get("Server"),
                    "title": _extract_title(r.text)[:200] if r.text else None,
                }
                break
            except requests.RequestException:
                continue
    return out


def _extract_title(html: str) -> str:
    import re
    m = re.search(r"<title[^>]*>(.*?)</title>", html, re.IGNORECASE | re.DOTALL)
    return m.group(1).strip() if m else ""
