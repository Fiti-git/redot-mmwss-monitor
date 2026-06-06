"""WordPress synthetic checks — HTTP-only, no WP API key required.

Each check returns either nothing (pass) or a finding dict:
    {"check": stable_id, "severity": "critical|warning|info", "details": "..."}

Findings are bucketed into categories:
    exposures  — files/endpoints that should never be reachable
    config     — misconfigurations a hardening checklist would call out
    health     — site is unreachable, returning 5xx, has DB errors, etc.
    info       — disclosure-style (version leakage)

Defensive design:
- All requests are GET/POST with short timeouts (8s default)
- We never send credentials or trigger any state change
- We only LOOK at responses; we never try to exploit anything
- If a probe fails (DNS, timeout, refused), we do NOT report it as a finding
  — that just means the path isn't reachable, which is the desired state
"""
from __future__ import annotations

import logging
import re
import time
from urllib.parse import urljoin

import requests

log = logging.getLogger(__name__)

_TIMEOUT = 8
_UA = "MMWSS-Scanner/0.1 (+https://coldcalling.redotglobal.agency/mmwss; internal monitoring)"
_HEADERS = {"User-Agent": _UA, "Accept": "*/*"}

# A few signatures we look for in HTML bodies to recognize WordPress
WP_FINGERPRINTS = (
    "wp-content/",
    "wp-includes/",
    "/wp-json/",
    'name="generator" content="WordPress',
    "wp-emoji-release.min.js",
)

# WP-version detection regexes (try in order)
RE_GENERATOR = re.compile(r'<meta\s+name=["\']generator["\']\s+content=["\']WordPress\s+([\d.]+)', re.I)
RE_README_VER = re.compile(r"<h1[^>]*>\s*Version\s+([\d.]+)", re.I)

# Strings that mean "site is broken right now"
HEALTH_ERROR_MARKERS = (
    "Error establishing a database connection",
    "MySQL server has gone away",
    "Fatal error:",
    "Parse error:",
    "Maximum execution time of",
)


# ───────── helpers ─────────


def _get(url: str, *, allow_redirects: bool = False, method: str = "GET", **kwargs):
    """Wrapper that swallows network errors — they are the desired state for
    most defensive checks (path not reachable = good)."""
    try:
        return requests.request(
            method, url, timeout=_TIMEOUT, headers=_HEADERS,
            allow_redirects=allow_redirects, **kwargs,
        )
    except requests.RequestException:
        return None


def _add(findings: dict, bucket: str, **payload) -> None:
    findings.setdefault(bucket, []).append(payload)


# ───────── individual checks ─────────


def _check_home(base: str, findings: dict) -> tuple[int | None, int | None, bool, str | None, str]:
    """Hit the home page. Returns (status_code, latency_ms, is_wp, wp_version, body_excerpt)."""
    t = time.monotonic()
    r = _get(base, allow_redirects=True)
    latency_ms = int((time.monotonic() - t) * 1000)
    if r is None:
        _add(findings, "health", check="home_unreachable", severity="critical",
             details="Home page request failed (DNS, timeout, or connection refused).")
        return None, latency_ms, False, None, ""

    body = r.text[:80000] if r.text else ""
    if r.status_code >= 500:
        _add(findings, "health", check="home_5xx", severity="critical",
             details=f"Home page returned HTTP {r.status_code}.")
    elif r.status_code >= 400:
        _add(findings, "health", check="home_4xx", severity="warning",
             details=f"Home page returned HTTP {r.status_code}.")

    for marker in HEALTH_ERROR_MARKERS:
        if marker in body:
            _add(findings, "health", check="error_text_on_page", severity="critical",
                 details=f"Home page contains: '{marker}'")
            break  # one is enough

    is_wp = any(sig in body for sig in WP_FINGERPRINTS)
    wp_version = None
    m = RE_GENERATOR.search(body)
    if m:
        wp_version = m.group(1)
        _add(findings, "info", check="wp_version_in_generator", severity="info",
             details=f"WordPress version {wp_version} disclosed via <meta name=\"generator\"> — easy attacker fingerprinting.")
    return r.status_code, latency_ms, is_wp, wp_version, body


def _check_wp_config(base: str, findings: dict) -> None:
    r = _get(urljoin(base, "/wp-config.php"))
    if r and r.status_code == 200 and r.text and (
        "DB_PASSWORD" in r.text or "<?php" in r.text
    ):
        _add(findings, "exposures", check="wp_config_exposed", severity="critical",
             details="/wp-config.php is being served with content. Database credentials are leaked. Block immediately via web server config.")


def _check_env(base: str, findings: dict) -> None:
    r = _get(urljoin(base, "/.env"))
    if r and r.status_code == 200 and r.text and "=" in r.text and len(r.text) < 20000:
        # Heuristic: env files are key=value lines, modest in size
        if re.search(r"(?im)^\s*[A-Z_][A-Z0-9_]+\s*=", r.text):
            _add(findings, "exposures", check="env_exposed", severity="critical",
                 details="/.env is publicly served. Secrets exposed.")


def _check_install_script(base: str, findings: dict) -> None:
    r = _get(urljoin(base, "/wp-admin/install.php"))
    if r and r.status_code == 200 and r.text and ("WordPress" in r.text and "install" in r.text.lower()):
        _add(findings, "exposures", check="install_script_accessible", severity="critical",
             details="/wp-admin/install.php is accessible. An attacker may be able to re-install over the site.")


def _check_wp_admin(base: str, findings: dict) -> None:
    """/wp-admin/ should redirect to /wp-login.php (or 302/301 to login).
    If it returns 200 with admin UI markers, that's catastrophic."""
    r = _get(urljoin(base, "/wp-admin/"), allow_redirects=False)
    if r and r.status_code == 200 and r.text and ("dashboard" in r.text.lower() and "wp-admin" in r.text.lower()):
        # Could be the login form embedded; require stronger signal
        if "wp-admin/edit.php" in r.text or "Howdy," in r.text:
            _add(findings, "exposures", check="wp_admin_exposed", severity="critical",
                 details="/wp-admin/ serves an authenticated admin page without redirecting to login.")


def _check_xmlrpc(base: str, findings: dict) -> None:
    """A GET to /xmlrpc.php on an enabled install returns
       'XML-RPC server accepts POST requests only.' — that's the signal."""
    r = _get(urljoin(base, "/xmlrpc.php"))
    if r and r.status_code == 405 and r.text and "XML-RPC server accepts POST requests only" in r.text:
        _add(findings, "config", check="xmlrpc_enabled", severity="warning",
             details="/xmlrpc.php is enabled. Common vector for brute-force amplification and pingback DDoS. Disable unless explicitly needed.")
    elif r and r.status_code == 200 and r.text and "XML-RPC" in r.text:
        _add(findings, "config", check="xmlrpc_enabled", severity="warning",
             details="/xmlrpc.php is enabled. Common vector for brute-force amplification. Disable unless needed.")


def _check_rest_users(base: str, findings: dict) -> None:
    """Default WP REST API leaks /wp-json/wp/v2/users — username enumeration."""
    r = _get(urljoin(base, "/wp-json/wp/v2/users"), allow_redirects=True)
    if r is None or r.status_code != 200:
        return
    try:
        data = r.json()
    except ValueError:
        return
    if isinstance(data, list) and len(data) > 0 and isinstance(data[0], dict) and "slug" in data[0]:
        usernames = [u.get("slug") for u in data[:5] if u.get("slug")]
        _add(findings, "exposures", check="rest_users_enumerable", severity="warning",
             details=f"REST API /wp-json/wp/v2/users returns {len(data)} user(s) publicly. Sample: {usernames}. Restrict to authenticated requests.")


def _check_readme(base: str, findings: dict) -> str | None:
    """WP's readme.html sometimes survives upgrades and leaks the version."""
    r = _get(urljoin(base, "/readme.html"))
    if not (r and r.status_code == 200 and r.text):
        return None
    if "WordPress" not in r.text:
        return None
    _add(findings, "config", check="readme_html_present", severity="info",
         details="/readme.html exists and identifies the install as WordPress. Delete to reduce fingerprinting.")
    m = RE_README_VER.search(r.text)
    return m.group(1) if m else None


def _check_backup_files(base: str, findings: dict) -> None:
    """Common careless leftovers from staging migrations."""
    for path in ("/wp-config.php.bak", "/wp-config.bak", "/backup.sql", "/database.sql",
                 "/.git/config", "/.htaccess.bak"):
        r = _get(urljoin(base, path))
        if r and r.status_code == 200 and r.text and len(r.text) > 0:
            _add(findings, "exposures", check="backup_file_exposed",
                 severity="critical",
                 details=f"{path} is publicly accessible. Likely a forgotten backup or VCS leak.")


# ───────── orchestration ─────────


def run_checks(zone_name: str) -> dict:
    """Run all checks against https://<zone_name>. Returns:
        {
            "is_wordpress": bool,
            "wp_version":   str | None,
            "home_status":  int | None,
            "home_latency_ms": int | None,
            "findings": {"exposures": [...], "config": [...], "health": [...], "info": [...]},
        }
    """
    base = f"https://{zone_name}"
    findings: dict = {}
    status, latency, is_wp, wp_version, _body = _check_home(base, findings)

    # All the others — safe to run regardless, but if the home page is fully
    # unreachable we skip the WP-specific ones to avoid noise.
    if status is not None:
        _check_wp_config(base, findings)
        _check_env(base, findings)
        _check_install_script(base, findings)
        _check_wp_admin(base, findings)
        _check_xmlrpc(base, findings)
        _check_rest_users(base, findings)
        readme_ver = _check_readme(base, findings)
        if readme_ver and not wp_version:
            wp_version = readme_ver
        _check_backup_files(base, findings)

    # Normalize: make sure all four buckets exist (UI is simpler when keys are present)
    for k in ("exposures", "config", "health", "info"):
        findings.setdefault(k, [])

    return {
        "is_wordpress": is_wp,
        "wp_version": wp_version,
        "home_status": status,
        "home_latency_ms": latency,
        "findings": findings,
    }
