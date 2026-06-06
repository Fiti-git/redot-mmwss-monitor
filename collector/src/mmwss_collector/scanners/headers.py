"""Internal security-headers probe.

Replaces a dependency on the Mozilla Observatory API — we do a single HTTPS
HEAD/GET, inspect response headers, and emit findings for each missing or
weak control. Deterministic, no external API calls, no rate limits.

Header policy matches OWASP Secure Headers Project recommendations + Mozilla
Observatory grading defaults.
"""
from __future__ import annotations

import logging

import requests

from .base import RawFinding, ScanTarget

log = logging.getLogger(__name__)

USER_AGENT = "mmwss-collector/0.1 (security-headers-probe)"
TIMEOUT = 15


class HeadersScanner:
    name = "headers"
    kind = "headers"

    def run(self, target: ScanTarget, config: dict) -> list[RawFinding]:
        timeout = int(config.get("timeout_secs", TIMEOUT))
        url = target.base_url
        try:
            r = requests.get(
                url, timeout=timeout, allow_redirects=True,
                headers={"User-Agent": USER_AGENT},
            )
        except requests.RequestException as e:
            log.warning("headers probe failed for %s: %s", url, e)
            return []

        h = {k.lower(): v for k, v in r.headers.items()}
        findings: list[RawFinding] = []

        # CSP
        if "content-security-policy" not in h:
            findings.append(self._mk(url, "missing-csp", "medium",
                "Content-Security-Policy missing",
                "No CSP header sent. Without CSP, the browser cannot enforce a "
                "policy restricting which scripts/styles/images may load — a "
                "successful XSS becomes fully exploitable."))

        # X-Frame-Options (or CSP frame-ancestors)
        csp_val = h.get("content-security-policy", "")
        has_frame_ancestors = "frame-ancestors" in csp_val.lower()
        if "x-frame-options" not in h and not has_frame_ancestors:
            findings.append(self._mk(url, "missing-x-frame-options", "medium",
                "X-Frame-Options missing",
                "Site can be embedded in an iframe by any origin (clickjacking)."))

        # X-Content-Type-Options
        if h.get("x-content-type-options", "").lower() != "nosniff":
            findings.append(self._mk(url, "missing-x-content-type-options", "low",
                "X-Content-Type-Options missing or wrong value",
                "Browsers may MIME-sniff responses, enabling injection attacks."))

        # Referrer-Policy
        if "referrer-policy" not in h:
            findings.append(self._mk(url, "missing-referrer-policy", "low",
                "Referrer-Policy missing",
                "Full URL leaks to third parties via Referer header."))

        # Permissions-Policy (formerly Feature-Policy)
        if "permissions-policy" not in h and "feature-policy" not in h:
            findings.append(self._mk(url, "missing-permissions-policy", "low",
                "Permissions-Policy missing",
                "No control over which browser APIs (geo, camera, mic, etc.) "
                "can be used by the site or embedded content."))

        # HSTS
        hsts = h.get("strict-transport-security", "")
        if not hsts:
            findings.append(self._mk(url, "missing-hsts", "medium",
                "Strict-Transport-Security missing",
                "Without HSTS, the first HTTP→HTTPS upgrade is interceptable."))
        else:
            # Parse max-age
            max_age = 0
            for part in hsts.split(";"):
                p = part.strip().lower()
                if p.startswith("max-age="):
                    try:
                        max_age = int(p.split("=", 1)[1])
                    except ValueError:
                        pass
            if max_age < 15552000:    # 180 days = Observatory threshold
                findings.append(self._mk(url, "weak-hsts", "low",
                    f"HSTS max-age too short ({max_age}s)",
                    f"max-age below 180 days. Increase to 31536000 (1 year)."))

        # Server / X-Powered-By disclosure
        for hdr in ("server", "x-powered-by"):
            v = h.get(hdr)
            if v and any(p in v.lower() for p in ("apache/", "nginx/", "php/", "iis/", "openresty/")):
                # Version disclosed
                if any(c.isdigit() for c in v):
                    findings.append(self._mk(url, f"disclosure-{hdr}", "info",
                        f"{hdr} header discloses version: {v}",
                        f"Consider stripping the version from the {hdr} header."))

        # Cookie attributes
        for c in r.cookies:
            issues = []
            if not c.secure:
                issues.append("Secure flag missing")
            if "httponly" not in str(getattr(c, "_rest", {})).lower():
                # requests' cookie object doesn't expose HttpOnly cleanly; inspect raw headers
                pass
            if issues:
                findings.append(self._mk(url, f"cookie-{c.name}", "low",
                    f"Cookie '{c.name}' missing security attributes",
                    f"Issues: {', '.join(issues)}. Add Secure and HttpOnly flags."))

        # HttpOnly via raw header
        raw_set_cookies = r.raw.headers.getlist("Set-Cookie") if hasattr(r.raw, "headers") else []
        for sc in raw_set_cookies:
            sc_l = sc.lower()
            if "httponly" not in sc_l and "session" in sc_l.split("=", 1)[0].lower():
                findings.append(self._mk(url, "cookie-no-httponly", "low",
                    f"Session cookie missing HttpOnly",
                    "Session cookies should have the HttpOnly flag so JavaScript cannot read them."))
                break

        return findings

    @staticmethod
    def _mk(url: str, template_id: str, sev: str, title: str, desc: str) -> RawFinding:
        return RawFinding(
            template_id=template_id,
            title=title,
            severity=sev,
            target_url=url,
            description=desc,
        )
