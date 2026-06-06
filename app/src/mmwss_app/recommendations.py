"""Recommendations engine — rules over the latest snapshot per zone.

Same rules as collector/reports.py (intentional duplication; the rule set is
small and the alternative — shared package mounted into both containers —
adds deploy complexity without much code reuse).

Scoring: start at 100, subtract weight per rule that fires. Floor at 0.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone


@dataclass
class Recommendation:
    severity: str       # 'critical' | 'warning' | 'info'
    title: str          # short, scannable
    body: str           # one-sentence why + how
    rule_id: str        # stable id e.g. 'ssl_unsafe' — useful for analytics

    @property
    def weight(self) -> int:
        return {"critical": 15, "warning": 7, "info": 2}.get(self.severity, 0)


def score_to_grade(score: int) -> tuple[str, str]:
    """Return (letter, color)."""
    if score >= 90: return ("A", "ok")
    if score >= 80: return ("B", "ok")
    if score >= 70: return ("C", "warn")
    if score >= 60: return ("D", "warn")
    return ("F", "danger")


def evaluate(*, name: str, settings: dict, ssl_expiry, fw_rules_total) -> list[Recommendation]:
    """Return all firing recommendations for one zone."""
    out: list[Recommendation] = []
    s = settings or {}
    ssl_mode = (s.get("ssl") or "").lower()

    if ssl_mode in ("off", "flexible"):
        out.append(Recommendation(
            severity="critical", rule_id="ssl_unsafe",
            title="SSL mode is unsafe",
            body=f"Origin certificate is not being validated (mode = '{ssl_mode}'). Switch to 'strict' (or 'full' if origin cert is self-signed).",
        ))
    elif ssl_mode == "full":
        out.append(Recommendation(
            severity="warning", rule_id="ssl_full",
            title="SSL mode is 'full' — consider 'strict'",
            body="'Full' accepts any cert at the origin including expired or self-signed. 'Strict' validates against a trusted CA.",
        ))

    if (s.get("always_use_https") or "").lower() == "off":
        out.append(Recommendation(
            severity="critical", rule_id="https_off",
            title="Always Use HTTPS is OFF",
            body="HTTP requests reach the origin in plaintext. Turn on in Cloudflare → SSL/TLS → Edge Certificates.",
        ))

    sec = (s.get("security_level") or "").lower()
    if sec in ("off", "essentially_off"):
        out.append(Recommendation(
            severity="critical", rule_id="security_off",
            title="Security level is essentially off",
            body="Basic bot/DDoS protection disabled. Raise to 'Medium' minimum.",
        ))

    tls = str(s.get("min_tls_version") or "")
    if tls in ("1.0", "1.1"):
        out.append(Recommendation(
            severity="warning", rule_id="tls_old",
            title=f"Minimum TLS version is {tls}",
            body="TLS 1.0/1.1 are deprecated and below the PCI-DSS baseline. Set minimum to 1.2.",
        ))

    if (s.get("brotli") or "").lower() == "off":
        out.append(Recommendation(
            severity="info", rule_id="brotli_off",
            title="Brotli compression disabled",
            body="Enabling Brotli reduces bandwidth by ~15–25% over Gzip. Zero-risk change.",
        ))

    if (s.get("development_mode") or "").lower() == "on":
        out.append(Recommendation(
            severity="warning", rule_id="dev_mode_on",
            title="Development mode is ON",
            body="Cache is bypassed. Origin is taking all the load. Turn off unless actively debugging.",
        ))

    if (fw_rules_total or 0) == 0:
        out.append(Recommendation(
            severity="info", rule_id="no_fw_rules",
            title="No custom firewall rules",
            body="Only default Cloudflare protection active. Adding targeted rules (block country X, rate-limit /wp-login) makes a real difference for WordPress sites.",
        ))

    if ssl_expiry:
        days = (ssl_expiry - datetime.now(timezone.utc)).days
        if 0 <= days <= 30:
            sev = "warning" if days >= 7 else "critical"
            out.append(Recommendation(
                severity=sev, rule_id="ssl_expiry_near",
                title=f"SSL certificate expires in {days} days",
                body=f"Cert expires {ssl_expiry.strftime('%Y-%m-%d')}. Cloudflare auto-renews; verify in the dashboard.",
            ))

    return out


def calculate_score(recommendations: list[Recommendation]) -> int:
    score = 100 - sum(r.weight for r in recommendations)
    return max(0, score)
