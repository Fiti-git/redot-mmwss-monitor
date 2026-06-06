"""Scanner contract + normalized finding shape.

Every scanner produces a list of RawFinding records. The runner is responsible
for dedup, rule application, risk scoring, and persistence — scanners stay
focused on "what did the tool find."
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol


@dataclass
class ScanTarget:
    zone_id: int
    zone_name: str
    base_url: str            # 'https://example.com'
    cf_zone_id: str | None = None
    cf_token: str | None = None  # injected so scanners can poke CF settings if needed


# Valid severities (mirror mmwss.vapt_severity enum)
VALID_SEVERITIES = ("critical", "high", "medium", "low", "info")


@dataclass
class RawFinding:
    """Scanner output, pre-normalization.

    Fingerprint is computed by the runner from (scanner, template_id, target_url, parameter).
    Severity is the scanner's own opinion — the rule engine may downgrade or upgrade.
    """
    template_id: str                    # 'CVE-2023-1234' | 'wp/yoast-seo/outdated' | 'tls/weak-cipher'
    title: str
    severity: str                       # one of VALID_SEVERITIES
    target_url: str                     # specific URL that tripped
    parameter: str | None = None        # specific param, when applicable
    description: str | None = None
    cve: str | None = None
    cvss: float | None = None
    epss: float | None = None
    owasp_category: str | None = None
    proof: str | None = None
    raw: dict | None = field(default=None)  # full original record for audit

    def __post_init__(self):
        if self.severity not in VALID_SEVERITIES:
            raise ValueError(f"invalid severity {self.severity!r}, must be one of {VALID_SEVERITIES}")
        self.title = self.title.strip()[:200]
        if self.cve:
            self.cve = self.cve.strip().upper()


class Scanner(Protocol):
    """Contract: implement run() to return findings for a target."""
    name: str                # registered in mmwss.scanners.name
    kind: str                # 'dast' | 'cms' | 'tls' | 'headers' | 'surface'

    def run(self, target: ScanTarget, config: dict) -> list[RawFinding]:
        ...
