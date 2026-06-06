"""Phase 1 in-house VAPT scanners.

Every scanner returns a list of RawFinding objects. The runner module
normalizes, dedupes, applies triage rules, and upserts into mmwss.vapt_findings
so scanner output flows through the same VAPT pipeline (ticket auto-creation,
SLA timers, change-log on remediation) that vendor findings use.
"""
from .base import RawFinding, ScanTarget, Scanner

__all__ = ["RawFinding", "ScanTarget", "Scanner"]
