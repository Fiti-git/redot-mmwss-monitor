"""SLA targets as committed in the MMWSS proposal (Section 5).

Business days are simplified to 24 elapsed hours for now (no calendar /
public-holiday handling). If MMWSS later requests Singapore-PH-aware
calculations, swap business_to_seconds() for a calendar-based helper.
"""
from __future__ import annotations

# (response_secs, resolution_secs)
TARGETS: dict[str, tuple[int, int]] = {
    "p1": (2 * 3600,        8 * 3600),         # 2h / 8h
    "p2": (4 * 3600,       24 * 3600),         # 4h / 24h
    "p3": (1 * 24 * 3600,  3 * 24 * 3600),     # 1 BD / 3 BD
    "p4": (3 * 24 * 3600,  7 * 24 * 3600),     # 3 BD / 7 BD
}

LABEL: dict[str, str] = {
    "p1": "P1 — Critical",
    "p2": "P2 — High",
    "p3": "P3 — Medium",
    "p4": "P4 — Low",
}

EXAMPLE: dict[str, str] = {
    "p1": "Website down, payment failure, or major security breach",
    "p2": "Major functionality failure (donations, user forms, CMS access)",
    "p3": "Plugin update or layout display issue",
    "p4": "Cosmetic UI issue or non-critical bug",
}


def secs_to_human(secs: int) -> str:
    """Render an interval like 2h, 24h, 3d, 7d."""
    if secs < 60:
        return f"{secs}s"
    if secs < 3600:
        return f"{secs // 60}m"
    if secs < 86400:
        return f"{secs // 3600}h"
    return f"{secs // 86400}d"


def targets_human(priority: str) -> tuple[str, str]:
    r, s = TARGETS[priority]
    return secs_to_human(r), secs_to_human(s)
