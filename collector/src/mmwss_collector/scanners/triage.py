"""Deterministic triage engine.

Three responsibilities:
1. Fingerprint a raw finding so re-runs upsert instead of duplicate.
2. Apply finding_rules (FP suppression, severity override, accept-risk).
3. Compute risk_score from CVSS × EPSS × asset_criticality.

No ML, no LLM — every decision is auditable by inspecting the row that fired.
"""
from __future__ import annotations

import fnmatch
import hashlib
import logging
from dataclasses import dataclass

from .base import RawFinding

log = logging.getLogger(__name__)

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
SEVERITY_TO_CVSS_FLOOR = {"info": 0.0, "low": 2.0, "medium": 5.0, "high": 7.5, "critical": 9.0}


def fingerprint(scanner: str, template_id: str, target_url: str, parameter: str | None) -> str:
    """Stable hash for dedup. Same finding from the same scanner against the same
    URL+param always produces the same hash, so the UNIQUE index does the dedup."""
    key = f"{scanner}|{template_id}|{target_url}|{parameter or ''}"
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


@dataclass
class TriageDecision:
    """Result of running rules + scoring against a raw finding."""
    final_severity: str            # may differ from raw if a rule fired
    risk_score: float              # 0-100
    suppressed_rule_id: int | None # set if a 'suppress' or 'accept_risk' rule matched
    initial_status: str            # 'open' normally; 'false_positive' / 'accepted_risk' if rule killed it
    matched_rule_ids: list[int]    # all rules that matched (for audit)
    extra_notes: list[str]         # 'tag' rule notes concatenated into proof_text


def _glob_match(pattern: str | None, value: str | None) -> bool:
    """fnmatch with None semantics. NULL pattern = match anything."""
    if pattern is None:
        return True
    if value is None:
        return False
    return fnmatch.fnmatchcase(value.lower(), pattern.lower())


def _list_match(allow_list: list[str] | None, value: str) -> bool:
    if not allow_list:
        return True
    return value in allow_list


def load_active_rules(conn) -> list[dict]:
    """Fetch enabled rules ordered by specificity (most specific first)."""
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT id, name, scanner, template_id_pattern, url_pattern, title_pattern,
                   zone_id, severity_in, action, action_value
              FROM mmwss.finding_rules
             WHERE enabled = TRUE
             ORDER BY
                 (scanner             IS NOT NULL)::int +
                 (template_id_pattern IS NOT NULL)::int +
                 (url_pattern         IS NOT NULL)::int +
                 (title_pattern       IS NOT NULL)::int +
                 (zone_id             IS NOT NULL)::int DESC,
                 id ASC
            """
        )
        return cur.fetchall()


def _rule_matches(rule: dict, scanner_name: str, finding: RawFinding, zone_id: int) -> bool:
    if rule["scanner"] is not None and rule["scanner"] != scanner_name:
        return False
    if rule["zone_id"] is not None and rule["zone_id"] != zone_id:
        return False
    if not _glob_match(rule["template_id_pattern"], finding.template_id):
        return False
    if not _glob_match(rule["url_pattern"], finding.target_url):
        return False
    if not _glob_match(rule["title_pattern"], finding.title):
        return False
    if not _list_match(rule["severity_in"], finding.severity):
        return False
    return True


def compute_risk_score(
    *,
    severity: str,
    cvss: float | None,
    epss: float | None,
    asset_multiplier: float,
) -> float:
    """0–100 composite score.

    Weighting rationale:
      - 50% base impact (CVSS or severity-derived floor) — what damage if exploited
      - 30% exploit probability (EPSS)                   — how likely
      - 20% asset criticality                            — how much we care
    Multiplied by 100 and clamped.
    """
    base = (cvss if cvss is not None else SEVERITY_TO_CVSS_FLOOR.get(severity, 5.0)) / 10.0
    base = max(0.0, min(1.0, base))
    epss_v = max(0.0, min(1.0, epss if epss is not None else 0.0))
    crit = max(0.1, min(2.0, asset_multiplier)) / 2.0      # normalize to 0-1
    raw = (base * 0.5 + epss_v * 0.3 + crit * 0.2) * 100.0
    return round(min(100.0, max(0.0, raw)), 2)


def triage(
    finding: RawFinding,
    *,
    scanner_name: str,
    zone_id: int,
    asset_multiplier: float,
    rules: list[dict],
) -> TriageDecision:
    final_sev = finding.severity
    suppressed_id: int | None = None
    initial_status = "open"
    matched: list[int] = []
    notes: list[str] = []

    for rule in rules:
        if not _rule_matches(rule, scanner_name, finding, zone_id):
            continue
        matched.append(rule["id"])
        action = rule["action"]
        if action == "suppress":
            suppressed_id = rule["id"]
            initial_status = "false_positive"
            break    # terminal
        if action == "accept_risk":
            suppressed_id = rule["id"]
            initial_status = "accepted_risk"
            break
        if action in ("downgrade", "upgrade"):
            target = (rule["action_value"] or "").strip().lower()
            if target in SEVERITY_ORDER:
                if action == "downgrade" and SEVERITY_ORDER[target] < SEVERITY_ORDER[final_sev]:
                    final_sev = target
                elif action == "upgrade" and SEVERITY_ORDER[target] > SEVERITY_ORDER[final_sev]:
                    final_sev = target
        elif action == "tag":
            if rule["action_value"]:
                notes.append(rule["action_value"])

    risk = compute_risk_score(
        severity=final_sev,
        cvss=finding.cvss,
        epss=finding.epss,
        asset_multiplier=asset_multiplier,
    )
    return TriageDecision(
        final_severity=final_sev,
        risk_score=risk,
        suppressed_rule_id=suppressed_id,
        initial_status=initial_status,
        matched_rule_ids=matched,
        extra_notes=notes,
    )


def get_asset_multiplier(conn, zone_id: int) -> float:
    """Default 1.0 if no row. Cached per scan run by caller."""
    with conn.cursor() as cur:
        cur.execute(
            "SELECT criticality_multiplier FROM mmwss.asset_criticality WHERE zone_id = %s",
            (zone_id,),
        )
        row = cur.fetchone()
    if not row:
        return 1.0
    return float(row["criticality_multiplier"])
