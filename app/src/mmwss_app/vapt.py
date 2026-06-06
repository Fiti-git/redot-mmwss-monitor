"""VAPT report + finding queries & mutations.

Severity → SLA mapping per the MMWSS proposal:
    critical →  8 h resolution (P1)   — Section 2.2.1
    high     → 14 d resolution (P2-ish but with longer fix window per Section 2.5.2)
    medium   → 30 d
    low      → 60 d
    info     → no SLA (tracked for completeness)

These targets are snapshotted on the finding row so changes to policy
later don't retroactively re-grade past findings.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from . import db


SLA_BY_SEVERITY: dict[str, int] = {
    "critical":  8 * 3600,
    "high":     14 * 24 * 3600,
    "medium":   30 * 24 * 3600,
    "low":      60 * 24 * 3600,
    "info":      0,
}

SEVERITY_LABEL: dict[str, str] = {
    "critical": "Critical",
    "high":     "High",
    "medium":   "Medium",
    "low":      "Low",
    "info":     "Info",
}

STATUS_LABEL: dict[str, str] = {
    "open":            "Open",
    "in_progress":     "In progress",
    "remediated":      "Remediated",
    "verified":        "Verified",
    "accepted_risk":   "Accepted risk",
    "false_positive":  "False positive",
}


# Map VAPT severity → ticket priority for auto-ticket creation.
# 'info' findings don't get a ticket; they're tracked passively.
SEVERITY_TO_TICKET_PRIORITY: dict[str, str] = {
    "critical": "p1",
    "high":     "p2",
    "medium":   "p3",
    "low":      "p4",
    # 'info' intentionally omitted — no ticket
}


# ───────── reports ─────────


def list_reports() -> list[dict]:
    return db.fetch_all(
        """
        SELECT r.id, r.title, r.vendor, r.report_date, r.received_at, r.notes,
               u.email AS uploaded_by_email,
               (SELECT COUNT(*) FROM mmwss.vapt_findings f WHERE f.report_id = r.id) AS total_findings,
               (SELECT COUNT(*) FROM mmwss.vapt_findings f WHERE f.report_id = r.id AND f.status NOT IN ('verified','accepted_risk','false_positive')) AS open_findings,
               (SELECT COUNT(*) FROM mmwss.vapt_findings f WHERE f.report_id = r.id AND f.severity = 'critical' AND f.status NOT IN ('verified','accepted_risk','false_positive')) AS open_critical
        FROM mmwss.vapt_reports r
        LEFT JOIN mmwss.users u ON u.id = r.uploaded_by_user_id
        ORDER BY r.report_date DESC NULLS LAST, r.id DESC
        """
    )


def get_report(report_id: int) -> dict | None:
    return db.fetch_one(
        """
        SELECT r.*, u.email AS uploaded_by_email
        FROM mmwss.vapt_reports r
        LEFT JOIN mmwss.users u ON u.id = r.uploaded_by_user_id
        WHERE r.id = %s
        """,
        (report_id,),
    )


def create_report(*, title: str, vendor: str | None, report_date: str | None,
                  notes: str | None, uploaded_by_user_id: int) -> int:
    rd = report_date if report_date else None
    r = db.fetch_one(
        """
        INSERT INTO mmwss.vapt_reports (title, vendor, report_date, notes, uploaded_by_user_id)
        VALUES (%s, %s, %s, %s, %s) RETURNING id
        """,
        (title.strip(), (vendor or "").strip() or None, rd, (notes or "").strip() or None, uploaded_by_user_id),
    )
    return r["id"]


# ───────── findings ─────────


def list_findings(*, report_id: int | None = None, status: str | None = None,
                  severity: str | None = None, zone_id: int | None = None) -> list[dict]:
    where = []
    params: list[Any] = []
    if report_id:
        where.append("f.report_id = %s"); params.append(report_id)
    if status:
        where.append("f.status = %s"); params.append(status)
    if severity:
        where.append("f.severity = %s"); params.append(severity)
    if zone_id:
        where.append("f.zone_id = %s"); params.append(zone_id)
    sql = """
        SELECT f.*, z.name AS zone_name, r.title AS report_title, r.report_date,
               t.id AS linked_ticket_id, t.status AS linked_ticket_status
        FROM mmwss.vapt_findings f
        LEFT JOIN mmwss.zones z   ON z.id = f.zone_id
        LEFT JOIN mmwss.vapt_reports r ON r.id = f.report_id
        LEFT JOIN mmwss.tickets t ON t.id = f.ticket_id
    """
    if where:
        sql += " WHERE " + " AND ".join(where)
    sql += " ORDER BY CASE f.severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5 END, f.discovered_at DESC"
    return db.fetch_all(sql, tuple(params))


def get_finding(finding_id: int) -> dict | None:
    return db.fetch_one(
        """
        SELECT f.*, z.name AS zone_name, r.title AS report_title, r.report_date, r.vendor,
               t.id AS linked_ticket_id, t.status AS linked_ticket_status
        FROM mmwss.vapt_findings f
        LEFT JOIN mmwss.zones z   ON z.id = f.zone_id
        LEFT JOIN mmwss.vapt_reports r ON r.id = f.report_id
        LEFT JOIN mmwss.tickets t ON t.id = f.ticket_id
        WHERE f.id = %s
        """,
        (finding_id,),
    )


def create_finding(*, report_id: int, title: str, severity: str,
                   description: str | None = None,
                   vendor_finding_id: str | None = None,
                   cve_reference: str | None = None,
                   cvss_score: float | None = None,
                   owasp_category: str | None = None,
                   affected_url: str | None = None,
                   proof_text: str | None = None,
                   zone_id: int | None = None,
                   auto_create_ticket: bool = True,
                   opened_by_user_id: int | None = None) -> tuple[int, int | None]:
    """Returns (finding_id, ticket_id_or_None)."""
    if severity not in SLA_BY_SEVERITY:
        raise ValueError(f"unknown severity: {severity}")
    sla = SLA_BY_SEVERITY[severity]

    with db.conn() as c:
        with c.cursor() as cur:
            cur.execute(
                """
                INSERT INTO mmwss.vapt_findings
                    (report_id, vendor_finding_id, title, description, severity,
                     cve_reference, cvss_score, owasp_category, affected_url, proof_text,
                     zone_id, sla_resolution_secs)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                RETURNING id
                """,
                (report_id, vendor_finding_id, title.strip(),
                 (description or "").strip() or None, severity,
                 (cve_reference or "").strip() or None, cvss_score,
                 (owasp_category or "").strip() or None,
                 (affected_url or "").strip() or None,
                 (proof_text or "").strip() or None,
                 zone_id, sla),
            )
            finding_id = cur.fetchone()["id"]

            ticket_id = None
            if auto_create_ticket and severity in SEVERITY_TO_TICKET_PRIORITY:
                from . import sla as sla_mod
                priority = SEVERITY_TO_TICKET_PRIORITY[severity]
                resp_s, resol_s = sla_mod.TARGETS[priority]
                tag = f"[{severity.upper()}]"
                ttitle = f"{tag} VAPT: {title}".strip()[:200]
                vendor_ref = f"\nVendor finding ID: {vendor_finding_id}" if vendor_finding_id else ""
                cve_ref = f"\nCVE: {cve_reference}" if cve_reference else ""
                cvss_ref = f"\nCVSS: {cvss_score}" if cvss_score else ""
                tdesc = f"{description or ''}{vendor_ref}{cve_ref}{cvss_ref}\n\nAffected: {affected_url or 'see finding'}".strip()
                cur.execute(
                    """
                    INSERT INTO mmwss.tickets
                        (title, description, priority, category, source, zone_id,
                         sla_response_secs, sla_resolution_secs, opened_by_user_id)
                    VALUES (%s, %s, %s, 'vapt', 'auto_alert', %s, %s, %s, %s)
                    RETURNING id
                    """,
                    (ttitle, tdesc, priority, zone_id, resp_s, resol_s, opened_by_user_id),
                )
                ticket_id = cur.fetchone()["id"]
                cur.execute(
                    "INSERT INTO mmwss.ticket_events (ticket_id, user_id, event_type, details_json) "
                    "VALUES (%s, %s, 'created', %s::jsonb)",
                    (ticket_id, opened_by_user_id,
                     json.dumps({"source": "vapt_finding", "finding_id": finding_id, "severity": severity})),
                )
                cur.execute(
                    "UPDATE mmwss.vapt_findings SET ticket_id = %s WHERE id = %s",
                    (ticket_id, finding_id),
                )
        c.commit()
    return finding_id, ticket_id


def update_finding_status(finding_id: int, new_status: str, *,
                          remediation_plan: str | None = None,
                          remediation_evidence: str | None = None) -> None:
    if new_status not in STATUS_LABEL:
        raise ValueError(f"unknown status: {new_status}")
    sets = ["status = %s"]
    params: list[Any] = [new_status]
    now = datetime.now(timezone.utc)
    if new_status == "in_progress":
        sets.append("in_progress_at = COALESCE(in_progress_at, %s)"); params.append(now)
    elif new_status == "remediated":
        sets.append("remediated_at = COALESCE(remediated_at, %s)"); params.append(now)
    elif new_status == "verified":
        sets.append("verified_at = COALESCE(verified_at, %s)"); params.append(now)
        sets.append("remediated_at = COALESCE(remediated_at, %s)"); params.append(now)
    if remediation_plan is not None:
        sets.append("remediation_plan = %s"); params.append(remediation_plan.strip() or None)
    if remediation_evidence is not None:
        sets.append("remediation_evidence = %s"); params.append(remediation_evidence.strip() or None)
    params.append(finding_id)
    sql = f"UPDATE mmwss.vapt_findings SET {', '.join(sets)} WHERE id = %s"
    db.execute(sql, tuple(params))


# ───────── aggregate counters for nav badge / dashboard ─────────


def counters() -> dict:
    row = db.fetch_one(
        """
        SELECT
          (SELECT COUNT(*)::int FROM mmwss.vapt_reports) AS reports,
          (SELECT COUNT(*)::int FROM mmwss.vapt_findings) AS findings_total,
          (SELECT COUNT(*)::int FROM mmwss.vapt_findings WHERE status IN ('open','in_progress')) AS findings_open,
          (SELECT COUNT(*)::int FROM mmwss.vapt_findings WHERE severity = 'critical' AND status IN ('open','in_progress')) AS open_critical,
          (SELECT COUNT(*)::int FROM mmwss.vapt_findings WHERE severity = 'high'     AND status IN ('open','in_progress')) AS open_high,
          (SELECT COUNT(*)::int FROM mmwss.vapt_findings WHERE severity = 'medium'   AND status IN ('open','in_progress')) AS open_medium,
          (SELECT COUNT(*)::int FROM mmwss.vapt_findings WHERE severity = 'low'      AND status IN ('open','in_progress')) AS open_low
        """
    )
    return row or {}
