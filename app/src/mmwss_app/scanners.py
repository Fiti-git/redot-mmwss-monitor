"""App-side queries for scanner registry, scan runs, rules, and surface diff.

Findings themselves come through the existing mmwss_app.vapt module since
scanner findings live in mmwss.vapt_findings (with source='internal_scan').
"""
from __future__ import annotations

import json
from typing import Any

from . import db


SCANNER_LABEL: dict[str, str] = {
    "nuclei":  "Nuclei (template DAST)",
    "wpscan":  "WPScan (WordPress)",
    "testssl": "testssl.sh (TLS)",
    "headers": "Security headers",
    "surface": "Attack surface",
}

RULE_ACTION_LABEL: dict[str, str] = {
    "suppress":    "Suppress (auto-close as false positive)",
    "downgrade":   "Downgrade severity",
    "upgrade":     "Upgrade severity",
    "accept_risk": "Accept risk (auto-close as accepted)",
    "tag":         "Tag with note (no status change)",
}


# ───── scanners registry ─────


def list_scanners() -> list[dict]:
    return db.fetch_all(
        """
        SELECT s.id, s.name, s.kind, s.description, s.enabled, s.version,
               s.config_json, s.last_run_at, s.created_at,
               (SELECT COUNT(*)::int FROM mmwss.scan_runs r WHERE r.scanner_id = s.id) AS total_runs,
               (SELECT COUNT(*)::int FROM mmwss.scan_runs r WHERE r.scanner_id = s.id AND r.status = 'failed') AS failed_runs,
               (SELECT COUNT(*)::int FROM mmwss.vapt_findings f
                  WHERE f.scanner = s.name AND f.status IN ('open','in_progress')) AS open_findings
          FROM mmwss.scanners s
         ORDER BY s.name
        """
    )


def get_scanner(scanner_id: int) -> dict | None:
    return db.fetch_one("SELECT * FROM mmwss.scanners WHERE id = %s", (scanner_id,))


def toggle_scanner(scanner_id: int, enabled: bool) -> None:
    db.execute("UPDATE mmwss.scanners SET enabled = %s WHERE id = %s", (enabled, scanner_id))


# ───── scan runs ─────


def list_scan_runs(*, scanner_id: int | None = None, zone_id: int | None = None,
                   limit: int = 100) -> list[dict]:
    where = []
    params: list[Any] = []
    if scanner_id:
        where.append("r.scanner_id = %s"); params.append(scanner_id)
    if zone_id:
        where.append("r.zone_id = %s"); params.append(zone_id)
    sql = """
        SELECT r.id, r.scanner_id, s.name AS scanner_name, s.kind AS scanner_kind,
               r.zone_id, z.name AS zone_name,
               r.target_url, r.started_at, r.finished_at, r.duration_secs,
               r.status, r.error_message, r.raw_artifact_path,
               r.findings_total, r.findings_new, r.findings_resolved, r.findings_suppressed,
               r.triggered_by, r.vapt_report_id
          FROM mmwss.scan_runs r
          JOIN mmwss.scanners s ON s.id = r.scanner_id
          JOIN mmwss.zones z    ON z.id = r.zone_id
    """
    if where:
        sql += " WHERE " + " AND ".join(where)
    sql += " ORDER BY r.started_at DESC LIMIT %s"
    params.append(limit)
    return db.fetch_all(sql, tuple(params))


def get_scan_run(run_id: int) -> dict | None:
    return db.fetch_one(
        """
        SELECT r.*, s.name AS scanner_name, s.kind AS scanner_kind, z.name AS zone_name
          FROM mmwss.scan_runs r
          JOIN mmwss.scanners s ON s.id = r.scanner_id
          JOIN mmwss.zones z    ON z.id = r.zone_id
         WHERE r.id = %s
        """,
        (run_id,),
    )


# ───── scanner findings (lives in vapt_findings, filtered) ─────


def list_scanner_findings(*, scanner: str | None = None, status: str | None = None,
                           severity: str | None = None, zone_id: int | None = None,
                           min_risk: float | None = None, limit: int = 500) -> list[dict]:
    where = ["f.source = 'internal_scan'"]
    params: list[Any] = []
    if scanner:
        where.append("f.scanner = %s"); params.append(scanner)
    if status:
        where.append("f.status = %s"); params.append(status)
    if severity:
        where.append("f.severity = %s"); params.append(severity)
    if zone_id:
        where.append("f.zone_id = %s"); params.append(zone_id)
    if min_risk is not None:
        where.append("f.risk_score >= %s"); params.append(min_risk)
    sql = """
        SELECT f.id, f.title, f.severity, f.status, f.scanner, f.scanner_template_id,
               f.target_url, f.parameter, f.cve_reference, f.cvss_score, f.epss_score,
               f.risk_score, f.first_seen_at, f.last_seen_at, f.consecutive_misses,
               f.zone_id, z.name AS zone_name,
               f.ticket_id, t.status AS ticket_status,
               f.scan_run_id, f.suppressed_by_rule_id, f.report_id
          FROM mmwss.vapt_findings f
          LEFT JOIN mmwss.zones   z ON z.id = f.zone_id
          LEFT JOIN mmwss.tickets t ON t.id = f.ticket_id
    """
    sql += " WHERE " + " AND ".join(where)
    sql += " ORDER BY f.risk_score DESC NULLS LAST, f.last_seen_at DESC LIMIT %s"
    params.append(limit)
    return db.fetch_all(sql, tuple(params))


def scanner_counters() -> dict:
    r = db.fetch_one(
        """
        SELECT
            (SELECT COUNT(*)::int FROM mmwss.vapt_findings
              WHERE source = 'internal_scan') AS total,
            (SELECT COUNT(*)::int FROM mmwss.vapt_findings
              WHERE source = 'internal_scan' AND status IN ('open','in_progress')) AS open_total,
            (SELECT COUNT(*)::int FROM mmwss.vapt_findings
              WHERE source = 'internal_scan' AND status IN ('open','in_progress') AND severity = 'critical') AS open_critical,
            (SELECT COUNT(*)::int FROM mmwss.vapt_findings
              WHERE source = 'internal_scan' AND status IN ('open','in_progress') AND severity = 'high') AS open_high,
            (SELECT COUNT(*)::int FROM mmwss.vapt_findings
              WHERE source = 'internal_scan' AND status IN ('open','in_progress') AND severity = 'medium') AS open_medium,
            (SELECT COUNT(*)::int FROM mmwss.vapt_findings
              WHERE source = 'internal_scan' AND status = 'verified'
                AND verified_at >= now() - interval '30 days') AS verified_30d,
            (SELECT COUNT(*)::int FROM mmwss.vapt_findings
              WHERE source = 'internal_scan' AND first_seen_at >= now() - interval '7 days') AS new_7d,
            (SELECT COUNT(*)::int FROM mmwss.scan_runs
              WHERE started_at >= now() - interval '7 days') AS runs_7d,
            (SELECT COUNT(*)::int FROM mmwss.scan_runs
              WHERE status = 'failed' AND started_at >= now() - interval '7 days') AS failed_runs_7d
        """
    )
    return r or {}


# ───── finding rules ─────


def list_rules() -> list[dict]:
    return db.fetch_all(
        """
        SELECT r.id, r.name, r.scanner, r.template_id_pattern, r.url_pattern,
               r.title_pattern, r.zone_id, z.name AS zone_name,
               r.severity_in, r.action, r.action_value, r.enabled, r.notes,
               r.hit_count, r.last_hit_at, r.created_at,
               u.email AS created_by_email
          FROM mmwss.finding_rules r
          LEFT JOIN mmwss.zones z ON z.id = r.zone_id
          LEFT JOIN mmwss.users u ON u.id = r.created_by_user_id
         ORDER BY r.enabled DESC, r.id DESC
        """
    )


def get_rule(rule_id: int) -> dict | None:
    return db.fetch_one(
        "SELECT * FROM mmwss.finding_rules WHERE id = %s",
        (rule_id,),
    )


def create_rule(*, name: str, scanner: str | None, template_id_pattern: str | None,
                url_pattern: str | None, title_pattern: str | None, zone_id: int | None,
                severity_in: list[str] | None, action: str, action_value: str | None,
                notes: str | None, created_by_user_id: int) -> int:
    if action not in RULE_ACTION_LABEL:
        raise ValueError(f"unknown action: {action}")
    if action in ("downgrade", "upgrade") and (action_value or "").lower() not in (
        "critical", "high", "medium", "low", "info"):
        raise ValueError("downgrade/upgrade requires target severity in action_value")
    sev_list = [s for s in (severity_in or []) if s in ("critical","high","medium","low","info")]
    r = db.fetch_one(
        """
        INSERT INTO mmwss.finding_rules
            (name, scanner, template_id_pattern, url_pattern, title_pattern,
             zone_id, severity_in, action, action_value, notes, created_by_user_id)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        RETURNING id
        """,
        (name.strip(),
         (scanner or "").strip() or None,
         (template_id_pattern or "").strip() or None,
         (url_pattern or "").strip() or None,
         (title_pattern or "").strip() or None,
         zone_id, sev_list or None,
         action, (action_value or "").strip() or None,
         (notes or "").strip() or None, created_by_user_id),
    )
    return r["id"]


def toggle_rule(rule_id: int, enabled: bool) -> None:
    db.execute("UPDATE mmwss.finding_rules SET enabled = %s WHERE id = %s",
               (enabled, rule_id))


def delete_rule(rule_id: int) -> None:
    db.execute("DELETE FROM mmwss.finding_rules WHERE id = %s", (rule_id,))


# ───── asset criticality ─────


def list_asset_criticality() -> list[dict]:
    return db.fetch_all(
        """
        SELECT z.id AS zone_id, z.name AS zone_name,
               COALESCE(a.criticality_multiplier, 1.0) AS criticality_multiplier,
               a.notes, a.updated_at,
               u.email AS updated_by_email
          FROM mmwss.zones z
          LEFT JOIN mmwss.asset_criticality a ON a.zone_id = z.id
          LEFT JOIN mmwss.users u             ON u.id = a.updated_by_user_id
         WHERE z.status = 'active'
         ORDER BY z.name
        """
    )


def upsert_criticality(zone_id: int, multiplier: float, notes: str | None,
                       user_id: int) -> None:
    db.execute(
        """
        INSERT INTO mmwss.asset_criticality
            (zone_id, criticality_multiplier, notes, updated_by_user_id, updated_at)
        VALUES (%s, %s, %s, %s, now())
        ON CONFLICT (zone_id) DO UPDATE SET
            criticality_multiplier = EXCLUDED.criticality_multiplier,
            notes = EXCLUDED.notes,
            updated_by_user_id = EXCLUDED.updated_by_user_id,
            updated_at = now()
        """,
        (zone_id, multiplier, (notes or "").strip() or None, user_id),
    )


# ───── surface hosts ─────


def list_surface_hosts(zone_id: int | None = None) -> list[dict]:
    where = []
    params: list[Any] = []
    if zone_id:
        where.append("h.zone_id = %s"); params.append(zone_id)
    sql = """
        SELECT h.id, h.zone_id, z.name AS zone_name,
               h.host, h.first_seen_at, h.last_seen_at,
               h.last_status, h.last_server, h.last_title, h.active
          FROM mmwss.surface_hosts h
          JOIN mmwss.zones z ON z.id = h.zone_id
    """
    if where:
        sql += " WHERE " + " AND ".join(where)
    sql += " ORDER BY h.active DESC, h.zone_id, h.host"
    return db.fetch_all(sql, tuple(params))
