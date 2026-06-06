"""Patch + change log queries and mutations.

This is the single source of truth for "what changed, when, by whom" across
the whole MMWSS estate. Used by:
- The monthly report (rolled up by category)
- The platform's own one-click fix path (auto-records cf_setting and
  cf_firewall_rule changes)
- VAPT remediation flow (auto-records vapt_remediation entries when a
  finding transitions to 'remediated')
- Manual entries by engineers for everything else (plugin updates,
  WordPress core, theme changes, server config, custom code, etc.)
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from . import db


CATEGORY_LABEL: dict[str, str] = {
    "plugin_update":      "Plugin update",
    "core_update":        "WordPress core",
    "theme_update":       "Theme update",
    "cf_setting":         "Cloudflare setting",
    "cf_firewall_rule":   "CF firewall rule",
    "cf_dns":             "CF DNS",
    "ssl_renewal":        "SSL renewal",
    "server_config":      "Server config",
    "database_change":    "Database change",
    "custom_code":        "Custom code",
    "vapt_remediation":   "VAPT remediation",
    "other":              "Other",
}

TEST_RESULT_LABEL: dict[str, str] = {
    "passed":     "Passed",
    "failed":     "Failed",
    "not_tested": "Not tested",
}


def create_entry(
    *,
    category: str,
    title: str,
    description: str | None = None,
    before_state: str | None = None,
    after_state: str | None = None,
    test_result: str = "not_tested",
    test_notes: str | None = None,
    rollback_plan: str | None = None,
    zone_id: int | None = None,
    ticket_id: int | None = None,
    vapt_finding_id: int | None = None,
    source: str = "manual",
    engineer_user_id: int | None = None,
    executed_at: datetime | None = None,
) -> int:
    if category not in CATEGORY_LABEL:
        raise ValueError(f"unknown category: {category}")
    if test_result not in TEST_RESULT_LABEL:
        raise ValueError(f"unknown test_result: {test_result}")
    row = db.fetch_one(
        """
        INSERT INTO mmwss.change_log
            (category, title, description, before_state, after_state,
             test_result, test_notes, rollback_plan,
             zone_id, ticket_id, vapt_finding_id,
             source, engineer_user_id, executed_at)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, COALESCE(%s, now()))
        RETURNING id
        """,
        (category, title.strip(), (description or "").strip() or None,
         (before_state or "").strip() or None, (after_state or "").strip() or None,
         test_result, (test_notes or "").strip() or None,
         (rollback_plan or "").strip() or None,
         zone_id, ticket_id, vapt_finding_id,
         source, engineer_user_id, executed_at),
    )
    return row["id"]


def list_entries(
    *,
    category: str | None = None,
    zone_id: int | None = None,
    source: str | None = None,
    since: datetime | None = None,
    until: datetime | None = None,
    rolled_back: bool | None = None,
    limit: int = 200,
) -> list[dict]:
    where = []
    params: list[Any] = []
    if category:
        where.append("c.category = %s"); params.append(category)
    if zone_id:
        where.append("c.zone_id = %s"); params.append(zone_id)
    if source:
        where.append("c.source = %s"); params.append(source)
    if since:
        where.append("c.executed_at >= %s"); params.append(since)
    if until:
        where.append("c.executed_at < %s"); params.append(until)
    if rolled_back is not None:
        where.append("c.rolled_back = %s"); params.append(rolled_back)
    sql = """
        SELECT c.id, c.category, c.title, c.description,
               c.before_state, c.after_state,
               c.test_result, c.test_notes,
               c.rollback_plan, c.rolled_back, c.rollback_notes, c.rolled_back_at,
               c.zone_id, z.name AS zone_name,
               c.ticket_id, c.vapt_finding_id,
               c.source, c.engineer_user_id, u.email AS engineer_email,
               c.executed_at, c.created_at
        FROM mmwss.change_log c
        LEFT JOIN mmwss.zones z ON z.id = c.zone_id
        LEFT JOIN mmwss.users u ON u.id = c.engineer_user_id
    """
    if where:
        sql += " WHERE " + " AND ".join(where)
    sql += " ORDER BY c.executed_at DESC LIMIT %s"
    params.append(limit)
    return db.fetch_all(sql, tuple(params))


def get_entry(entry_id: int) -> dict | None:
    return db.fetch_one(
        """
        SELECT c.*, z.name AS zone_name, u.email AS engineer_email,
               t.title AS ticket_title, t.priority AS ticket_priority,
               t.status AS ticket_status,
               vf.title AS vapt_title, vf.severity AS vapt_severity
        FROM mmwss.change_log c
        LEFT JOIN mmwss.zones z         ON z.id = c.zone_id
        LEFT JOIN mmwss.users u         ON u.id = c.engineer_user_id
        LEFT JOIN mmwss.tickets t       ON t.id = c.ticket_id
        LEFT JOIN mmwss.vapt_findings vf ON vf.id = c.vapt_finding_id
        WHERE c.id = %s
        """,
        (entry_id,),
    )


def update_test_result(entry_id: int, test_result: str, test_notes: str | None) -> None:
    if test_result not in TEST_RESULT_LABEL:
        raise ValueError(test_result)
    db.execute(
        "UPDATE mmwss.change_log SET test_result = %s, test_notes = COALESCE(%s, test_notes) WHERE id = %s",
        (test_result, (test_notes or "").strip() or None, entry_id),
    )


def mark_rolled_back(entry_id: int, notes: str | None) -> None:
    db.execute(
        """
        UPDATE mmwss.change_log
        SET rolled_back = TRUE,
            rollback_notes = COALESCE(%s, rollback_notes),
            rolled_back_at = COALESCE(rolled_back_at, now())
        WHERE id = %s
        """,
        ((notes or "").strip() or None, entry_id),
    )


def counters() -> dict:
    """For the home page tile strip + sidebar badge."""
    r = db.fetch_one(
        """
        SELECT
            (SELECT COUNT(*)::int FROM mmwss.change_log) AS total,
            (SELECT COUNT(*)::int FROM mmwss.change_log WHERE executed_at >= now() - interval '30 days') AS last_30d,
            (SELECT COUNT(*)::int FROM mmwss.change_log WHERE test_result = 'not_tested' AND rolled_back = FALSE AND executed_at >= now() - interval '90 days') AS untested,
            (SELECT COUNT(*)::int FROM mmwss.change_log WHERE rolled_back = TRUE AND rolled_back_at >= now() - interval '90 days') AS rolled_back_recent,
            (SELECT COUNT(*)::int FROM mmwss.change_log WHERE source = 'auto_cf_fix'        AND executed_at >= now() - interval '30 days') AS auto_cf_30d,
            (SELECT COUNT(*)::int FROM mmwss.change_log WHERE source = 'auto_vapt_remediation' AND executed_at >= now() - interval '30 days') AS auto_vapt_30d
        """
    )
    return r or {}
