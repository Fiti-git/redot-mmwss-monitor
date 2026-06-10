"""Ticket queries + mutations. Thin layer over the raw SQL — the rest of
the app stays in `queries.py` for read endpoints; tickets are state-
changing so they get their own module.
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timedelta, timezone
from typing import Any

from . import db, sla

log = logging.getLogger(__name__)


def list_tickets(
    *,
    status: str | None = None,
    priority: str | None = None,
    zone_id: int | None = None,
    limit: int = 200,
) -> list[dict]:
    where = []
    params: list[Any] = []
    if status:
        where.append("t.status = %s")
        params.append(status)
    if priority:
        where.append("t.priority = %s")
        params.append(priority)
    if zone_id:
        where.append("t.zone_id = %s")
        params.append(zone_id)
    sql = """
        SELECT t.id, t.title, t.priority, t.status, t.category, t.source,
               t.zone_id, z.name AS zone_name,
               t.incident_id,
               t.sla_response_secs, t.sla_resolution_secs,
               t.opened_at, t.response_at, t.resolved_at, t.closed_at,
               t.opened_by_user_id, t.assigned_to_user_id,
               u_open.email AS opened_by_email,
               u_assn.email AS assigned_to_email
        FROM mmwss.tickets t
        LEFT JOIN mmwss.zones z         ON z.id = t.zone_id
        LEFT JOIN mmwss.users u_open    ON u_open.id = t.opened_by_user_id
        LEFT JOIN mmwss.users u_assn    ON u_assn.id = t.assigned_to_user_id
    """
    if where:
        sql += " WHERE " + " AND ".join(where)
    sql += " ORDER BY CASE t.priority WHEN 'p1' THEN 1 WHEN 'p2' THEN 2 WHEN 'p3' THEN 3 ELSE 4 END, t.opened_at DESC LIMIT %s"
    params.append(limit)
    return db.fetch_all(sql, tuple(params))


def get_ticket(ticket_id: int) -> dict | None:
    rows = list_tickets(limit=1)  # placeholder typing, replaced below
    row = db.fetch_one(
        """
        SELECT t.*, z.name AS zone_name,
               u_open.email AS opened_by_email,
               u_assn.email AS assigned_to_email
        FROM mmwss.tickets t
        LEFT JOIN mmwss.zones z         ON z.id = t.zone_id
        LEFT JOIN mmwss.users u_open    ON u_open.id = t.opened_by_user_id
        LEFT JOIN mmwss.users u_assn    ON u_assn.id = t.assigned_to_user_id
        WHERE t.id = %s
        """,
        (ticket_id,),
    )
    return row


def get_events(ticket_id: int) -> list[dict]:
    return db.fetch_all(
        """
        SELECT e.id, e.ts, e.event_type, e.details_json,
               e.user_id, u.email AS user_email
        FROM mmwss.ticket_events e
        LEFT JOIN mmwss.users u ON u.id = e.user_id
        WHERE e.ticket_id = %s
        ORDER BY e.ts ASC
        """,
        (ticket_id,),
    )


def _record_event(ticket_id: int, user_id: int | None, event_type: str, details: dict | None = None) -> None:
    db.execute(
        """
        INSERT INTO mmwss.ticket_events (ticket_id, user_id, event_type, details_json)
        VALUES (%s, %s, %s, %s::jsonb)
        """,
        (ticket_id, user_id, event_type, json.dumps(details) if details else None),
    )


def create_ticket(
    *,
    title: str,
    description: str | None,
    priority: str,
    category: str = "other",
    zone_id: int | None = None,
    incident_id: int | None = None,
    source: str = "manual",
    opened_by_user_id: int | None = None,
) -> int:
    if priority not in sla.TARGETS:
        raise ValueError(f"unknown priority: {priority}")
    resp, resol = sla.TARGETS[priority]
    with db.conn() as c:
        with c.cursor() as cur:
            cur.execute(
                """
                INSERT INTO mmwss.tickets
                    (title, description, priority, category, source,
                     zone_id, incident_id,
                     sla_response_secs, sla_resolution_secs,
                     opened_by_user_id)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                RETURNING id
                """,
                (title.strip(), (description or "").strip() or None,
                 priority, category, source,
                 zone_id, incident_id,
                 resp, resol,
                 opened_by_user_id),
            )
            ticket_id = cur.fetchone()["id"]
            cur.execute(
                """
                INSERT INTO mmwss.ticket_events
                    (ticket_id, user_id, event_type, details_json)
                VALUES (%s, %s, 'created', %s::jsonb)
                """,
                (ticket_id, opened_by_user_id,
                 json.dumps({"priority": priority, "category": category, "source": source})),
            )
        c.commit()

    # Fan-out push for P1 tickets. Best-effort — never let a failed push
    # roll back the ticket. Lazy import so test runs without firebase-admin
    # don't break ticket creation.
    if priority == "p1":
        try:
            from . import fcm
            fcm.send_to_admins(
                kind="p1_ticket",
                title=f"P1 ticket #{ticket_id}",
                body=title.strip()[:160],
                data={"ticket_id": ticket_id, "category": category},
                deep_link=f"/tickets/{ticket_id}",
            )
        except Exception:
            log.exception("Failed to send P1 push for ticket %d", ticket_id)

    return ticket_id


def mark_response(ticket_id: int, user_id: int | None, note: str | None = None) -> None:
    """First operator action acknowledging the ticket (stops the response-time clock)."""
    with db.conn() as c:
        with c.cursor() as cur:
            cur.execute(
                """
                UPDATE mmwss.tickets
                SET response_at = COALESCE(response_at, now()),
                    status = CASE WHEN status = 'open' THEN 'in_progress'::mmwss.ticket_status ELSE status END
                WHERE id = %s
                """,
                (ticket_id,),
            )
            cur.execute(
                "INSERT INTO mmwss.ticket_events (ticket_id, user_id, event_type, details_json) "
                "VALUES (%s, %s, 'responded', %s::jsonb)",
                (ticket_id, user_id, json.dumps({"note": note}) if note else None),
            )
        c.commit()


def mark_resolved(ticket_id: int, user_id: int | None, resolution_notes: str | None = None,
                  rca_text: str | None = None) -> None:
    with db.conn() as c:
        with c.cursor() as cur:
            cur.execute(
                """
                UPDATE mmwss.tickets
                SET resolved_at = COALESCE(resolved_at, now()),
                    response_at = COALESCE(response_at, now()),
                    resolution_notes = COALESCE(%s, resolution_notes),
                    rca_text = COALESCE(%s, rca_text),
                    status = 'resolved'
                WHERE id = %s
                """,
                (resolution_notes, rca_text, ticket_id),
            )
            cur.execute(
                "INSERT INTO mmwss.ticket_events (ticket_id, user_id, event_type, details_json) "
                "VALUES (%s, %s, 'resolved', %s::jsonb)",
                (ticket_id, user_id, json.dumps({
                    "resolution_notes": resolution_notes, "rca_text": rca_text,
                })),
            )
        c.commit()


def reopen_ticket(ticket_id: int, user_id: int | None, reason: str | None = None) -> None:
    with db.conn() as c:
        with c.cursor() as cur:
            cur.execute(
                """
                UPDATE mmwss.tickets
                SET status = 'in_progress', resolved_at = NULL, closed_at = NULL
                WHERE id = %s
                """,
                (ticket_id,),
            )
            cur.execute(
                "INSERT INTO mmwss.ticket_events (ticket_id, user_id, event_type, details_json) "
                "VALUES (%s, %s, 'reopened', %s::jsonb)",
                (ticket_id, user_id, json.dumps({"reason": reason}) if reason else None),
            )
        c.commit()


def close_ticket(ticket_id: int, user_id: int | None) -> None:
    with db.conn() as c:
        with c.cursor() as cur:
            cur.execute(
                """
                UPDATE mmwss.tickets
                SET status = 'closed',
                    closed_at = COALESCE(closed_at, now()),
                    resolved_at = COALESCE(resolved_at, now()),
                    response_at = COALESCE(response_at, now())
                WHERE id = %s
                """,
                (ticket_id,),
            )
            cur.execute(
                "INSERT INTO mmwss.ticket_events (ticket_id, user_id, event_type, details_json) "
                "VALUES (%s, %s, 'closed', NULL)",
                (ticket_id, user_id),
            )
        c.commit()


def add_comment(ticket_id: int, user_id: int | None, body: str) -> None:
    db.execute(
        "INSERT INTO mmwss.ticket_events (ticket_id, user_id, event_type, details_json) "
        "VALUES (%s, %s, 'comment', %s::jsonb)",
        (ticket_id, user_id, json.dumps({"body": body})),
    )


# ───────── SLA calculations (computed at read time) ─────────


def compute_sla_state(ticket: dict, now: datetime | None = None) -> dict:
    """Return {response_state, resolution_state, response_elapsed_s,
    resolution_elapsed_s, response_breach_at, resolution_breach_at}.

    State values: 'met' | 'pending' | 'breached'."""
    now = (now or datetime.now(timezone.utc))
    opened: datetime = ticket["opened_at"]
    resp: datetime | None = ticket.get("response_at")
    resol: datetime | None = ticket.get("resolved_at")
    rs: int = ticket["sla_response_secs"]
    rls: int = ticket["sla_resolution_secs"]

    response_breach_at = opened + timedelta(seconds=rs)
    resolution_breach_at = opened + timedelta(seconds=rls)

    if resp is not None:
        response_elapsed_s = int((resp - opened).total_seconds())
        response_state = "met" if response_elapsed_s <= rs else "breached"
    else:
        response_elapsed_s = int((now - opened).total_seconds())
        response_state = "breached" if response_elapsed_s > rs else "pending"

    if resol is not None:
        resolution_elapsed_s = int((resol - opened).total_seconds())
        resolution_state = "met" if resolution_elapsed_s <= rls else "breached"
    else:
        resolution_elapsed_s = int((now - opened).total_seconds())
        resolution_state = "breached" if resolution_elapsed_s > rls else "pending"

    return {
        "response_state": response_state,
        "response_elapsed_s": response_elapsed_s,
        "response_breach_at": response_breach_at,
        "resolution_state": resolution_state,
        "resolution_elapsed_s": resolution_elapsed_s,
        "resolution_breach_at": resolution_breach_at,
    }


# ───────── aggregates for the dashboard / monthly report ─────────


def queue_counters() -> dict:
    """Used by sidebar badge + dashboard tiles."""
    rows = db.fetch_all(
        "SELECT priority, status, COUNT(*)::int AS n FROM mmwss.tickets GROUP BY priority, status"
    )
    out = {"open_total": 0, "by_priority": {"p1": 0, "p2": 0, "p3": 0, "p4": 0}}
    for r in rows:
        if r["status"] in ("open", "in_progress"):
            out["open_total"] += r["n"]
            out["by_priority"][r["priority"]] = out["by_priority"].get(r["priority"], 0) + r["n"]
    return out


def sla_summary_for_period(period_start: datetime, period_end: datetime) -> dict:
    """Compliance report for the monthly deliverable.
    A ticket counts toward the period if opened_at falls within it."""
    rows = db.fetch_all(
        """
        SELECT priority, sla_response_secs, sla_resolution_secs,
               opened_at, response_at, resolved_at
        FROM mmwss.tickets
        WHERE opened_at >= %s AND opened_at < %s
        """,
        (period_start, period_end),
    )
    out: dict[str, dict[str, int]] = {p: {"total": 0, "response_met": 0, "resolution_met": 0,
                                          "response_breached": 0, "resolution_breached": 0,
                                          "still_open": 0}
                                      for p in ("p1", "p2", "p3", "p4")}
    for r in rows:
        p = r["priority"]
        if p not in out:
            continue
        out[p]["total"] += 1
        if r["response_at"]:
            elapsed = (r["response_at"] - r["opened_at"]).total_seconds()
            if elapsed <= r["sla_response_secs"]:
                out[p]["response_met"] += 1
            else:
                out[p]["response_breached"] += 1
        if r["resolved_at"]:
            elapsed = (r["resolved_at"] - r["opened_at"]).total_seconds()
            if elapsed <= r["sla_resolution_secs"]:
                out[p]["resolution_met"] += 1
            else:
                out[p]["resolution_breached"] += 1
        else:
            out[p]["still_open"] += 1
    return out
