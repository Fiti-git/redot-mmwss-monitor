"""Ticket queue, detail, create, and state-change routes."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from .. import auth, queries, sla, tickets

router = APIRouter()
templates: Jinja2Templates = None  # type: ignore  set in main


def _client_ip(request: Request) -> str | None:
    fwd = request.headers.get("x-forwarded-for")
    if fwd:
        return fwd.split(",")[0].strip()
    return request.client.host if request.client else None


@router.get("/tickets", response_class=HTMLResponse)
def tickets_list(
    request: Request,
    user: dict = Depends(auth.require_user),
    status: str | None = None,
    priority: str | None = None,
):
    rows = tickets.list_tickets(status=status, priority=priority)
    # Compute SLA state for each row
    enriched = []
    for r in rows:
        r["sla"] = tickets.compute_sla_state(r)
        enriched.append(r)
    counters = tickets.queue_counters()
    return templates.TemplateResponse(
        "tickets.html",
        {
            "request": request, "user": user, "active": "tickets",
            "tickets": enriched, "counters": counters,
            "filter_status": status, "filter_priority": priority,
            "sla_labels": sla.LABEL,
            "sla_examples": sla.EXAMPLE,
        },
    )


@router.get("/tickets/new", response_class=HTMLResponse)
def ticket_new(request: Request, user: dict = Depends(auth.require_user)):
    zones = queries.zones_with_status()
    return templates.TemplateResponse(
        "ticket_new.html",
        {"request": request, "user": user, "active": "tickets",
         "zones": zones, "sla_labels": sla.LABEL, "sla_examples": sla.EXAMPLE},
    )


@router.post("/tickets/new")
def ticket_create(
    request: Request,
    title: str = Form(...),
    description: str = Form(""),
    priority: str = Form(...),
    category: str = Form("other"),
    zone_id: str = Form(""),
    user: dict = Depends(auth.require_user),
):
    if priority not in sla.TARGETS:
        raise HTTPException(400, "invalid priority")
    zid = int(zone_id) if zone_id.strip().isdigit() else None
    tid = tickets.create_ticket(
        title=title, description=description, priority=priority,
        category=category, zone_id=zid, source="manual",
        opened_by_user_id=int(user["id"]),
    )
    auth.record_audit(int(user["id"]), user["email"], "ticket.create",
                      ip=_client_ip(request), target_type="ticket", target_id=str(tid),
                      details={"priority": priority, "category": category, "zone_id": zid})
    return RedirectResponse(f"/mmwss/tickets/{tid}", status_code=303)


@router.get("/tickets/{ticket_id}", response_class=HTMLResponse)
def ticket_detail(ticket_id: int, request: Request, user: dict = Depends(auth.require_user)):
    t = tickets.get_ticket(ticket_id)
    if not t:
        raise HTTPException(404, "Ticket not found")
    t["sla"] = tickets.compute_sla_state(t)
    events = tickets.get_events(ticket_id)
    return templates.TemplateResponse(
        "ticket_detail.html",
        {"request": request, "user": user, "active": "tickets",
         "t": t, "events": events,
         "sla_labels": sla.LABEL,
         "secs_to_human": sla.secs_to_human},
    )


@router.post("/tickets/{ticket_id}/respond")
def ticket_respond(
    ticket_id: int, request: Request,
    note: str = Form(""),
    user: dict = Depends(auth.require_user),
):
    tickets.mark_response(ticket_id, int(user["id"]), note=note or None)
    auth.record_audit(int(user["id"]), user["email"], "ticket.respond",
                      ip=_client_ip(request), target_type="ticket", target_id=str(ticket_id))
    return RedirectResponse(f"/mmwss/tickets/{ticket_id}", status_code=303)


@router.post("/tickets/{ticket_id}/resolve")
def ticket_resolve(
    ticket_id: int, request: Request,
    resolution_notes: str = Form(""),
    rca_text: str = Form(""),
    user: dict = Depends(auth.require_user),
):
    tickets.mark_resolved(ticket_id, int(user["id"]),
                          resolution_notes=resolution_notes or None,
                          rca_text=rca_text or None)
    auth.record_audit(int(user["id"]), user["email"], "ticket.resolve",
                      ip=_client_ip(request), target_type="ticket", target_id=str(ticket_id),
                      details={"resolution_notes": resolution_notes, "rca": rca_text})
    return RedirectResponse(f"/mmwss/tickets/{ticket_id}", status_code=303)


@router.post("/tickets/{ticket_id}/reopen")
def ticket_reopen(
    ticket_id: int, request: Request,
    reason: str = Form(""),
    user: dict = Depends(auth.require_user),
):
    tickets.reopen_ticket(ticket_id, int(user["id"]), reason=reason or None)
    auth.record_audit(int(user["id"]), user["email"], "ticket.reopen",
                      ip=_client_ip(request), target_type="ticket", target_id=str(ticket_id),
                      details={"reason": reason})
    return RedirectResponse(f"/mmwss/tickets/{ticket_id}", status_code=303)


@router.post("/tickets/{ticket_id}/close")
def ticket_close(ticket_id: int, request: Request, user: dict = Depends(auth.require_user)):
    tickets.close_ticket(ticket_id, int(user["id"]))
    auth.record_audit(int(user["id"]), user["email"], "ticket.close",
                      ip=_client_ip(request), target_type="ticket", target_id=str(ticket_id))
    return RedirectResponse(f"/mmwss/tickets/{ticket_id}", status_code=303)


@router.post("/tickets/{ticket_id}/comment")
def ticket_comment(
    ticket_id: int, request: Request,
    body: str = Form(...),
    user: dict = Depends(auth.require_user),
):
    tickets.add_comment(ticket_id, int(user["id"]), body)
    return RedirectResponse(f"/mmwss/tickets/{ticket_id}", status_code=303)
