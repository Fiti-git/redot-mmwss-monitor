from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from .. import auth, queries

router = APIRouter()
templates: Jinja2Templates = None  # type: ignore  set in main


@router.get("/dashboard", response_class=HTMLResponse)
def dashboard(request: Request, user: dict = Depends(auth.require_user)):
    stats = queries.overview_stats()
    zones = queries.zones_with_status()
    traffic = queries.overview_traffic_24h()
    uptime = queries.overview_uptime_24h()
    return templates.TemplateResponse(
        "dashboard.html",
        {"request": request, "user": user, "stats": stats, "zones": zones,
         "traffic": traffic, "uptime": uptime, "active": "dashboard"},
    )


@router.get("/zones", response_class=HTMLResponse)
def zones_list(request: Request, user: dict = Depends(auth.require_user)):
    zones = queries.zones_with_status()
    return templates.TemplateResponse(
        "zones.html",
        {"request": request, "user": user, "zones": zones, "active": "zones"},
    )


@router.get("/zones/{zone_id}", response_class=HTMLResponse)
def zone_detail(request: Request, zone_id: int, user: dict = Depends(auth.require_user)):
    zone = queries.zone_by_id(zone_id)
    if not zone:
        raise HTTPException(404, "Zone not found")
    snapshot = queries.zone_latest_snapshot(zone_id)
    dns_records = queries.zone_dns_records(snapshot["id"]) if snapshot else []
    uptime = queries.zone_uptime_recent(zone_id, limit=20)
    traffic = queries.zone_traffic_24h(zone_id)
    uptime_sum = queries.zone_uptime_24h_summary(zone_id)
    incidents = queries.zone_incidents(zone_id, limit=10)
    return templates.TemplateResponse(
        "zone_detail.html",
        {
            "request": request, "user": user, "active": "zones",
            "zone": zone, "snapshot": snapshot, "dns_records": dns_records,
            "uptime": uptime, "traffic": traffic, "uptime_sum": uptime_sum,
            "incidents": incidents,
        },
    )


@router.get("/incidents", response_class=HTMLResponse)
def incidents(request: Request, user: dict = Depends(auth.require_user)):
    rows = queries.recent_incidents(limit=200)
    return templates.TemplateResponse(
        "incidents.html",
        {"request": request, "user": user, "incidents": rows, "active": "incidents"},
    )


@router.get("/uptime", response_class=HTMLResponse)
def uptime_page(request: Request, user: dict = Depends(auth.require_user)):
    summaries = queries.uptime_summary_all()
    return templates.TemplateResponse(
        "uptime.html",
        {"request": request, "user": user, "summaries": summaries, "active": "uptime"},
    )


@router.get("/reports", response_class=HTMLResponse)
def reports(request: Request, user: dict = Depends(auth.require_user)):
    rows = queries.list_reports(limit=50)
    return templates.TemplateResponse(
        "reports.html",
        {"request": request, "user": user, "reports": rows, "active": "reports"},
    )


@router.get("/settings", response_class=HTMLResponse)
def settings_page(request: Request, user: dict = Depends(auth.require_admin)):
    users = queries.list_users()
    tokens = queries.list_cf_tokens()
    return templates.TemplateResponse(
        "settings.html",
        {"request": request, "user": user, "users": users, "tokens": tokens, "active": "settings"},
    )
