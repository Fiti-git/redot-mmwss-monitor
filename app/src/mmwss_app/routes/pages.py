from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import FileResponse, HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from .. import auth, db, fixers, queries

router = APIRouter()
templates: Jinja2Templates = None  # type: ignore  set in main


@router.get("/dashboard", response_class=HTMLResponse)
def dashboard(request: Request, user: dict = Depends(auth.require_user)):
    stats = queries.overview_stats()
    zones = queries.zones_scored()
    traffic = queries.overview_traffic_24h()
    uptime = queries.overview_uptime_24h()
    security = queries.aggregate_security_score()
    return templates.TemplateResponse(
        "dashboard.html",
        {"request": request, "user": user, "stats": stats, "zones": zones,
         "traffic": traffic, "uptime": uptime, "security": security, "active": "dashboard"},
    )


@router.get("/recommendations", response_class=HTMLResponse)
def recommendations_page(request: Request, user: dict = Depends(auth.require_user)):
    items = queries.all_recommendations()
    sec = queries.aggregate_security_score()
    by_sev = {"critical": [], "warning": [], "info": []}
    for r in items:
        by_sev.setdefault(r["severity"], []).append(r)
    return templates.TemplateResponse(
        "recommendations.html",
        {"request": request, "user": user, "items": items, "by_sev": by_sev,
         "security": sec, "active": "recommendations",
         "fixable_rules": fixers.human_titles_map()},
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
    recs = queries.zone_recommendations(zone_id)
    wp = queries.latest_wp_check(zone_id)
    return templates.TemplateResponse(
        "zone_detail.html",
        {
            "request": request, "user": user, "active": "zones",
            "zone": zone, "snapshot": snapshot, "dns_records": dns_records,
            "uptime": uptime, "traffic": traffic, "uptime_sum": uptime_sum,
            "incidents": incidents, "recommendations": recs, "wp": wp,
        },
    )


@router.get("/incidents", response_class=HTMLResponse)
def incidents(request: Request, user: dict = Depends(auth.require_user)):
    rows = queries.recent_incidents(limit=200)
    return templates.TemplateResponse(
        "incidents.html",
        {"request": request, "user": user, "incidents": rows, "active": "incidents"},
    )


@router.get("/trends", response_class=HTMLResponse)
def trends_page(request: Request, user: dict = Depends(auth.require_user),
                days: int = 30):
    if days not in (7, 30, 90):
        days = 30
    totals = queries.period_totals(days)
    daily = queries.analytics_daily(days)
    uptime_d = queries.uptime_daily(days)
    top_threats = queries.top_sites_by_threats(days)
    top_traffic = queries.top_sites_by_traffic(days)

    # Group daily uptime: {zone_name: [{day, pct}, ...]}
    per_zone: dict[str, list[dict]] = {}
    for r in uptime_d:
        if r["total"]:
            per_zone.setdefault(r["zone_name"], []).append({
                "day": r["day"].isoformat(),
                "pct": (r["ok"] / r["total"] * 100),
            })

    return templates.TemplateResponse(
        "trends.html",
        {
            "request": request, "user": user, "active": "trends",
            "days": days, "totals": totals,
            "daily": [{"day": r["day"].isoformat(),
                       "requests": int(r["requests"]),
                       "cached": int(r["cached"]),
                       "bytes": int(r["bytes"]),
                       "threats": int(r["threats"])} for r in daily],
            "uptime_per_zone": per_zone,
            "top_threats": [{"name": r["name"], "threats": int(r["threats"])} for r in top_threats],
            "top_traffic": [{"name": r["name"], "requests": int(r["requests"]),
                              "bytes": int(r["bytes"])} for r in top_traffic],
        },
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


REPORTS_ROOT = Path("/app/reports")


def _serve_report(report_id: int, fmt: str, user: dict):
    """Common path: validate id, fetch row, increment counter, serve file."""
    r = db.fetch_one(
        "SELECT id, html_path, pdf_path, type, period_start FROM mmwss.reports WHERE id = %s",
        (report_id,),
    )
    if not r:
        raise HTTPException(404, "Report not found")
    path = r["html_path"] if fmt == "html" else r["pdf_path"]
    if not path:
        raise HTTPException(404, f"{fmt.upper()} not available for this report")
    p = Path(path)
    # Defense in depth — never serve outside REPORTS_ROOT
    try:
        p.relative_to(REPORTS_ROOT)
    except ValueError:
        raise HTTPException(403, "Forbidden")
    if not p.exists():
        raise HTTPException(404, "File missing on disk")
    db.execute("UPDATE mmwss.reports SET downloaded_count = downloaded_count + 1 WHERE id = %s", (report_id,))
    period = r["period_start"].strftime("%Y-%m-%d")
    download_name = f"mmwss-{r['type']}-{period}.{fmt}"
    media = "text/html" if fmt == "html" else "application/pdf"
    return FileResponse(str(p), media_type=media, filename=download_name)


@router.get("/reports/{report_id}/html")
def report_html(report_id: int, user: dict = Depends(auth.require_user)):
    return _serve_report(report_id, "html", user)


@router.get("/reports/{report_id}/pdf")
def report_pdf(report_id: int, user: dict = Depends(auth.require_user)):
    return _serve_report(report_id, "pdf", user)


@router.get("/settings", response_class=HTMLResponse)
def settings_page(request: Request, user: dict = Depends(auth.require_admin)):
    users = queries.list_users()
    tokens = queries.list_cf_tokens()
    return templates.TemplateResponse(
        "settings.html",
        {"request": request, "user": user, "users": users, "tokens": tokens, "active": "settings"},
    )
