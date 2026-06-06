"""Scanner findings, runs, rules, and asset-criticality routes."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from .. import auth, queries, scanners, vapt

router = APIRouter()
templates: Jinja2Templates = None  # type: ignore


def _client_ip(request: Request) -> str | None:
    fwd = request.headers.get("x-forwarded-for")
    if fwd:
        return fwd.split(",")[0].strip()
    return request.client.host if request.client else None


# ───── overview ─────


@router.get("/scanners", response_class=HTMLResponse)
def scanners_home(
    request: Request,
    user: dict = Depends(auth.require_user),
    scanner: str | None = None,
    status: str | None = None,
    severity: str | None = None,
):
    counters = scanners.scanner_counters()
    scanner_rows = scanners.list_scanners()
    findings = scanners.list_scanner_findings(
        scanner=scanner, status=status, severity=severity, limit=300,
    )
    recent_runs = scanners.list_scan_runs(limit=20)
    return templates.TemplateResponse(
        "scanners_home.html",
        {"request": request, "user": user, "active": "scanners",
         "counters": counters, "scanner_rows": scanner_rows,
         "findings": findings, "recent_runs": recent_runs,
         "scanner_label": scanners.SCANNER_LABEL,
         "sev_label": vapt.SEVERITY_LABEL, "status_label": vapt.STATUS_LABEL,
         "filter_scanner": scanner, "filter_status": status, "filter_severity": severity},
    )


# ───── scan runs ─────


@router.get("/scanners/runs", response_class=HTMLResponse)
def scanner_runs(
    request: Request,
    user: dict = Depends(auth.require_user),
    scanner_id: str | None = None,
    zone_id: str | None = None,
):
    sid = int(scanner_id) if scanner_id and scanner_id.isdigit() else None
    zid = int(zone_id) if zone_id and zone_id.isdigit() else None
    runs = scanners.list_scan_runs(scanner_id=sid, zone_id=zid, limit=200)
    scanner_rows = scanners.list_scanners()
    zones = queries.zones_with_status()
    return templates.TemplateResponse(
        "scanner_runs.html",
        {"request": request, "user": user, "active": "scanners",
         "runs": runs, "scanner_rows": scanner_rows, "zones": zones,
         "filter_scanner_id": sid, "filter_zone_id": zid,
         "scanner_label": scanners.SCANNER_LABEL},
    )


@router.get("/scanners/runs/{run_id}", response_class=HTMLResponse)
def scanner_run_detail(run_id: int, request: Request, user: dict = Depends(auth.require_user)):
    run = scanners.get_scan_run(run_id)
    if not run:
        raise HTTPException(404, "Run not found")
    # Findings that touched this run (either first seen or re-detected)
    findings = scanners.list_scanner_findings(limit=500)
    findings = [f for f in findings if f.get("scan_run_id") == run_id]
    return templates.TemplateResponse(
        "scanner_run_detail.html",
        {"request": request, "user": user, "active": "scanners",
         "run": run, "findings": findings,
         "scanner_label": scanners.SCANNER_LABEL,
         "sev_label": vapt.SEVERITY_LABEL, "status_label": vapt.STATUS_LABEL},
    )


# ───── rules ─────


@router.get("/scanners/rules", response_class=HTMLResponse)
def scanner_rules(request: Request, user: dict = Depends(auth.require_user)):
    rules = scanners.list_rules()
    scanner_rows = scanners.list_scanners()
    zones = queries.zones_with_status()
    return templates.TemplateResponse(
        "scanner_rules.html",
        {"request": request, "user": user, "active": "scanners",
         "rules": rules, "scanner_rows": scanner_rows, "zones": zones,
         "rule_action_label": scanners.RULE_ACTION_LABEL,
         "scanner_label": scanners.SCANNER_LABEL,
         "sev_label": vapt.SEVERITY_LABEL},
    )


@router.post("/scanners/rules/new")
def scanner_rule_create(
    request: Request,
    name: str = Form(...),
    action: str = Form(...),
    action_value: str = Form(""),
    scanner: str = Form(""),
    template_id_pattern: str = Form(""),
    url_pattern: str = Form(""),
    title_pattern: str = Form(""),
    zone_id: str = Form(""),
    severity_in: list[str] = Form(default=[]),
    notes: str = Form(""),
    user: dict = Depends(auth.require_admin),
):
    zid = int(zone_id) if zone_id.strip().isdigit() else None
    sev_list = [s for s in severity_in if s]
    rid = scanners.create_rule(
        name=name, scanner=scanner, template_id_pattern=template_id_pattern,
        url_pattern=url_pattern, title_pattern=title_pattern, zone_id=zid,
        severity_in=sev_list or None, action=action, action_value=action_value,
        notes=notes, created_by_user_id=int(user["id"]),
    )
    auth.record_audit(int(user["id"]), user["email"], "scanner_rule.create",
                      ip=_client_ip(request), target_type="finding_rule", target_id=str(rid),
                      details={"name": name, "action": action})
    return RedirectResponse("/mmwss/scanners/rules", status_code=303)


@router.post("/scanners/rules/{rule_id}/toggle")
def scanner_rule_toggle(
    rule_id: int, request: Request,
    enabled: str = Form("on"),
    user: dict = Depends(auth.require_admin),
):
    new_state = (enabled == "on")
    scanners.toggle_rule(rule_id, new_state)
    auth.record_audit(int(user["id"]), user["email"], "scanner_rule.toggle",
                      ip=_client_ip(request), target_type="finding_rule", target_id=str(rule_id),
                      details={"enabled": new_state})
    return RedirectResponse("/mmwss/scanners/rules", status_code=303)


@router.post("/scanners/rules/{rule_id}/delete")
def scanner_rule_delete(rule_id: int, request: Request,
                       user: dict = Depends(auth.require_admin)):
    scanners.delete_rule(rule_id)
    auth.record_audit(int(user["id"]), user["email"], "scanner_rule.delete",
                      ip=_client_ip(request), target_type="finding_rule", target_id=str(rule_id))
    return RedirectResponse("/mmwss/scanners/rules", status_code=303)


# ───── "create rule from this finding" shortcut ─────


@router.get("/scanners/rules/from-finding/{finding_id}", response_class=HTMLResponse)
def scanner_rule_from_finding(
    finding_id: int, request: Request,
    user: dict = Depends(auth.require_admin),
):
    f = vapt.get_finding(finding_id)
    if not f:
        raise HTTPException(404, "Finding not found")
    return templates.TemplateResponse(
        "scanner_rule_from_finding.html",
        {"request": request, "user": user, "active": "scanners",
         "f": f,
         "rule_action_label": scanners.RULE_ACTION_LABEL,
         "sev_label": vapt.SEVERITY_LABEL},
    )


# ───── asset criticality ─────


@router.get("/scanners/criticality", response_class=HTMLResponse)
def scanner_criticality(request: Request, user: dict = Depends(auth.require_user)):
    rows = scanners.list_asset_criticality()
    return templates.TemplateResponse(
        "scanner_criticality.html",
        {"request": request, "user": user, "active": "scanners", "rows": rows},
    )


@router.post("/scanners/criticality/{zone_id}")
def scanner_criticality_save(
    zone_id: int, request: Request,
    criticality_multiplier: str = Form(...),
    notes: str = Form(""),
    user: dict = Depends(auth.require_admin),
):
    try:
        mult = float(criticality_multiplier)
    except ValueError:
        raise HTTPException(400, "criticality_multiplier must be a number")
    if mult < 0.1 or mult > 5.0:
        raise HTTPException(400, "criticality_multiplier must be between 0.1 and 5.0")
    scanners.upsert_criticality(zone_id, mult, notes, int(user["id"]))
    auth.record_audit(int(user["id"]), user["email"], "scanner_criticality.set",
                      ip=_client_ip(request), target_type="zone", target_id=str(zone_id),
                      details={"multiplier": mult})
    return RedirectResponse("/mmwss/scanners/criticality", status_code=303)


# ───── attack surface ─────


@router.get("/scanners/surface", response_class=HTMLResponse)
def scanner_surface(
    request: Request,
    user: dict = Depends(auth.require_user),
    zone_id: str | None = None,
):
    zid = int(zone_id) if zone_id and zone_id.isdigit() else None
    hosts = scanners.list_surface_hosts(zid)
    zones = queries.zones_with_status()
    return templates.TemplateResponse(
        "scanner_surface.html",
        {"request": request, "user": user, "active": "scanners",
         "hosts": hosts, "zones": zones, "filter_zone_id": zid},
    )
