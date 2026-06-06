"""Auto-resolution queue routes."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from .. import auth, auto_fix, queries

router = APIRouter()
templates: Jinja2Templates = None  # type: ignore


def _client_ip(request: Request) -> str | None:
    fwd = request.headers.get("x-forwarded-for")
    if fwd:
        return fwd.split(",")[0].strip()
    return request.client.host if request.client else None


@router.get("/scanners/auto-fix", response_class=HTMLResponse)
def auto_fix_home(
    request: Request,
    user: dict = Depends(auth.require_user),
    status: str | None = None,
    zone_id: str | None = None,
):
    zid = int(zone_id) if zone_id and zone_id.isdigit() else None
    proposals = auto_fix.list_proposals(status=status, zone_id=zid)
    counters = auto_fix.counters()
    zones = queries.zones_with_status()
    zone_settings = auto_fix.list_zone_settings()
    return templates.TemplateResponse(
        "auto_fix.html",
        {"request": request, "user": user, "active": "scanners",
         "proposals": proposals, "counters": counters, "zones": zones,
         "zone_settings": zone_settings,
         "filter_status": status, "filter_zone_id": zid},
    )


@router.post("/scanners/auto-fix/{proposal_id}/apply")
def auto_fix_apply(proposal_id: int, request: Request,
                   user: dict = Depends(auth.require_admin)):
    result = auto_fix.apply_proposal(proposal_id, int(user["id"]))
    auth.record_audit(int(user["id"]), user["email"], "auto_fix.apply",
                      ip=_client_ip(request), target_type="auto_fix_proposal",
                      target_id=str(proposal_id),
                      details={"ok": result.get("ok"),
                               "error": result.get("error"),
                               "change_log_id": result.get("change_log_id")})
    return RedirectResponse("/mmwss/scanners/auto-fix", status_code=303)


@router.post("/scanners/auto-fix/{proposal_id}/reject")
def auto_fix_reject(proposal_id: int, request: Request,
                    reason: str = Form(""),
                    user: dict = Depends(auth.require_admin)):
    auto_fix.reject_proposal(proposal_id, reason, int(user["id"]))
    auth.record_audit(int(user["id"]), user["email"], "auto_fix.reject",
                      ip=_client_ip(request), target_type="auto_fix_proposal",
                      target_id=str(proposal_id),
                      details={"reason": reason})
    return RedirectResponse("/mmwss/scanners/auto-fix", status_code=303)


@router.post("/scanners/auto-fix/apply-batch")
def auto_fix_apply_batch(request: Request,
                          proposal_ids: list[int] = Form(default=[]),
                          user: dict = Depends(auth.require_admin)):
    results = []
    for pid in proposal_ids:
        r = auto_fix.apply_proposal(pid, int(user["id"]))
        results.append({"id": pid, **r})
    auth.record_audit(int(user["id"]), user["email"], "auto_fix.apply_batch",
                      ip=_client_ip(request), target_type="auto_fix_proposal",
                      target_id=",".join(str(p) for p in proposal_ids),
                      details={"count": len(proposal_ids),
                               "ok": sum(1 for r in results if r.get("ok")),
                               "failed": sum(1 for r in results if not r.get("ok"))})
    return RedirectResponse("/mmwss/scanners/auto-fix", status_code=303)


@router.post("/scanners/auto-fix/zone/{zone_id}")
def auto_fix_zone_toggle(zone_id: int, request: Request,
                          enabled: str = Form("off"),
                          user: dict = Depends(auth.require_admin)):
    new_state = (enabled == "on")
    auto_fix.set_zone_enabled(zone_id, new_state, int(user["id"]))
    auth.record_audit(int(user["id"]), user["email"], "auto_fix.zone_toggle",
                      ip=_client_ip(request), target_type="zone", target_id=str(zone_id),
                      details={"enabled": new_state})
    # If enabling, backfill proposals for that zone's existing open findings
    if new_state:
        auto_fix.generate_proposals_for_open_findings()
    return RedirectResponse("/mmwss/scanners/auto-fix", status_code=303)


@router.post("/scanners/auto-fix/regenerate")
def auto_fix_regenerate(request: Request,
                         user: dict = Depends(auth.require_admin)):
    created = auto_fix.generate_proposals_for_open_findings()
    auth.record_audit(int(user["id"]), user["email"], "auto_fix.regenerate",
                      ip=_client_ip(request), target_type="auto_fix_proposal",
                      target_id="batch", details={"created": created})
    return RedirectResponse("/mmwss/scanners/auto-fix", status_code=303)
