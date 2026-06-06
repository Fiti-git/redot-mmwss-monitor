"""Change log routes."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from .. import auth, change_log, queries

router = APIRouter()
templates: Jinja2Templates = None  # type: ignore


def _client_ip(request: Request) -> str | None:
    fwd = request.headers.get("x-forwarded-for")
    if fwd:
        return fwd.split(",")[0].strip()
    return request.client.host if request.client else None


@router.get("/change-log", response_class=HTMLResponse)
def change_log_list(
    request: Request,
    user: dict = Depends(auth.require_user),
    category: str | None = None,
    zone_id: str | None = None,
    source: str | None = None,
):
    zid = int(zone_id) if zone_id and zone_id.isdigit() else None
    entries = change_log.list_entries(category=category, zone_id=zid, source=source)
    counters = change_log.counters()
    return templates.TemplateResponse(
        "change_log.html",
        {"request": request, "user": user, "active": "change-log",
         "entries": entries, "counters": counters,
         "category_label": change_log.CATEGORY_LABEL,
         "test_result_label": change_log.TEST_RESULT_LABEL,
         "filter_category": category, "filter_source": source},
    )


@router.get("/change-log/new", response_class=HTMLResponse)
def change_log_new(request: Request, user: dict = Depends(auth.require_user)):
    zones = queries.zones_with_status()
    return templates.TemplateResponse(
        "change_log_new.html",
        {"request": request, "user": user, "active": "change-log",
         "zones": zones, "category_label": change_log.CATEGORY_LABEL},
    )


@router.post("/change-log/new")
def change_log_create(
    request: Request,
    category: str = Form(...),
    title: str = Form(...),
    description: str = Form(""),
    before_state: str = Form(""),
    after_state: str = Form(""),
    test_result: str = Form("not_tested"),
    test_notes: str = Form(""),
    rollback_plan: str = Form(""),
    zone_id: str = Form(""),
    user: dict = Depends(auth.require_user),
):
    zid = int(zone_id) if zone_id.strip().isdigit() else None
    eid = change_log.create_entry(
        category=category, title=title, description=description,
        before_state=before_state, after_state=after_state,
        test_result=test_result, test_notes=test_notes,
        rollback_plan=rollback_plan, zone_id=zid,
        source="manual", engineer_user_id=int(user["id"]),
    )
    auth.record_audit(int(user["id"]), user["email"], "change_log.create",
                      ip=_client_ip(request), target_type="change_log", target_id=str(eid),
                      details={"category": category, "zone_id": zid})
    return RedirectResponse(f"/mmwss/change-log/{eid}", status_code=303)


@router.get("/change-log/{entry_id}", response_class=HTMLResponse)
def change_log_detail(entry_id: int, request: Request, user: dict = Depends(auth.require_user)):
    e = change_log.get_entry(entry_id)
    if not e:
        raise HTTPException(404, "Entry not found")
    return templates.TemplateResponse(
        "change_log_detail.html",
        {"request": request, "user": user, "active": "change-log", "e": e,
         "category_label": change_log.CATEGORY_LABEL,
         "test_result_label": change_log.TEST_RESULT_LABEL},
    )


@router.post("/change-log/{entry_id}/test")
def change_log_set_test(
    entry_id: int, request: Request,
    test_result: str = Form(...),
    test_notes: str = Form(""),
    user: dict = Depends(auth.require_user),
):
    change_log.update_test_result(entry_id, test_result, test_notes)
    auth.record_audit(int(user["id"]), user["email"], "change_log.set_test",
                      ip=_client_ip(request), target_type="change_log", target_id=str(entry_id),
                      details={"test_result": test_result})
    return RedirectResponse(f"/mmwss/change-log/{entry_id}", status_code=303)


@router.post("/change-log/{entry_id}/rollback")
def change_log_set_rollback(
    entry_id: int, request: Request,
    rollback_notes: str = Form(""),
    user: dict = Depends(auth.require_admin),
):
    change_log.mark_rolled_back(entry_id, rollback_notes)
    auth.record_audit(int(user["id"]), user["email"], "change_log.rollback",
                      ip=_client_ip(request), target_type="change_log", target_id=str(entry_id),
                      details={"notes": rollback_notes})
    return RedirectResponse(f"/mmwss/change-log/{entry_id}", status_code=303)
