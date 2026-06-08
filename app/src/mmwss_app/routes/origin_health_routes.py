"""Origin server health page — Lightsail instances + live metrics."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from .. import auth, lightsail

router = APIRouter()
templates: Jinja2Templates = None  # type: ignore


@router.get("/origin-health", response_class=HTMLResponse)
def origin_health(request: Request, user: dict = Depends(auth.require_user)):
    instances = lightsail.list_instances()
    counters = lightsail.counters()
    # Enrich each row with bundle verdict for the badge
    for inst in instances:
        label, verdict = lightsail.bundle_label(inst.get("bundle_id"))
        inst["bundle_label"] = label
        inst["bundle_verdict"] = verdict
    return templates.TemplateResponse(
        "origin_health.html",
        {"request": request, "user": user, "active": "origin-health",
         "instances": instances, "counters": counters},
    )


@router.get("/origin-health/{instance_id}", response_class=HTMLResponse)
def origin_health_detail(instance_id: int, request: Request,
                         user: dict = Depends(auth.require_user)):
    instances = [i for i in lightsail.list_instances() if i["id"] == instance_id]
    if not instances:
        raise HTTPException(404, "Instance not found")
    inst = instances[0]
    label, verdict = lightsail.bundle_label(inst.get("bundle_id"))
    inst["bundle_label"] = label
    inst["bundle_verdict"] = verdict
    history = lightsail.metrics_history(instance_id, hours_back=24)
    return templates.TemplateResponse(
        "origin_health_detail.html",
        {"request": request, "user": user, "active": "origin-health",
         "inst": inst, "history": history},
    )
