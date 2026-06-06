"""JSON endpoints (no HTML). Currently: one-click fix application."""
from __future__ import annotations

import json
import logging

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel

from .. import auth, cf_client, db, fixers

log = logging.getLogger(__name__)

router = APIRouter()


class FixRequest(BaseModel):
    zone_id: int
    rule_id: str
    password: str


def _client_ip(request: Request) -> str | None:
    fwd = request.headers.get("x-forwarded-for")
    if fwd:
        return fwd.split(",")[0].strip()
    return request.client.host if request.client else None


@router.post("/api/fix")
def apply_fix(req: FixRequest, request: Request, user: dict = Depends(auth.require_admin)):
    ip = _client_ip(request)

    # 1. Re-verify password (sensitive action — never trust the session alone)
    db_user = db.fetch_one(
        "SELECT password_hash FROM mmwss.users WHERE id = %s AND is_active = TRUE",
        (int(user["id"]),),
    )
    if not db_user or not auth.verify_password(req.password, db_user["password_hash"]):
        auth.record_audit(int(user["id"]), user["email"], "cf_fix.auth_failed", ip=ip,
                          target_type="zone", target_id=str(req.zone_id),
                          details={"rule_id": req.rule_id})
        raise HTTPException(401, "Password incorrect.")

    # 2. Validate rule
    if not fixers.is_fixable(req.rule_id):
        raise HTTPException(400, f"Rule '{req.rule_id}' is not auto-fixable.")

    # 3. Resolve zone
    zone = db.fetch_one(
        "SELECT id, cf_zone_id, name FROM mmwss.zones WHERE id = %s AND status = 'active'",
        (req.zone_id,),
    )
    if not zone:
        raise HTTPException(404, "Zone not found or inactive.")

    setting_id, new_value = fixers.setting_change(req.rule_id)

    # 4. Capture the "before" value for the audit log
    snap = db.fetch_one(
        "SELECT id, settings_json FROM mmwss.zone_snapshots WHERE zone_id = %s ORDER BY captured_at DESC LIMIT 1",
        (zone["id"],),
    )
    before = (snap["settings_json"] if snap else {}) .get(setting_id) if snap else None

    # 5. Apply via Cloudflare API
    try:
        result = cf_client.patch_zone_setting(zone["cf_zone_id"], setting_id, new_value)
    except cf_client.CloudflareApiError as e:
        log.warning("CF fix failed: zone=%s rule=%s err=%s", zone["name"], req.rule_id, e)
        auth.record_audit(int(user["id"]), user["email"], "cf_fix.cf_error", ip=ip,
                          target_type="zone", target_id=str(req.zone_id),
                          details={"rule_id": req.rule_id, "setting": setting_id,
                                   "intended_value": new_value, "error": str(e)})
        raise HTTPException(502, f"Cloudflare API rejected the change: {e}")

    # 6. Optimistically reflect the new value in the latest snapshot so the
    #    UI updates immediately. Next 6-hourly snapshot will reconcile with
    #    Cloudflare's actual state.
    if snap:
        db.execute(
            "UPDATE mmwss.zone_snapshots SET settings_json = jsonb_set(settings_json, %s, %s::jsonb) WHERE id = %s",
            ("{" + setting_id + "}", json.dumps(new_value), snap["id"]),
        )

    # 7. Audit
    auth.record_audit(int(user["id"]), user["email"], "cf_fix.applied", ip=ip,
                      target_type="zone", target_id=str(req.zone_id),
                      details={"rule_id": req.rule_id, "setting": setting_id,
                               "before": before, "after": new_value,
                               "cf_result": result})

    log.info("CF fix applied by %s: %s.%s %s -> %s", user["email"], zone["name"],
             setting_id, before, new_value)
    return {
        "success": True,
        "zone": zone["name"],
        "setting": setting_id,
        "before": before,
        "after": new_value,
    }
