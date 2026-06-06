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

    fix = fixers.get_fix(req.rule_id)

    # 4. Apply via Cloudflare — dispatch by fix kind
    if fix.kind == "setting":
        snap = db.fetch_one(
            "SELECT id, settings_json FROM mmwss.zone_snapshots WHERE zone_id = %s ORDER BY captured_at DESC LIMIT 1",
            (zone["id"],),
        )
        before = (snap["settings_json"] or {}).get(fix.target) if snap else None
        try:
            result = cf_client.patch_zone_setting(zone["cf_zone_id"], fix.target, fix.value)
        except cf_client.CloudflareApiError as e:
            log.warning("CF fix failed (setting): zone=%s rule=%s err=%s", zone["name"], req.rule_id, e)
            auth.record_audit(int(user["id"]), user["email"], "cf_fix.cf_error", ip=ip,
                              target_type="zone", target_id=str(req.zone_id),
                              details={"rule_id": req.rule_id, "kind": "setting",
                                       "setting": fix.target, "intended_value": fix.value,
                                       "error": str(e)})
            raise HTTPException(502, f"Cloudflare API rejected the change: {e}")
        # Optimistic snapshot update
        if snap:
            db.execute(
                "UPDATE mmwss.zone_snapshots SET settings_json = jsonb_set(settings_json, %s, %s::jsonb) WHERE id = %s",
                ("{" + fix.target + "}", json.dumps(fix.value), snap["id"]),
            )
        auth.record_audit(int(user["id"]), user["email"], "cf_fix.applied", ip=ip,
                          target_type="zone", target_id=str(req.zone_id),
                          details={"rule_id": req.rule_id, "kind": "setting",
                                   "setting": fix.target, "before": before, "after": fix.value,
                                   "cf_result": result})
        log.info("CF fix applied by %s: %s.%s %s -> %s", user["email"], zone["name"],
                 fix.target, before, fix.value)
        return {"success": True, "zone": zone["name"], "kind": "setting",
                "setting": fix.target, "before": before, "after": fix.value}

    elif fix.kind == "block_path":
        description = f"MMWSS auto-fix: block {fix.target} ({req.rule_id})"
        try:
            result = cf_client.add_block_path_rule(zone["cf_zone_id"], fix.target, description)
        except cf_client.CloudflareApiError as e:
            log.warning("CF fix failed (block_path): zone=%s rule=%s err=%s", zone["name"], req.rule_id, e)
            auth.record_audit(int(user["id"]), user["email"], "cf_fix.cf_error", ip=ip,
                              target_type="zone", target_id=str(req.zone_id),
                              details={"rule_id": req.rule_id, "kind": "block_path",
                                       "path": fix.target, "error": str(e)})
            raise HTTPException(502, f"Cloudflare API rejected the change: {e}")
        already = bool(result.get("already_exists"))
        # Bump the firewall counts on the latest snapshot so UI reflects the new rule.
        # (Only if we actually added a new rule.)
        if not already:
            db.execute(
                """
                UPDATE mmwss.zone_snapshots
                SET fw_rules_total = COALESCE(fw_rules_total, 0) + 1,
                    fw_rules_enabled = COALESCE(fw_rules_enabled, 0) + 1
                WHERE id = (SELECT id FROM mmwss.zone_snapshots WHERE zone_id = %s ORDER BY captured_at DESC LIMIT 1)
                """,
                (zone["id"],),
            )
        auth.record_audit(int(user["id"]), user["email"], "cf_fix.applied", ip=ip,
                          target_type="zone", target_id=str(req.zone_id),
                          details={"rule_id": req.rule_id, "kind": "block_path",
                                   "path": fix.target, "already_existed": already,
                                   "cf_result": result})
        log.info("CF firewall rule added by %s: %s block %s%s", user["email"], zone["name"],
                 fix.target, " (already existed)" if already else "")
        return {"success": True, "zone": zone["name"], "kind": "block_path",
                "path": fix.target, "already_existed": already}

    else:
        raise HTTPException(500, f"Unknown fix kind: {fix.kind}")
