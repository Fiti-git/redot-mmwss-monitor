"""Redot Sentinel mobile-app API (v1).

All routes are JSON-only, bearer-token authenticated (except /login and
/2fa/verify which bootstrap the session). Mounted at /mmwss/api/v1.

Auth flow (mirrors web /login but yields a bearer instead of a cookie):
    POST /login           {email,password,device_label?,app_version?}
                          → either 200 with {token, ...} (no 2FA on account),
                            or 200 with {pending_2fa_token, "2fa_required":true}
    POST /2fa/verify      {pending_2fa_token, code}
                          → 200 with {token, ...}

After login the app stores the bearer in flutter_secure_storage and sends
it as Authorization: Bearer <token> on every subsequent call.

Push subscribe flow:
    Phone obtains its FCM token, posts to /push/subscribe with token +
    device_label. We upsert into mmwss.push_subscriptions keyed on
    fcm_token (UNIQUE) so re-subscribing replaces the row owner.
"""
from __future__ import annotations

import secrets
import time
from datetime import datetime, timezone

from fastapi import APIRouter, Body, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from .. import auth, db, fcm, mobile_auth, queries, security, tickets, vapt

router = APIRouter()


# ─── Pending-2FA tokens ───
# After password-verify but before TOTP, we mint a short-lived (5 min) opaque
# token. It's NOT a session — it only proves "password is correct, here's
# which user is mid-login". Stored in-memory because the volume is tiny and
# we don't need it to survive restarts (user just re-enters password).
_PENDING_2FA: dict[str, tuple[int, float]] = {}
_PENDING_2FA_TTL = 5 * 60


def _gc_pending() -> None:
    now = time.time()
    expired = [k for k, (_, ts) in _PENDING_2FA.items() if now - ts > _PENDING_2FA_TTL]
    for k in expired:
        _PENDING_2FA.pop(k, None)


def _client_ip(request: Request) -> str | None:
    fwd = request.headers.get("x-forwarded-for")
    if fwd:
        return fwd.split(",")[0].strip()
    return request.client.host if request.client else None


# ─────────── Login + 2FA ───────────


class LoginIn(BaseModel):
    email: str = Field(..., min_length=3, max_length=254)
    password: str = Field(..., min_length=1)
    device_label: str | None = Field(None, max_length=120)
    app_version: str | None = Field(None, max_length=40)


class LoginOut(BaseModel):
    token: str | None = None
    expires_at: datetime | None = None
    user: dict | None = None
    pending_2fa_token: str | None = None
    two_factor_required: bool = False


@router.post("/login", response_model=LoginOut)
def mobile_login(request: Request, payload: LoginIn):
    ip = _client_ip(request)
    ua = request.headers.get("user-agent", "")
    norm_email = payload.email.lower().strip()

    if security.is_ip_rate_limited(db, ip):
        auth.record_audit(None, norm_email, "mobile.login.ratelimited", ip=ip)
        raise HTTPException(429, "Too many attempts. Try again in a few minutes.")

    if security.is_account_locked(db, norm_email):
        security.record_login_attempt(db, ip=ip, email=norm_email, success=False, user_agent=ua)
        auth.record_audit(None, norm_email, "mobile.login.account_locked", ip=ip)
        raise HTTPException(429, "This account is temporarily locked.")

    user = auth.authenticate(payload.email, payload.password)
    if not user:
        security.record_login_attempt(db, ip=ip, email=norm_email, success=False, user_agent=ua)
        security.register_failed_login(db, norm_email)
        auth.record_audit(None, norm_email, "mobile.login.fail", ip=ip)
        raise HTTPException(401, "Invalid email or password")

    security.record_login_attempt(db, ip=ip, email=norm_email, success=True, user_agent=ua)
    security.clear_failed_logins(db, int(user["id"]))
    db.execute("UPDATE mmwss.users SET last_login_at = now() WHERE id = %s", (user["id"],))

    # 2FA branch — issue a pending token, do NOT issue the bearer yet
    if user.get("totp_enabled") and user.get("totp_secret"):
        _gc_pending()
        pending = secrets.token_urlsafe(32)
        _PENDING_2FA[pending] = (int(user["id"]), time.time())
        auth.record_audit(int(user["id"]), user["email"], "mobile.login.2fa_required", ip=ip)
        return LoginOut(pending_2fa_token=pending, two_factor_required=True)

    # No 2FA — issue bearer directly
    token, _sid, exp = mobile_auth.issue_token(
        user_id=int(user["id"]),
        device_label=payload.device_label,
        user_agent=ua, ip=ip,
    )
    auth.record_audit(int(user["id"]), user["email"], "mobile.login.success", ip=ip)
    return LoginOut(
        token=token, expires_at=exp,
        user={"id": int(user["id"]), "email": user["email"],
              "name": user["name"], "role": user["role"]},
    )


class TwoFAVerifyIn(BaseModel):
    pending_2fa_token: str = Field(..., min_length=10)
    code: str = Field(..., min_length=6, max_length=8)
    device_label: str | None = Field(None, max_length=120)
    app_version: str | None = Field(None, max_length=40)


@router.post("/2fa/verify", response_model=LoginOut)
def mobile_2fa_verify(request: Request, payload: TwoFAVerifyIn):
    _gc_pending()
    ip = _client_ip(request)
    ua = request.headers.get("user-agent", "")

    entry = _PENDING_2FA.get(payload.pending_2fa_token)
    if not entry:
        raise HTTPException(401, "Pending 2FA token invalid or expired — log in again")
    user_id, ts = entry
    if time.time() - ts > _PENDING_2FA_TTL:
        _PENDING_2FA.pop(payload.pending_2fa_token, None)
        raise HTTPException(401, "Pending 2FA token expired — log in again")

    user = db.fetch_one(
        "SELECT id, email, name, role, totp_secret, totp_enabled, is_active "
        "FROM mmwss.users WHERE id = %s",
        (user_id,),
    )
    if not user or not user["is_active"] or not user.get("totp_secret"):
        _PENDING_2FA.pop(payload.pending_2fa_token, None)
        raise HTTPException(401, "Account no longer eligible")

    if not security.verify_totp(user["totp_secret"], payload.code):
        auth.record_audit(int(user["id"]), user["email"], "mobile.2fa.fail", ip=ip)
        raise HTTPException(401, "Incorrect 6-digit code")

    # 2FA passed — consume the pending token, issue the bearer
    _PENDING_2FA.pop(payload.pending_2fa_token, None)
    token, _sid, exp = mobile_auth.issue_token(
        user_id=int(user["id"]),
        device_label=payload.device_label,
        user_agent=ua, ip=ip,
    )
    auth.record_audit(int(user["id"]), user["email"], "mobile.2fa.success", ip=ip)
    return LoginOut(
        token=token, expires_at=exp,
        user={"id": int(user["id"]), "email": user["email"],
              "name": user["name"], "role": user["role"]},
    )


@router.post("/logout")
def mobile_logout(request: Request, u: dict = Depends(mobile_auth.require_mobile_user)):
    mobile_auth.revoke_session_id(u["session_id"])
    auth.record_audit(u["id"], u["email"], "mobile.logout", ip=_client_ip(request))
    return {"ok": True}


# ─────────── Identity ───────────


@router.get("/me")
def mobile_me(u: dict = Depends(mobile_auth.require_mobile_user)):
    return {
        "id": u["id"], "email": u["email"], "name": u["name"], "role": u["role"],
        "session_id": u["session_id"],
    }


# ─────────── Dashboard ───────────


@router.get("/dashboard")
def mobile_dashboard(_u: dict = Depends(mobile_auth.require_mobile_user)):
    stats = queries.overview_stats()
    sec = queries.aggregate_security_score()
    qc = tickets.queue_counters()
    upt = queries.overview_uptime_24h()
    return {
        "stats": stats,
        "security": sec,
        "tickets": qc,
        "uptime_24h": upt,
    }


# ─────────── Tickets ───────────


def _ticket_to_dict(t: dict, sla_state: dict) -> dict:
    return {
        "id": int(t["id"]),
        "title": t["title"],
        "priority": t["priority"],
        "status": t["status"],
        "category": t["category"],
        "source": t["source"],
        "zone_id": t.get("zone_id"),
        "zone_name": t.get("zone_name"),
        "opened_at": t["opened_at"],
        "response_at": t.get("response_at"),
        "resolved_at": t.get("resolved_at"),
        "closed_at": t.get("closed_at"),
        "opened_by_email": t.get("opened_by_email"),
        "assigned_to_email": t.get("assigned_to_email"),
        "sla_response_secs": t["sla_response_secs"],
        "sla_resolution_secs": t["sla_resolution_secs"],
        "sla": {
            "response_state": sla_state["response_state"],
            "response_elapsed_s": sla_state["response_elapsed_s"],
            "response_breach_at": sla_state["response_breach_at"],
            "resolution_state": sla_state["resolution_state"],
            "resolution_elapsed_s": sla_state["resolution_elapsed_s"],
            "resolution_breach_at": sla_state["resolution_breach_at"],
        },
    }


@router.get("/tickets")
def mobile_tickets_list(
    _u: dict = Depends(mobile_auth.require_mobile_user),
    status_filter: str | None = None,
    priority: str | None = None,
    limit: int = 100,
):
    rows = tickets.list_tickets(status=status_filter, priority=priority, limit=limit)
    return {
        "tickets": [_ticket_to_dict(r, tickets.compute_sla_state(r)) for r in rows],
        "counters": tickets.queue_counters(),
    }


@router.get("/tickets/{ticket_id}")
def mobile_ticket_detail(ticket_id: int, _u: dict = Depends(mobile_auth.require_mobile_user)):
    t = tickets.get_ticket(ticket_id)
    if not t:
        raise HTTPException(404, "Ticket not found")
    sla_state = tickets.compute_sla_state(t)
    events = tickets.get_events(ticket_id)
    return {
        "ticket": _ticket_to_dict(t, sla_state),
        "description": t.get("description"),
        "resolution_notes": t.get("resolution_notes"),
        "rca_text": t.get("rca_text"),
        "events": [
            {
                "id": int(e["id"]),
                "ts": e["ts"],
                "event_type": e["event_type"],
                "details": e.get("details_json"),
                "user_email": e.get("user_email"),
            }
            for e in events
        ],
    }


class TicketRespondIn(BaseModel):
    note: str | None = Field(None, max_length=2000)


@router.post("/tickets/{ticket_id}/respond")
def mobile_ticket_respond(
    ticket_id: int,
    request: Request,
    payload: TicketRespondIn = Body(default_factory=TicketRespondIn),
    u: dict = Depends(mobile_auth.require_mobile_user),
):
    if not tickets.get_ticket(ticket_id):
        raise HTTPException(404, "Ticket not found")
    tickets.mark_response(ticket_id, u["id"], note=payload.note)
    auth.record_audit(u["id"], u["email"], "ticket.respond",
                      ip=_client_ip(request), target_type="ticket", target_id=str(ticket_id))
    return {"ok": True}


class TicketCommentIn(BaseModel):
    body: str = Field(..., min_length=1, max_length=4000)


@router.post("/tickets/{ticket_id}/comment")
def mobile_ticket_comment(
    ticket_id: int,
    payload: TicketCommentIn,
    u: dict = Depends(mobile_auth.require_mobile_user),
):
    if not tickets.get_ticket(ticket_id):
        raise HTTPException(404, "Ticket not found")
    tickets.add_comment(ticket_id, u["id"], payload.body)
    return {"ok": True}


# ─────────── Incidents ───────────


@router.get("/incidents")
def mobile_incidents(
    _u: dict = Depends(mobile_auth.require_mobile_user),
    limit: int = 100,
    open_only: bool = False,
):
    rows = queries.recent_incidents(limit=limit)
    if open_only:
        rows = [r for r in rows if r.get("ended_at") is None]
    return {
        "incidents": [
            {
                "id": int(r["id"]),
                "zone_id": r.get("zone_id"),
                "zone_name": r.get("zone_name"),
                "type": r["type"],
                "severity": r["severity"],
                "started_at": r["started_at"],
                "ended_at": r.get("ended_at"),
                "summary": r.get("summary"),
                "is_open": r.get("ended_at") is None,
            }
            for r in rows
        ],
    }


@router.get("/incidents/{incident_id}")
def mobile_incident_detail(incident_id: int, _u: dict = Depends(mobile_auth.require_mobile_user)):
    row = db.fetch_one(
        """
        SELECT i.id, i.zone_id, z.name AS zone_name, i.type, i.severity,
               i.started_at, i.ended_at, i.summary,
               t.id AS ticket_id, t.status AS ticket_status, t.priority AS ticket_priority
          FROM mmwss.incidents i
          JOIN mmwss.zones z ON z.id = i.zone_id
          LEFT JOIN mmwss.tickets t ON t.incident_id = i.id
         WHERE i.id = %s
        """,
        (incident_id,),
    )
    if not row:
        raise HTTPException(404, "Incident not found")
    return {
        "id": int(row["id"]),
        "zone_id": row.get("zone_id"),
        "zone_name": row.get("zone_name"),
        "type": row["type"],
        "severity": row["severity"],
        "started_at": row["started_at"],
        "ended_at": row.get("ended_at"),
        "summary": row.get("summary"),
        "is_open": row.get("ended_at") is None,
        "ticket_id": row.get("ticket_id"),
        "ticket_status": row.get("ticket_status"),
        "ticket_priority": row.get("ticket_priority"),
    }


# ─────────── Origin health ───────────


@router.get("/origin-health")
def mobile_origin_health(_u: dict = Depends(mobile_auth.require_mobile_user)):
    rows = queries.uptime_summary_all()
    items = []
    for r in rows:
        total = r.get("total") or 0
        ok = r.get("ok") or 0
        pct = (ok / total * 100) if total else None
        items.append({
            "zone_id": int(r["id"]),
            "zone_name": r["name"],
            "checks_24h": total,
            "ok_24h": ok,
            "uptime_pct_24h": pct,
            "avg_latency_ms": float(r["avg_latency"]) if r.get("avg_latency") is not None else None,
            "latest_ok": r.get("latest_ok"),
            "latest_status": r.get("latest_status"),
            "aws": {
                "instance": r.get("aws_instance"),
                "bundle": r.get("aws_bundle"),
                "ram_gb": r.get("aws_ram_gb"),
                "state": r.get("aws_state"),
                "cpu_avg": float(r["aws_cpu_avg"]) if r.get("aws_cpu_avg") is not None else None,
                "cpu_max": float(r["aws_cpu_max"]) if r.get("aws_cpu_max") is not None else None,
                "burst_pct": float(r["aws_burst_pct"]) if r.get("aws_burst_pct") is not None else None,
                "status_failed": r.get("aws_status_failed"),
                "metric_hour": r.get("aws_metric_hour"),
            },
        })
    return {"zones": items}


# ─────────── Scanner findings ───────────


@router.get("/findings")
def mobile_findings_list(
    _u: dict = Depends(mobile_auth.require_mobile_user),
    severity: str | None = None,
    status_filter: str | None = None,
    zone_id: int | None = None,
):
    rows = vapt.list_findings(severity=severity, status=status_filter, zone_id=zone_id)
    return {
        "findings": [
            {
                "id": int(r["id"]),
                "title": r["title"],
                "severity": r["severity"],
                "status": r["status"],
                "zone_id": r.get("zone_id"),
                "zone_name": r.get("zone_name"),
                "discovered_at": r.get("discovered_at"),
                "cve_reference": r.get("cve_reference"),
                "linked_ticket_id": r.get("linked_ticket_id"),
                "linked_ticket_status": r.get("linked_ticket_status"),
            }
            for r in rows
        ],
    }


@router.get("/findings/{finding_id}")
def mobile_finding_detail(finding_id: int, _u: dict = Depends(mobile_auth.require_mobile_user)):
    f = vapt.get_finding(finding_id)
    if not f:
        raise HTTPException(404, "Finding not found")
    return {
        "id": int(f["id"]),
        "title": f["title"],
        "severity": f["severity"],
        "status": f["status"],
        "description": f.get("description"),
        "zone_id": f.get("zone_id"),
        "zone_name": f.get("zone_name"),
        "report_title": f.get("report_title"),
        "report_date": f.get("report_date"),
        "vendor": f.get("vendor"),
        "discovered_at": f.get("discovered_at"),
        "remediated_at": f.get("remediated_at"),
        "verified_at": f.get("verified_at"),
        "cve_reference": f.get("cve_reference"),
        "vendor_finding_id": f.get("vendor_finding_id"),
        "linked_ticket_id": f.get("linked_ticket_id"),
        "linked_ticket_status": f.get("linked_ticket_status"),
    }


# ─────────── Push subscriptions ───────────


class PushSubscribeIn(BaseModel):
    fcm_token: str = Field(..., min_length=20, max_length=400)
    platform: str = Field("android", pattern="^(android|ios|web)$")
    device_label: str | None = Field(None, max_length=120)
    app_version: str | None = Field(None, max_length=40)
    notify_p1: bool = True
    notify_scanner_critical: bool = True
    notify_honeytoken: bool = True
    notify_report_ready: bool = True
    notify_sla_warning: bool = True


@router.post("/push/subscribe")
def mobile_push_subscribe(
    payload: PushSubscribeIn,
    u: dict = Depends(mobile_auth.require_mobile_user),
):
    # Upsert on fcm_token (UNIQUE). If a different user previously owned this
    # token (phone switched accounts), the new user takes over.
    db.execute(
        """
        INSERT INTO mmwss.push_subscriptions
            (user_id, fcm_token, platform, device_label, app_version,
             notify_p1, notify_scanner_critical, notify_honeytoken,
             notify_report_ready, notify_sla_warning,
             is_active, last_seen_at)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, TRUE, now())
        ON CONFLICT (fcm_token) DO UPDATE SET
            user_id       = EXCLUDED.user_id,
            platform      = EXCLUDED.platform,
            device_label  = EXCLUDED.device_label,
            app_version   = EXCLUDED.app_version,
            notify_p1                 = EXCLUDED.notify_p1,
            notify_scanner_critical   = EXCLUDED.notify_scanner_critical,
            notify_honeytoken         = EXCLUDED.notify_honeytoken,
            notify_report_ready       = EXCLUDED.notify_report_ready,
            notify_sla_warning        = EXCLUDED.notify_sla_warning,
            is_active     = TRUE,
            last_seen_at  = now(),
            deactivated_at = NULL,
            deactivated_reason = NULL
        """,
        (u["id"], payload.fcm_token, payload.platform,
         payload.device_label, payload.app_version,
         payload.notify_p1, payload.notify_scanner_critical, payload.notify_honeytoken,
         payload.notify_report_ready, payload.notify_sla_warning),
    )
    return {"ok": True}


class PushUnsubscribeIn(BaseModel):
    fcm_token: str = Field(..., min_length=20, max_length=400)


@router.post("/push/unsubscribe")
def mobile_push_unsubscribe(
    payload: PushUnsubscribeIn,
    u: dict = Depends(mobile_auth.require_mobile_user),
):
    db.execute(
        """
        UPDATE mmwss.push_subscriptions
           SET is_active = FALSE, deactivated_at = now(),
               deactivated_reason = 'user_unsubscribed'
         WHERE user_id = %s AND fcm_token = %s
        """,
        (u["id"], payload.fcm_token),
    )
    return {"ok": True}


@router.post("/push/test")
def mobile_push_test(u: dict = Depends(mobile_auth.require_mobile_user)):
    try:
        n = fcm.send_test(u["id"])
    except RuntimeError as e:
        raise HTTPException(503, str(e))
    return {"sent": n}


# ─────────── Per-device notification preferences ───────────


class PushPreferencesIn(BaseModel):
    fcm_token: str = Field(..., min_length=20, max_length=400)
    notify_p1: bool | None = None
    notify_scanner_critical: bool | None = None
    notify_honeytoken: bool | None = None
    notify_report_ready: bool | None = None
    notify_sla_warning: bool | None = None


@router.get("/push/preferences")
def mobile_push_preferences_get(
    fcm_token: str,
    u: dict = Depends(mobile_auth.require_mobile_user),
):
    row = db.fetch_one(
        """
        SELECT notify_p1, notify_scanner_critical, notify_honeytoken,
               notify_report_ready, notify_sla_warning, is_active, device_label
          FROM mmwss.push_subscriptions
         WHERE user_id = %s AND fcm_token = %s
        """,
        (u["id"], fcm_token),
    )
    if not row:
        raise HTTPException(404, "Subscription not found for this device")
    return row


@router.post("/push/preferences")
def mobile_push_preferences_set(
    payload: PushPreferencesIn,
    u: dict = Depends(mobile_auth.require_mobile_user),
):
    sets, params = [], []
    for col in ("notify_p1", "notify_scanner_critical", "notify_honeytoken",
                "notify_report_ready", "notify_sla_warning"):
        v = getattr(payload, col)
        if v is not None:
            sets.append(f"{col} = %s")
            params.append(v)
    if not sets:
        return {"ok": True, "updated": 0}
    params.extend([u["id"], payload.fcm_token])
    sql = f"""
        UPDATE mmwss.push_subscriptions
           SET {', '.join(sets)}
         WHERE user_id = %s AND fcm_token = %s
    """
    db.execute(sql, tuple(params))
    return {"ok": True}


# ─────────── Heartbeat (lets app refresh last_used_at) ───────────


@router.get("/ping")
def mobile_ping(u: dict = Depends(mobile_auth.require_mobile_user)):
    return {"ok": True, "user_id": u["id"], "ts": datetime.now(timezone.utc)}
