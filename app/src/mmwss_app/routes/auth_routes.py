"""Login + logout + 2FA enrollment & verification routes."""
from __future__ import annotations

from fastapi import APIRouter, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from .. import auth, db, security
from ..config import get_settings

router = APIRouter()
templates: Jinja2Templates = None  # type: ignore   set in main

_settings = get_settings()
BASE = _settings.base_path


def _client_ip(request: Request) -> str | None:
    fwd = request.headers.get("x-forwarded-for")
    if fwd:
        return fwd.split(",")[0].strip()
    return request.client.host if request.client else None


def _safe_next(next_val: str | None) -> str:
    if not next_val:
        return f"{BASE}/dashboard"
    if not next_val.startswith("/"):
        return f"{BASE}/dashboard"
    if not next_val.startswith(BASE):
        return f"{BASE}/dashboard"
    return next_val


# ───── Login ─────


@router.get("/login", response_class=HTMLResponse)
def login_form(request: Request, next: str = ""):
    target = _safe_next(next)
    if auth.current_user(request):
        return RedirectResponse(target, status_code=303)
    if request.session.get("pending_2fa"):
        return RedirectResponse(f"{BASE}/2fa/verify", status_code=303)
    return templates.TemplateResponse(
        "login.html",
        {"request": request, "next": target, "error": None},
    )


@router.post("/login", response_class=HTMLResponse)
def login_submit(
    request: Request,
    email: str = Form(...),
    password: str = Form(...),
    next: str = Form(""),
):
    target = _safe_next(next)
    ip = _client_ip(request)
    ua = request.headers.get("user-agent", "")
    norm_email = email.lower().strip()

    # Per-IP rate limit
    if security.is_ip_rate_limited(db, ip):
        auth.record_audit(None, norm_email, "auth.login.ratelimited", ip=ip)
        return templates.TemplateResponse(
            "login.html",
            {"request": request, "next": target,
             "error": "Too many attempts from your network. Try again in a few minutes."},
            status_code=429,
        )

    # Per-account lockout
    if security.is_account_locked(db, norm_email):
        security.record_login_attempt(db, ip=ip, email=norm_email, success=False, user_agent=ua)
        auth.record_audit(None, norm_email, "auth.login.account_locked", ip=ip)
        return templates.TemplateResponse(
            "login.html",
            {"request": request, "next": target,
             "error": "This account is temporarily locked. Try again in 15 minutes."},
            status_code=429,
        )

    user = auth.authenticate(email, password)

    if not user:
        security.record_login_attempt(db, ip=ip, email=norm_email, success=False, user_agent=ua)
        security.register_failed_login(db, norm_email)
        auth.record_audit(None, norm_email, "auth.login.fail", ip=ip)
        return templates.TemplateResponse(
            "login.html",
            {"request": request, "next": target, "error": "Invalid email or password"},
            status_code=401,
        )

    # Password OK — log the success attempt, clear failure count
    security.record_login_attempt(db, ip=ip, email=norm_email, success=True, user_agent=ua)
    security.clear_failed_logins(db, int(user["id"]))
    db.execute("UPDATE mmwss.users SET last_login_at = now() WHERE id = %s", (user["id"],))

    request.session.clear()

    # If 2FA is enabled for this user, hold the session in 2FA-pending state.
    if user.get("totp_enabled") and user.get("totp_secret"):
        request.session["pending_2fa"] = int(user["id"])
        request.session["pending_2fa_target"] = target
        auth.record_audit(int(user["id"]), user["email"], "auth.login.2fa_required", ip=ip)
        return RedirectResponse(f"{BASE}/2fa/verify", status_code=303)

    # No 2FA: complete login. Admin without 2FA gets nudged to enroll on first hit
    # after migration 011 via the settings page — not blocking.
    auth.finalize_login(request, user)
    auth.record_audit(int(user["id"]), user["email"], "auth.login", ip=ip)
    return RedirectResponse(target, status_code=303)


@router.post("/logout")
def logout(request: Request):
    u = auth.current_user(request)
    if u:
        ip = _client_ip(request)
        auth.record_audit(int(u["id"]), u["email"], "auth.logout", ip=ip)
    request.session.clear()
    return RedirectResponse(f"{BASE}/login", status_code=303)


# ───── 2FA verify (post-login) ─────


@router.get("/2fa/verify", response_class=HTMLResponse)
def two_fa_verify_form(request: Request):
    if auth.current_user(request):
        return RedirectResponse(f"{BASE}/dashboard", status_code=303)
    if not request.session.get("pending_2fa"):
        return RedirectResponse(f"{BASE}/login", status_code=303)
    return templates.TemplateResponse(
        "two_fa_verify.html", {"request": request, "error": None},
    )


@router.post("/2fa/verify", response_class=HTMLResponse)
def two_fa_verify_submit(request: Request, code: str = Form(...)):
    pending_id = request.session.get("pending_2fa")
    target = request.session.get("pending_2fa_target") or f"{BASE}/dashboard"
    ip = _client_ip(request)
    if not pending_id:
        return RedirectResponse(f"{BASE}/login", status_code=303)
    user = db.fetch_one(
        "SELECT id, email, name, role, totp_secret, totp_enabled FROM mmwss.users WHERE id = %s",
        (pending_id,),
    )
    if not user or not user.get("totp_secret"):
        request.session.clear()
        return RedirectResponse(f"{BASE}/login", status_code=303)
    if not security.verify_totp(user["totp_secret"], code):
        auth.record_audit(int(user["id"]), user["email"], "auth.2fa.fail", ip=ip)
        return templates.TemplateResponse(
            "two_fa_verify.html",
            {"request": request, "error": "Incorrect 6-digit code. Try again."},
            status_code=401,
        )
    auth.finalize_login(request, user)
    auth.record_audit(int(user["id"]), user["email"], "auth.2fa.success", ip=ip)
    return RedirectResponse(target, status_code=303)


# ───── 2FA enrollment (logged-in user) ─────


@router.get("/2fa/setup", response_class=HTMLResponse)
def two_fa_setup_form(request: Request):
    u = auth.require_user(request)
    # If already enrolled, show the management page instead of fresh enrollment
    me = db.fetch_one(
        "SELECT totp_secret, totp_enabled FROM mmwss.users WHERE id = %s",
        (int(u["id"]),),
    )
    if me and me["totp_enabled"]:
        return templates.TemplateResponse(
            "two_fa_setup.html",
            {"request": request, "user": u, "enrolled": True,
             "secret": None, "qr_svg": None, "error": None, "active": "settings"},
        )
    # Generate a fresh secret if one isn't already pending in the session
    secret = request.session.get("pending_totp_secret")
    if not secret:
        secret = security.generate_totp_secret()
        request.session["pending_totp_secret"] = secret
    uri = security.totp_provisioning_uri(secret, account_email=u["email"])
    qr_svg = security.totp_qr_svg(uri)
    return templates.TemplateResponse(
        "two_fa_setup.html",
        {"request": request, "user": u, "enrolled": False,
         "secret": secret, "qr_svg": qr_svg, "error": None, "active": "settings"},
    )


@router.post("/2fa/setup")
def two_fa_setup_confirm(request: Request, code: str = Form(...)):
    u = auth.require_user(request)
    secret = request.session.get("pending_totp_secret")
    if not secret:
        return RedirectResponse(f"{BASE}/2fa/setup", status_code=303)
    if not security.verify_totp(secret, code):
        uri = security.totp_provisioning_uri(secret, account_email=u["email"])
        qr_svg = security.totp_qr_svg(uri)
        return templates.TemplateResponse(
            "two_fa_setup.html",
            {"request": request, "user": u, "enrolled": False,
             "secret": secret, "qr_svg": qr_svg,
             "error": "Code didn't match. Try the current 6-digit code from your authenticator app.",
             "active": "settings"},
            status_code=400,
        )
    db.execute(
        """
        UPDATE mmwss.users
           SET totp_secret = %s, totp_enabled = TRUE, totp_confirmed_at = now()
         WHERE id = %s
        """,
        (secret, int(u["id"])),
    )
    request.session.pop("pending_totp_secret", None)
    auth.record_audit(int(u["id"]), u["email"], "auth.2fa.enrolled",
                      ip=_client_ip(request))
    return RedirectResponse(f"{BASE}/2fa/setup", status_code=303)


@router.post("/2fa/disable")
def two_fa_disable(request: Request, password: str = Form(...)):
    u = auth.require_user(request)
    me = db.fetch_one(
        "SELECT password_hash FROM mmwss.users WHERE id = %s", (int(u["id"]),),
    )
    if not me or not auth.verify_password(password, me["password_hash"]):
        raise HTTPException(403, "Password verification failed")
    db.execute(
        "UPDATE mmwss.users SET totp_secret = NULL, totp_enabled = FALSE, totp_confirmed_at = NULL WHERE id = %s",
        (int(u["id"]),),
    )
    auth.record_audit(int(u["id"]), u["email"], "auth.2fa.disabled",
                      ip=_client_ip(request))
    return RedirectResponse(f"{BASE}/2fa/setup", status_code=303)
