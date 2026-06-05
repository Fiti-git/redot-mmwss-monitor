from __future__ import annotations

from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from .. import auth
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
    """Only allow internal paths under our base. Prevents open redirects."""
    if not next_val:
        return f"{BASE}/dashboard"
    if not next_val.startswith("/"):
        return f"{BASE}/dashboard"
    # Force inside our base
    if not next_val.startswith(BASE):
        return f"{BASE}/dashboard"
    return next_val


@router.get("/login", response_class=HTMLResponse)
def login_form(request: Request, next: str = ""):
    target = _safe_next(next)
    if auth.current_user(request):
        return RedirectResponse(target, status_code=303)
    return templates.TemplateResponse("login.html", {"request": request, "next": target, "error": None})


@router.post("/login", response_class=HTMLResponse)
def login_submit(
    request: Request,
    email: str = Form(...),
    password: str = Form(...),
    next: str = Form(""),
):
    target = _safe_next(next)
    user = auth.authenticate(email, password)
    ip = _client_ip(request)
    if not user:
        auth.record_audit(None, email.lower().strip(), "auth.login.fail", ip=ip)
        return templates.TemplateResponse(
            "login.html",
            {"request": request, "next": target, "error": "Invalid email or password"},
            status_code=401,
        )

    from .. import db
    db.execute("UPDATE mmwss.users SET last_login_at = now() WHERE id = %s", (user["id"],))

    request.session.clear()
    request.session["user_id"] = int(user["id"])
    request.session["email"] = user["email"]
    request.session["name"] = user["name"]
    request.session["role"] = user["role"]

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
