"""FastAPI app entry. Mounted at coldcalling.redotglobal.agency/mmwss via Caddy.

Caddy does NOT strip the /mmwss prefix on its way in — every route below is
registered with that prefix so RedirectResponse("/mmwss/dashboard") "just works".
"""
from __future__ import annotations

import logging
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware

from . import auth, filters
from .config import get_settings
from .routes import api_routes, auth_routes, pages, ticket_routes, vapt_routes

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s — %(message)s",
)
log = logging.getLogger("mmwss_app")

settings = get_settings()
BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR.parent.parent / "static"
BASE_PATH = settings.base_path  # "/mmwss"

app = FastAPI(title="MMWSS", docs_url=None, redoc_url=None, openapi_url=None)

app.add_middleware(
    SessionMiddleware,
    secret_key=settings.session_secret,
    max_age=settings.session_max_age_seconds,
    same_site=settings.cookie_samesite,
    https_only=settings.cookie_secure,
    session_cookie="mmwss_session",
    path="/",
)

# Static + templates (also under /mmwss/static so links in templates work)
app.mount(f"{BASE_PATH}/static", StaticFiles(directory=STATIC_DIR), name="static")
templates = Jinja2Templates(directory=BASE_DIR / "templates")
filters.register(templates.env)

templates.env.globals["base_path"] = BASE_PATH
templates.env.globals["app_name"] = "MMWSS"
templates.env.globals["company"] = "Redot Global"

pages.templates = templates
auth_routes.templates = templates

# All routes registered with the /mmwss prefix
app.include_router(auth_routes.router, prefix=BASE_PATH)
app.include_router(pages.router, prefix=BASE_PATH)
app.include_router(api_routes.router, prefix=BASE_PATH)
ticket_routes.templates = templates
app.include_router(ticket_routes.router, prefix=BASE_PATH)
vapt_routes.templates = templates
app.include_router(vapt_routes.router, prefix=BASE_PATH)


@app.get("/healthz")
def healthz():
    return {"ok": True}


@app.get("/")
def root_redirect(request: Request):
    if auth.current_user(request):
        return RedirectResponse(f"{BASE_PATH}/dashboard", status_code=303)
    return RedirectResponse(f"{BASE_PATH}/login", status_code=303)


@app.get(BASE_PATH)
@app.get(f"{BASE_PATH}/")
def mmwss_root(request: Request):
    if auth.current_user(request):
        return RedirectResponse(f"{BASE_PATH}/dashboard", status_code=303)
    return RedirectResponse(f"{BASE_PATH}/login", status_code=303)
