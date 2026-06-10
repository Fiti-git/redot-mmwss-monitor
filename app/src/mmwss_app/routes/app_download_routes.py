"""Redot Sentinel APK download — login-gated.

Serves the side-loadable APK built by mobile/redot_sentinel/bootstrap.sh.
Login-gated so a random visitor can't grab the APK (which contains the
Firebase client config + branding). The metadata JSON next to the APK
tells the install page the version + SHA so users can verify integrity.
"""
from __future__ import annotations

import json
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.templating import Jinja2Templates

from .. import auth

router = APIRouter()
templates: Jinja2Templates = None  # type: ignore  set in main


def _downloads_dir() -> Path:
    return Path(__file__).resolve().parent.parent.parent.parent / "static" / "downloads"


def _meta() -> dict:
    meta_path = _downloads_dir() / "redot-sentinel.json"
    if not meta_path.exists():
        return {}
    try:
        return json.loads(meta_path.read_text())
    except Exception:
        return {}


@router.get("/app/download", response_class=HTMLResponse)
def app_download_page(request: Request, user: dict = Depends(auth.require_user)):
    apk = _downloads_dir() / "redot-sentinel.apk"
    meta = _meta()
    available = apk.exists()
    return templates.TemplateResponse(
        "app_download.html",
        {
            "request": request, "user": user, "active": "app_download",
            "available": available,
            "version": meta.get("version"),
            "sha256": meta.get("sha256"),
            "size_bytes": meta.get("size_bytes"),
            "built_at": meta.get("built_at"),
        },
    )


@router.get("/app/download/redot-sentinel.apk")
def app_download_apk(_user: dict = Depends(auth.require_user)):
    apk = _downloads_dir() / "redot-sentinel.apk"
    if not apk.exists():
        raise HTTPException(404, "APK not built yet — run mobile/redot_sentinel/bootstrap.sh on the server.")
    return FileResponse(
        path=str(apk),
        media_type="application/vnd.android.package-archive",
        filename="redot-sentinel.apk",
    )
