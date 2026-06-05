"""Session-cookie auth: bcrypt password verify + signed cookie session.

Pattern:
- Login: verify password, set session["user_id"] etc. via Starlette SessionMiddleware
- Each request: routes that need auth call `require_user(request)`
- `require_admin(request)` for admin-only

Auth events are recorded in mmwss.audit_log via direct INSERT.
"""
from __future__ import annotations

from fastapi import HTTPException, Request, status
from fastapi.responses import RedirectResponse
import bcrypt

from . import db


def hash_password(plain: str) -> str:
    return bcrypt.hashpw(plain.encode("utf-8"), bcrypt.gensalt(rounds=12)).decode("utf-8")


def verify_password(plain: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(plain.encode("utf-8"), hashed.encode("utf-8"))
    except (ValueError, TypeError):
        return False


def authenticate(email: str, password: str) -> dict | None:
    """Return user dict on success, None on failure."""
    user = db.fetch_one(
        "SELECT id, email, name, password_hash, role, is_active FROM mmwss.users WHERE email = %s",
        (email.lower().strip(),),
    )
    if not user or not user["is_active"]:
        return None
    if not verify_password(password, user["password_hash"]):
        return None
    return user


def record_audit(user_id: int | None, email: str | None, action: str, ip: str | None = None,
                 target_type: str | None = None, target_id: str | None = None) -> None:
    db.execute(
        """
        INSERT INTO mmwss.audit_log (user_id, user_email, action, ip, target_type, target_id)
        VALUES (%s, %s, %s, %s, %s, %s)
        """,
        (user_id, email, action, ip, target_type, target_id),
    )


def current_user(request: Request) -> dict | None:
    s = request.session
    if not s.get("user_id"):
        return None
    return {
        "id": s["user_id"],
        "email": s["email"],
        "name": s["name"],
        "role": s["role"],
    }


def require_user(request: Request) -> dict:
    """Use as a FastAPI dependency. Redirects to login on miss."""
    u = current_user(request)
    if not u:
        from .config import get_settings
        base = get_settings().base_path
        raise HTTPException(
            status_code=status.HTTP_303_SEE_OTHER,
            headers={"Location": f"{base}/login?next={request.url.path}"},
        )
    return u


def require_admin(request: Request) -> dict:
    u = require_user(request)
    if u.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin only")
    return u
