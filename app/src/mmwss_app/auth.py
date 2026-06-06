"""Session-cookie auth + 2FA + rate limiting + hash-chained audit.

Login flow:
    /login (GET/POST) → password check → if user.totp_enabled, set
        session["pending_2fa"]=user_id and redirect to /2fa/verify;
        else fully sign in.

require_user / require_admin enforce that pending_2fa is cleared before
the user is granted access. Admins must enable 2FA (enforced by a UI
banner + middleware-level redirect on first login after migration 011).
"""
from __future__ import annotations

from fastapi import HTTPException, Request, status
import bcrypt

from . import db, security


def hash_password(plain: str) -> str:
    return bcrypt.hashpw(plain.encode("utf-8"), bcrypt.gensalt(rounds=12)).decode("utf-8")


def verify_password(plain: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(plain.encode("utf-8"), hashed.encode("utf-8"))
    except (ValueError, TypeError):
        return False


def authenticate(email: str, password: str) -> dict | None:
    """Return user dict on success, None on failure. Does NOT check 2FA — that's
    a separate step in the login flow."""
    user = db.fetch_one(
        """
        SELECT id, email, name, password_hash, role, is_active,
               totp_secret, totp_enabled, totp_confirmed_at,
               failed_login_count, locked_until
          FROM mmwss.users
         WHERE email = %s
        """,
        (email.lower().strip(),),
    )
    if not user or not user["is_active"]:
        return None
    if not verify_password(password, user["password_hash"]):
        return None
    return user


# ───── Audit (hash-chained) ─────


def record_audit(user_id: int | None, email: str | None, action: str, ip: str | None = None,
                 target_type: str | None = None, target_id: str | None = None,
                 details: dict | None = None) -> None:
    """Append a hash-chained audit row. Each row's hash links to the
    previous one so deletions/edits break the chain visibly."""
    security.write_audit_hashed(
        db,
        user_id=user_id, user_email=email, action=action, ip=ip,
        target_type=target_type, target_id=target_id,
        details=details,
    )


# ───── Session helpers ─────


def current_user(request: Request) -> dict | None:
    s = request.session
    # If pending_2fa is set, the user is NOT considered authenticated.
    if s.get("pending_2fa"):
        return None
    if not s.get("user_id"):
        return None
    return {
        "id": s["user_id"],
        "email": s["email"],
        "name": s["name"],
        "role": s["role"],
    }


def pending_2fa_user_id(request: Request) -> int | None:
    return request.session.get("pending_2fa")


def finalize_login(request: Request, user: dict) -> None:
    """Mark the session as fully authenticated. Called from /login (no 2FA)
    or from /2fa/verify after the code passes."""
    request.session["user_id"] = int(user["id"])
    request.session["email"] = user["email"]
    request.session["name"] = user["name"]
    request.session["role"] = user["role"]
    request.session.pop("pending_2fa", None)


def require_user(request: Request) -> dict:
    """FastAPI dep. Redirects to /login if not signed in. If 2FA is pending,
    redirects to /2fa/verify."""
    from .config import get_settings
    base = get_settings().base_path
    if request.session.get("pending_2fa"):
        raise HTTPException(
            status_code=status.HTTP_303_SEE_OTHER,
            headers={"Location": f"{base}/2fa/verify"},
        )
    u = current_user(request)
    if not u:
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
