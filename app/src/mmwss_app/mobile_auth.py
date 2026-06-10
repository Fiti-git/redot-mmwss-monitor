"""Bearer-token auth for the Redot Sentinel mobile app.

The mobile app does NOT use session cookies (those are scoped to the browser
flow). Instead, after a successful login + 2FA we mint a 64-byte random
token, store its sha256 in mmwss.mobile_sessions, and return the token
plaintext exactly once. Every subsequent API call sends
`Authorization: Bearer <token>`.

Why sha256, not plaintext: if the DB ever leaks, we don't want every active
phone's token to be usable. Tokens are also the credential that drives
push subscriptions, so a leak would mean an attacker could harvest pushes
silently.
"""
from __future__ import annotations

import hashlib
import secrets
from datetime import datetime, timedelta, timezone

from fastapi import HTTPException, Request, status

from . import db

TOKEN_BYTES = 48               # 384 bits — comfortable margin
TOKEN_TTL_DAYS = 90


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def issue_token(
    *, user_id: int, device_label: str | None, user_agent: str | None, ip: str | None
) -> tuple[str, int, datetime]:
    """Return (plaintext_token, session_id, expires_at). The plaintext is
    never persisted — caller MUST return it to the client immediately."""
    plaintext = secrets.token_urlsafe(TOKEN_BYTES)
    token_sha = _hash(plaintext)
    expires_at = datetime.now(timezone.utc) + timedelta(days=TOKEN_TTL_DAYS)
    with db.conn() as c:
        with c.cursor() as cur:
            cur.execute(
                """
                INSERT INTO mmwss.mobile_sessions
                    (user_id, token_sha256, device_label, user_agent, ip, expires_at)
                VALUES (%s, %s, %s, %s, %s, %s)
                RETURNING id
                """,
                (user_id, token_sha, device_label, user_agent, ip, expires_at),
            )
            sid = cur.fetchone()["id"]
        c.commit()
    return plaintext, sid, expires_at


def revoke_token(token: str) -> None:
    db.execute(
        "UPDATE mmwss.mobile_sessions SET revoked_at = now() WHERE token_sha256 = %s",
        (_hash(token),),
    )


def revoke_session_id(session_id: int) -> None:
    db.execute(
        "UPDATE mmwss.mobile_sessions SET revoked_at = now() WHERE id = %s",
        (session_id,),
    )


def _extract_bearer(request: Request) -> str | None:
    h = request.headers.get("authorization")
    if not h:
        return None
    parts = h.split(None, 1)
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return None
    return parts[1].strip() or None


def require_mobile_user(request: Request) -> dict:
    """FastAPI dependency: authenticates the request via Bearer token.

    Returns dict: {id, email, name, role, session_id, token_sha256}.
    Updates last_used_at on every call.
    """
    token = _extract_bearer(request)
    if not token:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Missing bearer token")
    sha = _hash(token)
    row = db.fetch_one(
        """
        SELECT s.id AS session_id, s.user_id, s.expires_at, s.revoked_at,
               u.email, u.name, u.role, u.is_active
          FROM mmwss.mobile_sessions s
          JOIN mmwss.users u ON u.id = s.user_id
         WHERE s.token_sha256 = %s
        """,
        (sha,),
    )
    if not row:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid token")
    if row["revoked_at"] is not None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Token revoked")
    if row["expires_at"] <= datetime.now(timezone.utc):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Token expired")
    if not row["is_active"]:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Account disabled")
    # Touch last_used_at (cheap UPDATE; ignored failure is fine)
    db.execute(
        "UPDATE mmwss.mobile_sessions SET last_used_at = now() WHERE id = %s",
        (row["session_id"],),
    )
    return {
        "id": int(row["user_id"]),
        "email": row["email"],
        "name": row["name"],
        "role": row["role"],
        "session_id": int(row["session_id"]),
        "token_sha256": sha,
    }


def list_sessions(user_id: int) -> list[dict]:
    return db.fetch_all(
        """
        SELECT id, device_label, ip, user_agent,
               created_at, last_used_at, expires_at, revoked_at
          FROM mmwss.mobile_sessions
         WHERE user_id = %s
         ORDER BY created_at DESC
        """,
        (user_id,),
    )
