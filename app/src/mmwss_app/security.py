"""Platform self-security primitives.

Three concerns covered here:

1. **Security headers middleware** — set CSP, HSTS, X-Frame-Options,
   X-Content-Type-Options, Referrer-Policy, Permissions-Policy on every
   response from our own app. We tell MMWSS to do this for their WP sites;
   we should be the first user of it.

2. **Origin / Referer check middleware** — defence against CSRF that
   complements the SameSite=Lax cookie we already set. For state-changing
   methods (POST/PUT/PATCH/DELETE), verify the Origin or Referer header
   points to our host. Cheaper than per-form CSRF tokens and equivalent
   when SameSite is enforced.

3. **Login rate limiting** — DB-backed sliding window. Blocks per-IP
   bursts (>= 10 in 5 min) and per-email lockout (>= 5 failures locks
   the account for 15 min).

4. **TOTP 2FA** — helpers to generate secret, issue QR provisioning URI,
   verify a 6-digit code. Calls live in auth.py.

5. **Audit hash chain** — every audit_log INSERT now computes
   row_hash = sha256(prev_hash || canonical_row) so later edits / deletes
   are detectable by walking the chain.
"""
from __future__ import annotations

import hashlib
import io
import json
import logging
import secrets
from datetime import datetime, timedelta, timezone

import pyotp
import segno
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

log = logging.getLogger(__name__)


# ───── Security headers middleware ─────

# Conservative CSP for our own UI. Tailwind CDN + Chart.js CDN + StPageFlip
# CDN + PDF.js CDN + Google Fonts are explicitly allowed because the app
# already depends on them; everything else is denied.
_DEFAULT_CSP = (
    "default-src 'self'; "
    "img-src 'self' data: blob: https:; "
    "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdn.tailwindcss.com "
        "https://fonts.googleapis.com https://cdnjs.cloudflare.com; "
    "style-src-elem 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdn.tailwindcss.com "
        "https://fonts.googleapis.com https://cdnjs.cloudflare.com; "
    "font-src 'self' data: https://fonts.gstatic.com; "
    "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdn.tailwindcss.com "
        "https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; "
    "script-src-elem 'self' 'unsafe-inline' https://cdn.tailwindcss.com "
        "https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; "
    "connect-src 'self' https://cdnjs.cloudflare.com; "
    "frame-ancestors 'self'; "
    "form-action 'self'; "
    "base-uri 'self'; "
    "object-src 'none';"
)

_HEADERS = {
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "X-Content-Type-Options":    "nosniff",
    "X-Frame-Options":           "SAMEORIGIN",
    "Referrer-Policy":           "strict-origin-when-cross-origin",
    "Permissions-Policy":        "geolocation=(), microphone=(), camera=(), payment=(), usb=()",
    "Cross-Origin-Opener-Policy": "same-origin",
    # Content-Security-Policy applied separately so it can be tuned per env.
}


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Add a baseline of security headers to every response."""
    def __init__(self, app, *, csp: str | None = None):
        super().__init__(app)
        self.csp = csp or _DEFAULT_CSP

    async def dispatch(self, request: Request, call_next):
        response: Response = await call_next(request)
        for k, v in _HEADERS.items():
            response.headers.setdefault(k, v)
        # Don't add CSP on raw file downloads (PDF, HTML reports)
        ctype = response.headers.get("content-type", "")
        if not ctype.startswith(("application/pdf", "application/octet-stream")):
            response.headers.setdefault("Content-Security-Policy", self.csp)
        return response


# ───── Origin / Referer check (CSRF defence layer 2) ─────


class OriginCheckMiddleware(BaseHTTPMiddleware):
    """For state-changing requests, require Origin or Referer to match our host.

    Combined with SameSite=Lax cookies this is functionally equivalent to
    per-form CSRF tokens for our use case (no GET-with-side-effects, no
    JS-driven cross-site form posts).
    """
    UNSAFE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}

    def __init__(self, app, *, allowed_hosts: list[str]):
        super().__init__(app)
        self.allowed = {h.lower() for h in allowed_hosts}

    async def dispatch(self, request: Request, call_next):
        if request.method in self.UNSAFE_METHODS:
            host = request.headers.get("host", "").lower()
            origin = (request.headers.get("origin") or "").lower()
            referer = (request.headers.get("referer") or "").lower()

            ok = False
            # Same-host origin
            if origin:
                ok = any(origin == f"https://{h}" or origin == f"http://{h}"
                         for h in self.allowed | {host})
            elif referer:
                ok = any(referer.startswith(f"https://{h}/")
                         or referer.startswith(f"http://{h}/")
                         for h in self.allowed | {host})
            else:
                # No Origin/Referer (some browsers/tools omit on same-origin POSTs);
                # rely on SameSite cookie. Accept.
                ok = True

            if not ok:
                log.warning("OriginCheck rejected %s %s origin=%r referer=%r host=%r",
                            request.method, request.url.path, origin, referer, host)
                return Response(content="Cross-origin POST blocked", status_code=403)
        return await call_next(request)


# ───── Login rate limiting ─────


def _now() -> datetime:
    return datetime.now(timezone.utc)


def record_login_attempt(db_mod, *, ip: str | None, email: str | None,
                          success: bool, user_agent: str | None) -> None:
    db_mod.execute(
        """
        INSERT INTO mmwss.login_attempts (ip, email, success, user_agent)
        VALUES (%s, %s, %s, %s)
        """,
        (ip, (email or "").lower().strip() or None, success, (user_agent or "")[:200]),
    )


def is_ip_rate_limited(db_mod, ip: str | None) -> bool:
    """Block if this IP has tried >= 10 logins in the last 5 minutes."""
    if not ip:
        return False
    cutoff = _now() - timedelta(minutes=5)
    r = db_mod.fetch_one(
        "SELECT COUNT(*)::int AS n FROM mmwss.login_attempts WHERE ip = %s AND attempted_at >= %s",
        (ip, cutoff),
    )
    return bool(r and r["n"] >= 10)


def is_account_locked(db_mod, email: str) -> bool:
    r = db_mod.fetch_one(
        "SELECT locked_until FROM mmwss.users WHERE email = %s",
        (email.lower().strip(),),
    )
    if not r or not r.get("locked_until"):
        return False
    return r["locked_until"] > _now()


def register_failed_login(db_mod, email: str) -> None:
    """Bump failed_login_count; lock account for 15 min after 5 failures."""
    db_mod.execute(
        """
        UPDATE mmwss.users
           SET failed_login_count = failed_login_count + 1,
               locked_until = CASE WHEN failed_login_count + 1 >= 5
                                   THEN now() + interval '15 minutes'
                                   ELSE locked_until END
         WHERE email = %s
        """,
        (email.lower().strip(),),
    )


def clear_failed_logins(db_mod, user_id: int) -> None:
    db_mod.execute(
        "UPDATE mmwss.users SET failed_login_count = 0, locked_until = NULL WHERE id = %s",
        (user_id,),
    )


# ───── TOTP 2FA ─────


def generate_totp_secret() -> str:
    return pyotp.random_base32()


def totp_provisioning_uri(secret: str, *, account_email: str, issuer: str = "MMWSS") -> str:
    return pyotp.TOTP(secret).provisioning_uri(name=account_email, issuer_name=issuer)


def totp_qr_svg(provisioning_uri: str) -> str:
    """Render the provisioning URI as an inline SVG QR code (no external deps in the browser)."""
    qr = segno.make(provisioning_uri, error="m")
    buf = io.BytesIO()
    qr.save(buf, kind="svg", scale=6, dark="#0F172A", light="#fbf8f1", border=1)
    return buf.getvalue().decode("utf-8")


def verify_totp(secret: str, code: str, *, valid_window: int = 1) -> bool:
    if not secret or not code or len(code.strip()) not in (6, 8):
        return False
    try:
        return pyotp.TOTP(secret).verify(code.strip(), valid_window=valid_window)
    except Exception:
        return False


# ───── Audit log hash chain ─────


def _canonical_audit_row(*, user_id: int | None, user_email: str | None,
                         action: str, ip: str | None, target_type: str | None,
                         target_id: str | None, details_json: dict | None,
                         created_at) -> str:
    return (
        f"{user_id or ''}|{user_email or ''}|{action or ''}|{ip or ''}"
        f"|{target_type or ''}|{target_id or ''}"
        f"|{json.dumps(details_json) if details_json else ''}|{created_at}"
    )


def _sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def latest_audit_hash(db_mod) -> str:
    """Return the row_hash of the most recent audit_log row (chain head),
    or the genesis seed if the table is empty."""
    r = db_mod.fetch_one(
        "SELECT row_hash FROM mmwss.audit_log ORDER BY id DESC LIMIT 1"
    )
    if r and r.get("row_hash"):
        return r["row_hash"]
    return "mmwss-audit-chain-genesis"


def write_audit_hashed(db_mod, *, user_id: int | None, user_email: str | None,
                       action: str, ip: str | None,
                       target_type: str | None, target_id: str | None,
                       details: dict | None) -> int:
    """Append an audit row with computed hash chain in a SINGLE INSERT.

    The existing audit_log_immutable trigger blocks UPDATE/DELETE — so we
    cannot do INSERT-then-UPDATE. Instead we pre-compute the timestamp in
    Python and hash everything before the INSERT.
    """
    prev = latest_audit_hash(db_mod)
    ts = _now()
    canonical = _canonical_audit_row(
        user_id=user_id, user_email=user_email, action=action, ip=ip,
        target_type=target_type, target_id=target_id,
        details_json=details, created_at=ts,
    )
    row_hash = _sha256_hex(prev + canonical)
    with db_mod.conn() as c:
        with c.cursor() as cur:
            cur.execute(
                """
                INSERT INTO mmwss.audit_log
                    (ts, user_id, user_email, action, ip,
                     target_type, target_id, details_json,
                     row_hash, prev_hash)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s::jsonb, %s, %s)
                RETURNING id
                """,
                (ts, user_id, user_email, action, ip, target_type, target_id,
                 json.dumps(details) if details else None, row_hash, prev),
            )
            row_id = cur.fetchone()["id"]
        c.commit()
    return row_id


def verify_audit_chain(db_mod, *, since_id: int | None = None) -> dict:
    """Walk the audit chain from `since_id` (default: earliest), recomputing
    every hash. Returns {'ok': bool, 'broken_at_id': int|None, 'checked': int}.
    """
    seed = "mmwss-audit-chain-genesis"
    with db_mod.conn() as c:
        with c.cursor() as cur:
            cur.execute(
                """
                SELECT id, user_id, user_email, action, ip,
                       target_type, target_id, details_json, ts,
                       row_hash, prev_hash
                  FROM mmwss.audit_log
                 WHERE id >= COALESCE(%s, 0)
                 ORDER BY id
                """,
                (since_id,),
            )
            rows = cur.fetchall()
    prev = seed
    if since_id and rows:
        # Start with stored prev_hash from the first row in window
        prev = rows[0]["prev_hash"] or seed
    checked = 0
    for r in rows:
        canonical = _canonical_audit_row(
            user_id=r["user_id"], user_email=r["user_email"],
            action=r["action"], ip=str(r["ip"]) if r["ip"] else None,
            target_type=r["target_type"], target_id=r["target_id"],
            details_json=r["details_json"], created_at=r["ts"],
        )
        expected = _sha256_hex(prev + canonical)
        if r["row_hash"] != expected or r["prev_hash"] != prev:
            return {"ok": False, "broken_at_id": r["id"], "checked": checked}
        prev = r["row_hash"]
        checked += 1
    return {"ok": True, "broken_at_id": None, "checked": checked}
