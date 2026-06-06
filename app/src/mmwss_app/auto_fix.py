"""Auto-resolution engine.

Three stages:

1. **Matcher** — given a finding, decide if a mechanical fix exists and
   build the proposed action payload (CF API args). Deterministic; same
   inputs always produce the same output.

2. **Proposal generator** — called after a scan. For each new finding on
   an auto-fix-enabled zone, insert an `auto_fix_proposals` row in
   `pending_approval` status. Idempotency handled by the unique index in
   migration 010.

3. **Applier** — invoked by routes when admin clicks Approve+Apply.
   Calls the appropriate cf_client function, records the change_log entry,
   marks the finding as `remediated` (so the next scan auto-verifies),
   stores the CF response for audit.

Approval model: always required. No autonomous application.
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from typing import Any, Callable

from . import cf_client, change_log, db

log = logging.getLogger(__name__)


# ───── Action payload schema ─────


@dataclass
class FixAction:
    kind: str                  # 'cf_setting' | 'cf_transform_header' | 'cf_waf_block_path'
    summary: str               # human-readable action description
    proposed_state: str        # human-readable target state
    payload: dict              # exact args for the applier
    estimated_findings_resolved: int = 1


# ───── Matchers ─────
#
# Each matcher: (scanner, template_id_pattern_match_fn) → FixAction factory
# Returns None if no fix applies; FixAction if there's a known CF recipe.


def _hdr_csp() -> FixAction:
    return FixAction(
        kind="cf_transform_header",
        summary="Add Content-Security-Policy header via CF Transform Rule",
        proposed_state="CSP header set on all responses",
        payload={
            "header_name": "Content-Security-Policy",
            "header_value": (
                "default-src 'self'; "
                "img-src * data: blob:; "
                "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
                "font-src 'self' data: https://fonts.gstatic.com; "
                "script-src 'self' 'unsafe-inline' 'unsafe-eval'; "
                "frame-ancestors 'self'; "
                "form-action 'self';"
            ),
            "description": "MMWSS: add starter CSP (auto-resolved scanner finding)",
        },
    )


def _hdr_xframe() -> FixAction:
    return FixAction(
        kind="cf_transform_header",
        summary="Add X-Frame-Options: SAMEORIGIN",
        proposed_state="X-Frame-Options: SAMEORIGIN",
        payload={
            "header_name": "X-Frame-Options",
            "header_value": "SAMEORIGIN",
            "description": "MMWSS: prevent clickjacking",
        },
    )


def _hdr_xcto() -> FixAction:
    return FixAction(
        kind="cf_transform_header",
        summary="Add X-Content-Type-Options: nosniff",
        proposed_state="X-Content-Type-Options: nosniff",
        payload={
            "header_name": "X-Content-Type-Options",
            "header_value": "nosniff",
            "description": "MMWSS: disable MIME sniffing",
        },
    )


def _hdr_referrer() -> FixAction:
    return FixAction(
        kind="cf_transform_header",
        summary="Add Referrer-Policy: strict-origin-when-cross-origin",
        proposed_state="Referrer-Policy: strict-origin-when-cross-origin",
        payload={
            "header_name": "Referrer-Policy",
            "header_value": "strict-origin-when-cross-origin",
            "description": "MMWSS: limit Referer leakage",
        },
    )


def _hdr_permissions() -> FixAction:
    return FixAction(
        kind="cf_transform_header",
        summary="Add Permissions-Policy (restrict browser APIs)",
        proposed_state="Permissions-Policy: geolocation=(), microphone=(), camera=()",
        payload={
            "header_name": "Permissions-Policy",
            "header_value": "geolocation=(), microphone=(), camera=(), payment=()",
            "description": "MMWSS: restrict sensitive browser APIs",
        },
    )


def _hdr_hsts() -> FixAction:
    return FixAction(
        kind="cf_transform_header",
        summary="Add HSTS (1 year, includeSubDomains)",
        proposed_state="Strict-Transport-Security: max-age=31536000; includeSubDomains",
        payload={
            "header_name": "Strict-Transport-Security",
            "header_value": "max-age=31536000; includeSubDomains",
            "description": "MMWSS: enforce HTTPS for 1 year",
        },
    )


def _waf_block(path: str, why: str) -> FixAction:
    return FixAction(
        kind="cf_waf_block_path",
        summary=f"Block {path} via CF WAF",
        proposed_state=f"WAF rule: block requests to {path}",
        payload={
            "path": path,
            "description": f"MMWSS: {why}"[:255],
        },
    )


def _setting_tls12() -> FixAction:
    return FixAction(
        kind="cf_setting",
        summary="Set minimum TLS version to 1.2",
        proposed_state="min_tls_version = 1.2",
        payload={"setting_id": "min_tls_version", "value": "1.2"},
    )


def _setting_https_on() -> FixAction:
    return FixAction(
        kind="cf_setting",
        summary="Turn on Always Use HTTPS",
        proposed_state="always_use_https = on",
        payload={"setting_id": "always_use_https", "value": "on"},
    )


def _setting_ssl_strict() -> FixAction:
    return FixAction(
        kind="cf_setting",
        summary="Upgrade SSL mode to Strict",
        proposed_state="ssl = strict",
        payload={"setting_id": "ssl", "value": "strict"},
    )


# Matcher table — (scanner, template_id) → action factory
# Templates that map to a CF Transform Rule headed by `_hdr_*` produce a
# zone-wide fix that resolves ALL URL-level findings of the same template.
MATCHERS: dict[tuple[str, str], Callable[[], FixAction]] = {
    # ─── from our headers probe ───
    ("headers", "missing-csp"):                _hdr_csp,
    ("headers", "missing-x-frame-options"):    _hdr_xframe,
    ("headers", "missing-x-content-type-options"): _hdr_xcto,
    ("headers", "missing-referrer-policy"):    _hdr_referrer,
    ("headers", "missing-permissions-policy"): _hdr_permissions,
    ("headers", "missing-hsts"):               _hdr_hsts,
    ("headers", "weak-hsts"):                  _hdr_hsts,
    # ─── from ZAP ───
    ("zap", "zap-10020"): _hdr_xframe,                  # X-Frame-Options
    ("zap", "zap-10021"): _hdr_xcto,                    # X-Content-Type-Options
    ("zap", "zap-10035"): _hdr_hsts,                    # HSTS missing
    ("zap", "zap-10038"): _hdr_csp,                     # CSP missing
    ("zap", "zap-10063"): _hdr_permissions,             # Permissions-Policy
    # ─── from Nuclei (WP-specific blocks via WAF) ───
    ("nuclei", "wordpress-xmlrpc"):    lambda: _waf_block("/xmlrpc.php",         "block xmlrpc"),
    ("nuclei", "wp-user-enumeration"): lambda: _waf_block("/wp-json/wp/v2/users", "block REST user enum"),
    ("nuclei", "wp-readme"):           lambda: _waf_block("/readme.html",         "block WP readme leak"),
}


# Some ZAP templates fire on EVERY URL on a site (after rollup, just once).
# These are "zone-wide" — a single CF rule resolves the entire template.
ZONE_WIDE_TEMPLATES = {
    "headers": {"missing-csp", "missing-x-frame-options", "missing-x-content-type-options",
                "missing-referrer-policy", "missing-permissions-policy",
                "missing-hsts", "weak-hsts"},
    "zap": {"zap-10020", "zap-10021", "zap-10035", "zap-10038", "zap-10063"},
}


def match_finding(scanner: str, template_id: str) -> FixAction | None:
    fn = MATCHERS.get((scanner or "", template_id or ""))
    return fn() if fn else None


# ───── Proposal generator ─────


def zone_is_enabled(zone_id: int) -> bool:
    r = db.fetch_one(
        "SELECT enabled FROM mmwss.auto_fix_zone_settings WHERE zone_id = %s",
        (zone_id,),
    )
    return bool(r and r["enabled"])


def generate_proposals_for_finding(finding_id: int) -> int:
    """Create auto_fix_proposals rows for the given finding if matchers apply
    and the zone is enabled. Returns count of proposals created.

    Idempotency: unique index on (zone_id, action_kind, action_payload) means
    re-running this is safe — duplicates are NOT-created silently.
    """
    f = db.fetch_one(
        """
        SELECT id, scanner, scanner_template_id, zone_id, severity, status, source
          FROM mmwss.vapt_findings
         WHERE id = %s
        """,
        (finding_id,),
    )
    if not f or f["source"] != "internal_scan":
        return 0
    if f["status"] not in ("open", "in_progress"):
        return 0
    if not f["zone_id"]:
        return 0
    if not zone_is_enabled(f["zone_id"]):
        return 0

    action = match_finding(f["scanner"], f["scanner_template_id"])
    if not action:
        return 0

    # Estimate impact: zone-wide templates can close many same-template findings
    est = action.estimated_findings_resolved
    if f["scanner"] in ZONE_WIDE_TEMPLATES and f["scanner_template_id"] in ZONE_WIDE_TEMPLATES[f["scanner"]]:
        c = db.fetch_one(
            """
            SELECT COUNT(*)::int AS n FROM mmwss.vapt_findings
             WHERE source = 'internal_scan' AND zone_id = %s
               AND scanner = %s AND scanner_template_id = %s
               AND status IN ('open', 'in_progress')
            """,
            (f["zone_id"], f["scanner"], f["scanner_template_id"]),
        )
        est = max(1, c["n"] if c else 1)

    try:
        r = db.fetch_one(
            """
            INSERT INTO mmwss.auto_fix_proposals
                (finding_id, zone_id, action_kind, action_summary,
                 proposed_state, action_payload, estimated_findings_resolved)
            VALUES (%s, %s, %s, %s, %s, %s::jsonb, %s)
            ON CONFLICT (zone_id, action_kind, action_payload)
              WHERE status IN ('pending_approval', 'approved', 'applying')
              DO NOTHING
            RETURNING id
            """,
            (finding_id, f["zone_id"], action.kind, action.summary,
             action.proposed_state, json.dumps(action.payload), est),
        )
        return 1 if r else 0
    except Exception:
        log.exception("generate_proposals_for_finding failed for %d", finding_id)
        return 0


def generate_proposals_for_open_findings() -> int:
    """Backfill: scan all open scanner findings, generate proposals where applicable.
    Idempotent via the unique index. Returns count of NEW proposals created."""
    rows = db.fetch_all(
        """
        SELECT id FROM mmwss.vapt_findings
         WHERE source = 'internal_scan' AND status IN ('open', 'in_progress')
        """
    )
    created = 0
    for row in rows:
        created += generate_proposals_for_finding(row["id"])
    log.info("auto-fix backfill: %d new proposals from %d open findings", created, len(rows))
    return created


# ───── Queries for the UI ─────


def list_proposals(*, status: str | None = None, zone_id: int | None = None,
                   limit: int = 500) -> list[dict]:
    where = []
    params: list[Any] = []
    if status:
        where.append("p.status = %s"); params.append(status)
    if zone_id:
        where.append("p.zone_id = %s"); params.append(zone_id)
    sql = """
        SELECT p.id, p.finding_id, p.zone_id, z.name AS zone_name,
               p.action_kind, p.action_summary, p.before_state, p.proposed_state,
               p.action_payload, p.estimated_findings_resolved,
               p.status, p.created_at, p.approved_at, p.applied_at,
               p.failure_reason, p.change_log_id,
               u.email AS approved_by_email, u2.email AS applied_by_email,
               f.title AS finding_title, f.scanner, f.scanner_template_id,
               f.severity AS finding_severity, f.risk_score AS finding_risk
          FROM mmwss.auto_fix_proposals p
          JOIN mmwss.zones           z  ON z.id  = p.zone_id
          JOIN mmwss.vapt_findings   f  ON f.id  = p.finding_id
          LEFT JOIN mmwss.users      u  ON u.id  = p.approved_by_user_id
          LEFT JOIN mmwss.users      u2 ON u2.id = p.applied_by_user_id
    """
    if where:
        sql += " WHERE " + " AND ".join(where)
    sql += " ORDER BY (p.status='pending_approval') DESC, p.created_at DESC LIMIT %s"
    params.append(limit)
    return db.fetch_all(sql, tuple(params))


def get_proposal(proposal_id: int) -> dict | None:
    return db.fetch_one(
        """
        SELECT p.*, z.name AS zone_name, z.cf_zone_id,
               f.title AS finding_title, f.scanner, f.scanner_template_id,
               f.severity AS finding_severity, f.risk_score AS finding_risk
          FROM mmwss.auto_fix_proposals p
          JOIN mmwss.zones           z ON z.id = p.zone_id
          JOIN mmwss.vapt_findings   f ON f.id = p.finding_id
         WHERE p.id = %s
        """,
        (proposal_id,),
    )


def counters() -> dict:
    r = db.fetch_one(
        """
        SELECT
            (SELECT COUNT(*)::int FROM mmwss.auto_fix_proposals WHERE status = 'pending_approval') AS pending,
            (SELECT COUNT(*)::int FROM mmwss.auto_fix_proposals WHERE status = 'applied'
              AND applied_at >= now() - interval '30 days') AS applied_30d,
            (SELECT COUNT(*)::int FROM mmwss.auto_fix_proposals WHERE status = 'failed') AS failed,
            (SELECT COUNT(*)::int FROM mmwss.auto_fix_proposals WHERE status = 'rejected') AS rejected,
            (SELECT COALESCE(SUM(estimated_findings_resolved), 0)::int
               FROM mmwss.auto_fix_proposals WHERE status = 'pending_approval') AS pending_resolve_estimate
        """
    )
    return r or {}


# ───── Apply (admin action) ─────


def apply_proposal(proposal_id: int, user_id: int) -> dict:
    """Apply a proposal. Returns {'ok': bool, 'error': ..., 'change_log_id': ...}.

    Steps:
      1. Mark proposal as 'applying' (lock against concurrent applies).
      2. Look up zone's cf_zone_id.
      3. Dispatch to the right CF API call.
      4. On success: record change_log, mark finding as 'remediated',
         mark proposal as 'applied'.
      5. On failure: mark as 'failed' with error message.
    """
    p = db.fetch_one(
        """
        SELECT p.*, z.cf_zone_id, z.name AS zone_name,
               f.scanner, f.scanner_template_id, f.title AS finding_title,
               f.severity AS finding_severity
          FROM mmwss.auto_fix_proposals p
          JOIN mmwss.zones         z ON z.id = p.zone_id
          JOIN mmwss.vapt_findings f ON f.id = p.finding_id
         WHERE p.id = %s
        """,
        (proposal_id,),
    )
    if not p:
        return {"ok": False, "error": "Proposal not found"}
    if p["status"] not in ("pending_approval", "approved"):
        return {"ok": False, "error": f"Proposal status is {p['status']}, can't apply"}

    # Lock
    db.execute(
        """
        UPDATE mmwss.auto_fix_proposals
           SET status = 'applying',
               approved_by_user_id = COALESCE(approved_by_user_id, %s),
               approved_at = COALESCE(approved_at, now())
         WHERE id = %s
        """,
        (user_id, proposal_id),
    )

    payload = p["action_payload"] or {}
    if isinstance(payload, str):
        payload = json.loads(payload)
    cf_response: dict = {}
    err: str | None = None

    try:
        kind = p["action_kind"]
        cf_zone_id = p["cf_zone_id"]
        if kind == "cf_setting":
            cf_response = cf_client.patch_zone_setting(
                cf_zone_id, payload["setting_id"], payload["value"],
            )
        elif kind == "cf_transform_header":
            cf_response = cf_client.add_response_header_rule(
                cf_zone_id,
                payload["header_name"],
                payload["header_value"],
                payload.get("description", "MMWSS auto-fix"),
            )
        elif kind == "cf_waf_block_path":
            cf_response = cf_client.add_block_path_rule(
                cf_zone_id, payload["path"], payload.get("description", "MMWSS auto-fix"),
            )
        else:
            raise ValueError(f"unknown action_kind: {kind}")
    except cf_client.CloudflareApiError as e:
        err = str(e)
    except Exception as e:
        err = f"unexpected error: {e}"

    if err:
        db.execute(
            """
            UPDATE mmwss.auto_fix_proposals
               SET status = 'failed', failure_reason = %s, applied_at = now()
             WHERE id = %s
            """,
            (err[:500], proposal_id),
        )
        return {"ok": False, "error": err}

    # Success — record change_log + mark finding remediated
    cl_id = change_log.create_entry(
        category="cf_setting" if p["action_kind"] == "cf_setting"
                 else ("cf_firewall_rule" if p["action_kind"] == "cf_waf_block_path"
                       else "cf_setting"),
        title=f"Auto-fix: {p['action_summary']} ({p['zone_name']})",
        description=f"Auto-resolution of finding #{p['finding_id']}: {p['finding_title']}",
        before_state=p["before_state"] or "(not captured)",
        after_state=p["proposed_state"],
        test_result="passed",   # CF API returned success
        zone_id=p["zone_id"],
        source="auto_cf_fix",
        engineer_user_id=user_id,
    )
    db.execute(
        """
        UPDATE mmwss.auto_fix_proposals
           SET status = 'applied',
               applied_at = now(),
               applied_by_user_id = %s,
               cf_response_json = %s::jsonb,
               change_log_id = %s
         WHERE id = %s
        """,
        (user_id, json.dumps(cf_response, default=str), cl_id, proposal_id),
    )
    # Mark the finding as remediated. Next scan auto-verifies via
    # consecutive_misses; if the finding still appears, status flips back to
    # 'open' automatically (the runner handles regressions).
    db.execute(
        """
        UPDATE mmwss.vapt_findings
           SET status = 'remediated', remediated_at = COALESCE(remediated_at, now())
         WHERE id = %s AND status IN ('open', 'in_progress')
        """,
        (p["finding_id"],),
    )
    # For zone-wide templates, also remediate sibling findings in the same group.
    if (p["scanner"] in ZONE_WIDE_TEMPLATES
            and p["scanner_template_id"] in ZONE_WIDE_TEMPLATES[p["scanner"]]):
        db.execute(
            """
            UPDATE mmwss.vapt_findings
               SET status = 'remediated', remediated_at = COALESCE(remediated_at, now())
             WHERE source = 'internal_scan' AND zone_id = %s
               AND scanner = %s AND scanner_template_id = %s
               AND status IN ('open', 'in_progress')
            """,
            (p["zone_id"], p["scanner"], p["scanner_template_id"]),
        )
    return {"ok": True, "change_log_id": cl_id}


def reject_proposal(proposal_id: int, reason: str, user_id: int) -> None:
    db.execute(
        """
        UPDATE mmwss.auto_fix_proposals
           SET status = 'rejected',
               rejection_reason = %s,
               approved_by_user_id = %s,
               approved_at = now()
         WHERE id = %s AND status IN ('pending_approval', 'approved')
        """,
        ((reason or "").strip()[:500] or "(no reason given)", user_id, proposal_id),
    )


# ───── Zone settings ─────


def list_zone_settings() -> list[dict]:
    return db.fetch_all(
        """
        SELECT z.id AS zone_id, z.name AS zone_name,
               COALESCE(a.enabled, FALSE) AS enabled,
               a.updated_at,
               u.email AS updated_by_email
          FROM mmwss.zones z
          LEFT JOIN mmwss.auto_fix_zone_settings a ON a.zone_id = z.id
          LEFT JOIN mmwss.users u ON u.id = a.updated_by_user_id
         WHERE z.status = 'active'
         ORDER BY z.name
        """
    )


def set_zone_enabled(zone_id: int, enabled: bool, user_id: int) -> None:
    db.execute(
        """
        INSERT INTO mmwss.auto_fix_zone_settings
            (zone_id, enabled, updated_by_user_id, updated_at)
        VALUES (%s, %s, %s, now())
        ON CONFLICT (zone_id) DO UPDATE SET
            enabled = EXCLUDED.enabled,
            updated_by_user_id = EXCLUDED.updated_by_user_id,
            updated_at = now()
        """,
        (zone_id, enabled, user_id),
    )
