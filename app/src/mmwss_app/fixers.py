"""Maps `rule_id` → Cloudflare setting change.

Only CF-side rules from recommendations.py are mappable here — WordPress
findings require server-side access we don't have. If a rule_id is not in
FIXES, it has no Fix button in the UI.
"""
from __future__ import annotations

FIXES: dict[str, tuple[str, str, str]] = {
    # rule_id           : (cf_setting_id,     new_value, human-readable description)
    "ssl_unsafe":         ("ssl",              "strict", "Set SSL mode to 'strict'"),
    "ssl_full":           ("ssl",              "strict", "Set SSL mode to 'strict'"),
    "https_off":          ("always_use_https", "on",     "Turn on Always Use HTTPS"),
    "security_off":       ("security_level",   "medium", "Raise security level to 'medium'"),
    "tls_old":            ("min_tls_version",  "1.2",    "Set minimum TLS version to 1.2"),
    "brotli_off":         ("brotli",           "on",     "Enable Brotli compression"),
    "dev_mode_on":        ("development_mode", "off",    "Turn off Development Mode"),
}


def is_fixable(rule_id: str) -> bool:
    return rule_id in FIXES


def fix_action(rule_id: str) -> str | None:
    """Human-readable description for the confirmation dialog."""
    if rule_id not in FIXES:
        return None
    return FIXES[rule_id][2]


def setting_change(rule_id: str) -> tuple[str, str]:
    """(cf_setting_id, new_value) — call PATCH /zones/{id}/settings/{setting_id}."""
    if rule_id not in FIXES:
        raise KeyError(rule_id)
    return FIXES[rule_id][0], FIXES[rule_id][1]


def human_titles_map() -> dict[str, str]:
    """{rule_id: human_action} for use in the template."""
    return {k: v[2] for k, v in FIXES.items()}
