"""Maps `rule_id` → an actionable fix that MMWSS can apply via Cloudflare.

Two kinds of fix today:
  - `setting`     → PATCH /zones/{id}/settings/{setting_id} with `{value: ...}`
  - `block_path`  → add a Custom Firewall rule blocking the given URI path

Only rules that have a Fix here get a 'One-click fix' button in the UI.
Anything not in FIXES is intentionally non-fixable (WP findings that need
server-side access, ssl_expiry_near which CF auto-renews, etc.).
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Fix:
    kind: str                 # 'setting' | 'block_path'
    target: str               # setting_id (for 'setting') or URI path (for 'block_path')
    value: str | None         # new value (for 'setting'); None for block_path
    description: str          # human-readable action shown in the modal


FIXES: dict[str, Fix] = {
    # ─── Cloudflare setting tweaks ───
    "ssl_unsafe":   Fix("setting", "ssl",              "strict", "Set SSL mode to 'strict'"),
    "ssl_full":     Fix("setting", "ssl",              "strict", "Set SSL mode to 'strict'"),
    "https_off":    Fix("setting", "always_use_https", "on",     "Turn on Always Use HTTPS"),
    "security_off": Fix("setting", "security_level",   "medium", "Raise security level to 'medium'"),
    "tls_old":      Fix("setting", "min_tls_version",  "1.2",    "Set minimum TLS version to 1.2"),
    "brotli_off":   Fix("setting", "brotli",           "on",     "Enable Brotli compression"),
    "dev_mode_on":  Fix("setting", "development_mode", "off",    "Turn off Development Mode"),

    # ─── WordPress findings — fixed by blocking the offending path at Cloudflare ───
    "xmlrpc_enabled":         Fix("block_path", "/xmlrpc.php",          None, "Block /xmlrpc.php at Cloudflare"),
    "rest_users_enumerable":  Fix("block_path", "/wp-json/wp/v2/users", None, "Block /wp-json/wp/v2/users at Cloudflare"),
    "readme_html_present":    Fix("block_path", "/readme.html",         None, "Block /readme.html at Cloudflare"),
}


def is_fixable(rule_id: str) -> bool:
    return rule_id in FIXES


def get_fix(rule_id: str) -> Fix:
    return FIXES[rule_id]


def fix_action(rule_id: str) -> str | None:
    fx = FIXES.get(rule_id)
    return fx.description if fx else None


def human_titles_map() -> dict[str, str]:
    """{rule_id: human_action} — passed to the template so each Fix button
    shows the exact change it will make."""
    return {k: v.description for k, v in FIXES.items()}
