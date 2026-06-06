"""Static remediation template library.

Maps (scanner, template_id pattern, CWE) → human-written remediation text.
Engineers see this on every finding so they have an actionable next step
without going AI-hunting. Templates are intentionally short.

Lookup order:
  1. exact (scanner, template_id) match
  2. glob match within scanner
  3. generic by CWE
  4. generic by severity
"""
from __future__ import annotations

import fnmatch

# (scanner, template_id_pattern) → text
_TEMPLATES: dict[tuple[str, str], str] = {
    # ─── Nuclei ───
    ("nuclei", "tech-detect/*"):
        "Informational only — confirms a technology is present. Suppress via a finding rule "
        "if you don't want this category to alert.",

    ("nuclei", "exposures/configs/*"):
        "A config or environment file is reachable from the public internet. "
        "1) Block access via web server config (deny .env, wp-config.bak, etc.). "
        "2) Verify no secrets were leaked; rotate any exposed credentials. "
        "3) Record the change in the change log.",

    ("nuclei", "exposures/files/git-config"):
        "An exposed .git directory leaks source code. "
        "1) Remove .git from web root. "
        "2) Add a deny rule in nginx/Apache for /.git/. "
        "3) Treat repo history as public — audit for committed secrets.",

    ("nuclei", "exposures/files/wordpress-debug-log"):
        "WordPress debug log is publicly readable and may contain stack traces, paths, or PII. "
        "Delete the file and disable WP_DEBUG_LOG in wp-config.php, or set WP_DEBUG_LOG to a "
        "path outside the web root.",

    ("nuclei", "misconfiguration/*"):
        "Server / application misconfiguration. Review the specific finding output, "
        "apply the vendor's recommended config, and re-run the scan to confirm.",

    ("nuclei", "default-logins/*"):
        "Default credentials still active on an admin interface. "
        "1) Change the password immediately. "
        "2) Restrict the admin URL via IP allowlist or VPN. "
        "3) Enable MFA. "
        "4) Audit recent login activity for unauthorized access.",

    ("nuclei", "exposed-panels/*"):
        "Admin / management panel is reachable from the internet. "
        "Move behind VPN or restrict by IP at the Cloudflare WAF. Document the access policy.",

    ("nuclei", "cves/*"):
        "Known CVE. "
        "1) Upgrade the affected component to the patched version per the CVE advisory. "
        "2) If upgrade is blocked, apply the vendor's workaround (WAF rule, config flag). "
        "3) Re-scan to verify the fix.",

    # ─── WPScan ───
    ("wpscan", "wp-plugin-outdated/*"):
        "Outdated WordPress plugin. "
        "1) Test the upgrade on staging if available. "
        "2) Take a backup snapshot in Cloudflare/host before applying. "
        "3) Update via WP admin or WP-CLI. "
        "4) Record before/after versions in the change log.",

    ("wpscan", "wp-plugin-vulnerable/*"):
        "Plugin has a known vulnerability. "
        "1) Check vendor changelog for a patched release; upgrade. "
        "2) If no patch exists, evaluate disabling the plugin. "
        "3) Add WAF rule blocking the exploit path until patched. "
        "4) Record the remediation in the change log.",

    ("wpscan", "wp-theme-outdated/*"):
        "Outdated theme. "
        "Update to latest. If a parent theme of a customized child theme, test child overrides "
        "after upgrade.",

    ("wpscan", "wp-core-outdated/*"):
        "WordPress core is behind. Upgrade via WP-CLI: "
        "`wp core update && wp core update-db`. "
        "Test on staging first; take a full backup; record in change log.",

    ("wpscan", "wp-user-enumeration/*"):
        "Usernames are enumerable via /?author=N or /wp-json/wp/v2/users. "
        "1) Add WAF rule blocking /?author= and disable the REST users endpoint. "
        "2) Disable user enumeration in iThemes Security / Wordfence if installed.",

    # ─── testssl.sh ───
    ("testssl", "weak-cipher/*"):
        "Weak TLS cipher offered. "
        "Disable ciphers below TLS 1.2 strength; reload web server. "
        "Verify with `testssl.sh --severity HIGH <host>` after the change.",

    ("testssl", "deprecated-protocol/*"):
        "Deprecated SSL/TLS protocol enabled (SSLv3 / TLS 1.0 / TLS 1.1). "
        "Disable in web server config — TLS 1.2 minimum. Re-test after reload.",

    ("testssl", "hsts/*"):
        "HSTS header missing or weak. "
        "Add `Strict-Transport-Security: max-age=31536000; includeSubDomains` "
        "via Cloudflare Transform Rules or origin config.",

    ("testssl", "cert-expiring/*"):
        "Certificate expiring soon. "
        "If managed by Cloudflare, verify the Edge cert is auto-renewing. "
        "If origin cert, renew via your CA (Let's Encrypt: `certbot renew`).",

    # ─── headers ───
    ("headers", "missing-csp"):
        "Content-Security-Policy header is missing. "
        "Add a starter policy via Cloudflare Transform Rule: "
        "`Content-Security-Policy: default-src 'self'; img-src * data:; style-src 'self' 'unsafe-inline';` "
        "then tighten based on actual usage. Test on staging first — too-strict CSP breaks pages.",

    ("headers", "missing-x-frame-options"):
        "X-Frame-Options missing — site can be embedded in an iframe (clickjacking risk). "
        "Add `X-Frame-Options: SAMEORIGIN` via Cloudflare Transform Rule or origin config.",

    ("headers", "missing-x-content-type-options"):
        "X-Content-Type-Options missing — browsers may MIME-sniff responses. "
        "Add `X-Content-Type-Options: nosniff`.",

    ("headers", "missing-referrer-policy"):
        "Referrer-Policy missing — full URL leaks to third parties via Referer. "
        "Add `Referrer-Policy: strict-origin-when-cross-origin`.",

    ("headers", "missing-permissions-policy"):
        "Permissions-Policy missing — disables granular control over browser APIs. "
        "Add `Permissions-Policy: geolocation=(), microphone=(), camera=()` as a starter.",

    ("headers", "weak-hsts"):
        "HSTS max-age is below 6 months (15552000s). "
        "Increase to 31536000 (1 year) and add `includeSubDomains` if all subdomains are HTTPS.",

    # ─── ZAP (DAST) ───
    # Plugin IDs sourced from https://www.zaproxy.org/docs/alerts/
    # Most-common alerts are listed; everything else falls through to the
    # severity-based generic remediation.

    ("zap", "zap-10020"):
        "Missing/insecure X-Frame-Options. Add `X-Frame-Options: SAMEORIGIN` "
        "via Cloudflare Transform Rule or origin web server. "
        "Mitigates clickjacking.",

    ("zap", "zap-10021"):
        "X-Content-Type-Options missing. Add `X-Content-Type-Options: nosniff` "
        "so browsers don't MIME-sniff responses.",

    ("zap", "zap-10035"):
        "Strict-Transport-Security missing. Add "
        "`Strict-Transport-Security: max-age=31536000; includeSubDomains` "
        "via Cloudflare or origin.",

    ("zap", "zap-10038"):
        "Content-Security-Policy missing. Start with: "
        "`Content-Security-Policy: default-src 'self'; img-src * data:; "
        "style-src 'self' 'unsafe-inline';` then tighten based on actual usage.",

    ("zap", "zap-10054"):
        "Cookie missing HttpOnly flag. Update the application to set HttpOnly on "
        "all session/auth cookies so JavaScript cannot read them.",

    ("zap", "zap-10055"):
        "Cookie missing Secure flag. Update the application to set Secure on "
        "all cookies so they're only sent over HTTPS.",

    ("zap", "zap-10063"):
        "Permissions-Policy header missing. Add a starter policy: "
        "`Permissions-Policy: geolocation=(), microphone=(), camera=()`.",

    ("zap", "zap-90004"):
        "Insufficient Site Isolation Against Spectre Vulnerability. "
        "Add `Cross-Origin-Opener-Policy: same-origin` and "
        "`Cross-Origin-Embedder-Policy: require-corp` headers.",

    ("zap", "zap-10027"):
        "Information disclosure in HTTP response (timestamps, internal paths). "
        "Strip leaking headers/footers from the response. Audit error pages.",

    ("zap", "zap-10028"):
        "Open redirect vulnerability detected. Sanitize redirect targets — "
        "allow only relative URLs or a hard-coded allowlist of external hosts.",

    ("zap", "zap-10095"):
        "Backup file disclosure. Remove or block public access to .bak / .old / "
        "~ files. Add a deny rule in nginx/Apache.",

    ("zap", "zap-90022"):
        "Application error disclosure. Application is returning stack traces / "
        "detailed errors to users. Set production error handling to a generic page; "
        "log details server-side only.",

    ("zap", "zap-40012"):
        "Cross-Site Scripting (Reflected) detected by ZAP active scanner. "
        "Sanitize / encode the reflected parameter. Use framework-provided "
        "output-encoding helpers; never inline user input into HTML.",

    ("zap", "zap-40014"):
        "Cross-Site Scripting (Persistent). High-severity stored XSS — fix urgently. "
        "Sanitize input at write-time AND encode output at read-time.",

    ("zap", "zap-40018"):
        "SQL injection detected by ZAP active scanner. Replace string-concatenated "
        "SQL with parameterized queries / prepared statements. Validate at the "
        "application boundary. CRITICAL: rotate any credentials potentially exposed.",

    ("zap", "zap-90020"):
        "Remote OS Command Injection. CRITICAL — full server compromise possible. "
        "Disable affected endpoint immediately. Replace shell calls with safe "
        "library APIs; never pass user input to shell commands.",

    ("zap", "zap-90035"):
        "Server-Side Template Injection. Move user data out of the template "
        "rendering context. Use parameterized rendering.",

    ("zap", "zap-90019"):
        "Server-Side Code Injection. CRITICAL — disable affected endpoint. "
        "Never eval/exec user-controlled strings.",

    ("zap", "zap-90021"):
        "XPath Injection. Use parameterized XPath APIs or escape XPath special chars.",

    ("zap", "zap-40009"):
        "Server-Side Include detected. Disable SSI in web server config unless required.",

    # ─── surface ───
    ("surface", "new-subdomain/*"):
        "A new subdomain was detected. "
        "1) Verify this is an intended deployment. "
        "2) If unintended, identify origin (typo, abandoned env, attacker?). "
        "3) If staging/dev, ensure it's behind auth + not indexed. "
        "4) Add to monitored zones list if production.",

    ("surface", "exposed-staging/*"):
        "Staging/dev/test host is publicly accessible. "
        "Restrict via Cloudflare Access, basic auth, or IP allowlist. "
        "Block indexing with `X-Robots-Tag: noindex`.",
}

# Generic fallbacks keyed by severity
_FALLBACK_BY_SEVERITY: dict[str, str] = {
    "critical":
        "Critical severity — requires immediate attention. "
        "1) Validate the finding manually (the PoC in the finding detail). "
        "2) Determine the smallest change that closes the exposure. "
        "3) Apply, re-scan to confirm, and record in the change log.",
    "high":
        "High severity. Plan a fix within the high-severity SLA. "
        "Validate, remediate, re-scan, record.",
    "medium":
        "Medium severity. Schedule into the regular maintenance window. "
        "Validate finding accuracy before remediation.",
    "low":
        "Low severity. Address opportunistically or batch with related fixes.",
    "info":
        "Informational. No action required unless context elevates this.",
}


def lookup(scanner: str, template_id: str, severity: str) -> str:
    """Return the most specific remediation text we have."""
    # 1. exact
    key = (scanner, template_id)
    if key in _TEMPLATES:
        return _TEMPLATES[key]
    # 2. glob within scanner
    for (s, pat), text in _TEMPLATES.items():
        if s == scanner and fnmatch.fnmatchcase(template_id, pat):
            return text
    # 3. severity fallback
    return _FALLBACK_BY_SEVERITY.get(severity, _FALLBACK_BY_SEVERITY["medium"])
