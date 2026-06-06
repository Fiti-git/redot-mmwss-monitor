-- 009: Register the OWASP ZAP scanner.
--
-- ZAP runs as a long-lived daemon container (mmwss-zap) on the same Docker
-- network as collector + app. The collector talks to ZAP's REST API on
-- http://zap:8090 to spider, passive-scan, and (optionally) active-scan
-- each managed zone.
--
-- Phase 1 default: PASSIVE only (safe; no payload injection; no test
-- authorization required). Active scan mode is gated behind the
-- 'scan_mode': 'active' config knob — flip it only after MMWSS provides
-- written test authorization in the contract addendum.
--
-- Spider + passive scan together cover what most "industry-grade" DAST
-- products call a "baseline scan" — missing headers, info disclosure,
-- insecure cookies, mixed content, weak forms, exposed metadata, etc.

BEGIN;

INSERT INTO mmwss.scanners (name, kind, description, enabled, config_json)
VALUES (
    'zap',
    'dast',
    'OWASP ZAP (Zed Attack Proxy) — industry-standard web app DAST. Passive scan + spider in Phase 1; active scan behind feature flag.',
    TRUE,
    '{
      "scan_mode": "passive",
      "spider_max_duration_mins": 5,
      "spider_max_depth": 5,
      "passive_wait_secs": 60,
      "ascan_max_duration_mins": 30,
      "include_alerts_at_or_above": "low",
      "timeout_secs": 1800
    }'::jsonb
)
ON CONFLICT (name) DO UPDATE SET
    description = EXCLUDED.description,
    config_json = EXCLUDED.config_json;

COMMIT;
