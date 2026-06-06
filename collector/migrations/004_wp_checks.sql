-- 004: WordPress synthetic checks.
-- Stores the result of HTTP-only probes against each tracked site:
-- did the home page render, is /wp-config.php exposed, is /xmlrpc.php
-- enabled, is the REST users endpoint publicly enumerable, etc.
--
-- One row per zone per check cycle. Old rows accumulate; old data is
-- valuable for trending so we don't auto-trim.

BEGIN;

CREATE TABLE mmwss.wp_checks (
    id              BIGSERIAL PRIMARY KEY,
    zone_id         BIGINT NOT NULL REFERENCES mmwss.zones(id) ON DELETE CASCADE,
    captured_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    is_wordpress    BOOLEAN,
    wp_version      TEXT,
    home_status     INT,
    home_latency_ms INT,
    findings_json   JSONB NOT NULL
);

CREATE INDEX wp_checks_zone_captured_idx
    ON mmwss.wp_checks (zone_id, captured_at DESC);

COMMIT;
