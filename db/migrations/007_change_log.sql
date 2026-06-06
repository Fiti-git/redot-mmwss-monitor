-- 007: Patch + change log (unified).
-- Per the proposal Section 3.5: "All system changes (patches, plugin updates,
-- infrastructure adjustments) will be recorded in a change log. Each entry
-- will state date/time, engineer responsible, description of change, testing
-- results, and rollback confirmation."
--
-- One table covers all kinds. Filtering by category gives you the "patch log"
-- view (plugin_update + core_update + theme_update) or the "config log" view
-- (cf_setting + cf_firewall_rule + server_config), etc.

BEGIN;

CREATE TYPE mmwss.change_category AS ENUM (
    'plugin_update',
    'core_update',
    'theme_update',
    'cf_setting',
    'cf_firewall_rule',
    'cf_dns',
    'ssl_renewal',
    'server_config',
    'database_change',
    'custom_code',
    'vapt_remediation',
    'other'
);

CREATE TYPE mmwss.change_test_result AS ENUM ('passed', 'failed', 'not_tested');

CREATE TABLE mmwss.change_log (
    id                  BIGSERIAL PRIMARY KEY,
    -- What
    category            mmwss.change_category    NOT NULL,
    title               TEXT NOT NULL,
    description         TEXT,
    -- Before/after (free-form strings so it covers plugin versions, JSON
    -- settings, firewall rules, etc.)
    before_state        TEXT,
    after_state         TEXT,
    -- Test outcome (proposal requires this on every entry)
    test_result         mmwss.change_test_result NOT NULL DEFAULT 'not_tested',
    test_notes          TEXT,
    -- Rollback plan + outcome (rollback confirmation required by proposal)
    rollback_plan       TEXT,
    rolled_back         BOOLEAN                  NOT NULL DEFAULT FALSE,
    rollback_notes      TEXT,
    rolled_back_at      TIMESTAMPTZ,
    -- Where
    zone_id             BIGINT REFERENCES mmwss.zones(id) ON DELETE SET NULL,
    -- Cross-refs to operational items so monthly report can show ticket→change→VAPT chain
    ticket_id           BIGINT REFERENCES mmwss.tickets(id)       ON DELETE SET NULL,
    vapt_finding_id     BIGINT REFERENCES mmwss.vapt_findings(id) ON DELETE SET NULL,
    -- Source: 'manual' | 'auto_cf_fix' | 'auto_vapt_remediation' | 'scheduled'
    source              TEXT NOT NULL DEFAULT 'manual',
    -- Audit
    engineer_user_id    BIGINT REFERENCES mmwss.users(id) ON DELETE SET NULL,
    executed_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX change_log_executed_idx  ON mmwss.change_log (executed_at DESC);
CREATE INDEX change_log_category_idx  ON mmwss.change_log (category);
CREATE INDEX change_log_zone_idx      ON mmwss.change_log (zone_id) WHERE zone_id IS NOT NULL;
CREATE INDEX change_log_ticket_idx    ON mmwss.change_log (ticket_id) WHERE ticket_id IS NOT NULL;
CREATE INDEX change_log_vapt_idx      ON mmwss.change_log (vapt_finding_id) WHERE vapt_finding_id IS NOT NULL;

COMMIT;
