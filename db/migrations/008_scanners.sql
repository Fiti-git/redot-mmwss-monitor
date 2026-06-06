-- 008: In-house VAPT scanners (Phase 1, deterministic).
--
-- Per the proposal Section 5: "We will run internal validation scans using
-- OWASP ZAP / Nessus before final submission to the external auditor."
-- This schema gives us a registered set of scanners, a per-execution run
-- log with raw output retention, deterministic dedup keys for findings,
-- a YAML/JSON rule engine for false-positive suppression and severity
-- overrides, and a per-zone criticality multiplier used in risk scoring.
--
-- Scanner findings re-use the existing mmwss.vapt_findings table so they
-- flow through the same auto-ticketing, change-log, and SLA pipeline that
-- vendor findings already use. Each scan run creates an internal_scan
-- vapt_reports row that all that run's findings attach to.
--
-- DESIGN: dedup is hash-based on (scanner, template_id, target_url, parameter).
-- On every re-scan we touch last_seen_at; if a finding stops appearing for
-- N consecutive runs it can be auto-closed as 'verified'.

BEGIN;

-- ───── Per-zone criticality multiplier (drives risk_score) ─────
CREATE TABLE mmwss.asset_criticality (
    zone_id                  BIGINT PRIMARY KEY REFERENCES mmwss.zones(id) ON DELETE CASCADE,
    -- 1.0 = normal, 2.0 = revenue / sensitive, 0.5 = parked / non-prod
    criticality_multiplier   NUMERIC(3, 2) NOT NULL DEFAULT 1.0
        CHECK (criticality_multiplier >= 0.1 AND criticality_multiplier <= 5.0),
    notes                    TEXT,
    updated_at               TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_by_user_id       BIGINT REFERENCES mmwss.users(id) ON DELETE SET NULL
);

-- ───── Scanner registry ─────
-- One row per integrated scanner. Engineers can disable a scanner globally
-- via the enabled flag. config_json holds scanner-specific knobs
-- (template tags, timeout, severity floor, etc.) so we don't redeploy code
-- to tune behavior.
CREATE TABLE mmwss.scanners (
    id            BIGSERIAL PRIMARY KEY,
    name          TEXT NOT NULL UNIQUE,         -- 'nuclei' | 'wpscan' | 'testssl' | 'headers' | 'surface'
    kind          TEXT NOT NULL,                -- 'dast' | 'cms' | 'tls' | 'headers' | 'surface'
    description   TEXT,
    enabled       BOOLEAN NOT NULL DEFAULT TRUE,
    version       TEXT,                         -- last-known binary version string
    config_json   JSONB NOT NULL DEFAULT '{}'::jsonb,
    last_run_at   TIMESTAMPTZ,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Seed the five Phase-1 scanners.
INSERT INTO mmwss.scanners (name, kind, description, config_json) VALUES
  ('nuclei',   'dast',    'Template-based vulnerability scanner (8k+ community templates)',
                          '{"severity_floor":"low","tags":"cve,exposure,misconfig,default-login,exposed-panels","timeout_secs":900}'::jsonb),
  ('wpscan',   'cms',     'WordPress-specific scanner (core, plugin, theme enumeration)',
                          '{"enumerate":"vp,vt,cb,dbe","timeout_secs":900}'::jsonb),
  ('testssl',  'tls',     'TLS configuration and cipher inspection',
                          '{"severity_floor":"low","timeout_secs":600}'::jsonb),
  ('headers',  'headers', 'Security header probe (CSP, HSTS, X-Frame, Referrer, etc.)',
                          '{"timeout_secs":30}'::jsonb),
  ('surface',  'surface', 'Attack surface monitor (subdomain enumeration + reachable host diff)',
                          '{"timeout_secs":600}'::jsonb);

-- ───── Per-execution run log ─────
-- One row per (scanner, zone) execution. status: queued / running / ok / failed.
-- raw_artifact_path is a filesystem location for the full scanner output
-- (retained 1 year for audit trail per the proposal).
CREATE TYPE mmwss.scan_run_status AS ENUM ('queued', 'running', 'ok', 'failed', 'partial');

CREATE TABLE mmwss.scan_runs (
    id                   BIGSERIAL PRIMARY KEY,
    scanner_id           BIGINT NOT NULL REFERENCES mmwss.scanners(id) ON DELETE CASCADE,
    zone_id              BIGINT NOT NULL REFERENCES mmwss.zones(id) ON DELETE CASCADE,
    vapt_report_id       BIGINT REFERENCES mmwss.vapt_reports(id) ON DELETE SET NULL,
    target_url           TEXT NOT NULL,
    started_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    finished_at          TIMESTAMPTZ,
    duration_secs        INTEGER,
    status               mmwss.scan_run_status NOT NULL DEFAULT 'queued',
    error_message        TEXT,
    raw_artifact_path    TEXT,
    findings_total       INTEGER NOT NULL DEFAULT 0,
    findings_new         INTEGER NOT NULL DEFAULT 0,
    findings_resolved    INTEGER NOT NULL DEFAULT 0,    -- previously open, not seen in this run
    findings_suppressed  INTEGER NOT NULL DEFAULT 0,    -- killed by rule engine
    triggered_by         TEXT NOT NULL DEFAULT 'scheduled',  -- 'scheduled' | 'manual:<user_id>' | 'retest:<finding_id>'
    triggered_by_user_id BIGINT REFERENCES mmwss.users(id) ON DELETE SET NULL
);

CREATE INDEX scan_runs_scanner_idx  ON mmwss.scan_runs (scanner_id, started_at DESC);
CREATE INDEX scan_runs_zone_idx     ON mmwss.scan_runs (zone_id, started_at DESC);
CREATE INDEX scan_runs_status_idx   ON mmwss.scan_runs (status) WHERE status IN ('queued', 'running');

-- ───── Triage rule engine ─────
-- Deterministic FP suppression / severity override.
-- Rules are matched in order of specificity (most specific first), action applied to matching findings.
-- Match dimensions: scanner, template_id_pattern (glob), url_pattern (glob), severity floor.
-- Action: 'suppress' (auto-close as false_positive), 'set_severity:<sev>', 'add_note:<text>'.
CREATE TYPE mmwss.finding_rule_action AS ENUM (
    'suppress',           -- auto-close as false_positive on creation
    'downgrade',          -- set_severity to action_value
    'upgrade',            -- set_severity to action_value
    'accept_risk',        -- auto-close as accepted_risk
    'tag'                 -- attach a note, no status change
);

CREATE TABLE mmwss.finding_rules (
    id                    BIGSERIAL PRIMARY KEY,
    name                  TEXT NOT NULL,
    -- Match conditions (NULL = wildcard for that dimension)
    scanner               TEXT,                  -- e.g., 'nuclei'
    template_id_pattern   TEXT,                  -- glob, e.g., 'tech-detect/*'
    url_pattern           TEXT,                  -- glob, e.g., '*.staging.*'
    title_pattern         TEXT,                  -- glob across finding title (case-insensitive)
    zone_id               BIGINT REFERENCES mmwss.zones(id) ON DELETE CASCADE,
    severity_in           TEXT[],                -- only fire if finding's severity is in this list
    -- Action
    action                mmwss.finding_rule_action NOT NULL,
    action_value          TEXT,                  -- for downgrade/upgrade: target severity. for tag: the note.
    -- Audit
    enabled               BOOLEAN NOT NULL DEFAULT TRUE,
    notes                 TEXT,
    created_by_user_id    BIGINT REFERENCES mmwss.users(id) ON DELETE SET NULL,
    created_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
    hit_count             INTEGER NOT NULL DEFAULT 0,
    last_hit_at           TIMESTAMPTZ
);

CREATE INDEX finding_rules_enabled_idx ON mmwss.finding_rules (enabled, scanner);

-- ───── Extend vapt_reports for internal-scan vs vendor distinction ─────
ALTER TABLE mmwss.vapt_reports
    ADD COLUMN kind           TEXT NOT NULL DEFAULT 'vendor',  -- 'vendor' | 'internal_scan'
    ADD COLUMN scanner_id     BIGINT REFERENCES mmwss.scanners(id) ON DELETE SET NULL,
    ADD COLUMN scan_run_id    BIGINT;  -- back-ref (no FK to avoid cycle; runner sets both sides)

CREATE INDEX vapt_reports_kind_idx ON mmwss.vapt_reports (kind);

-- ───── Extend vapt_findings with scanner metadata + dedup + scoring ─────
ALTER TABLE mmwss.vapt_findings
    ADD COLUMN source                 TEXT NOT NULL DEFAULT 'vendor',  -- 'vendor' | 'internal_scan'
    ADD COLUMN scanner                TEXT,                            -- e.g., 'nuclei'
    ADD COLUMN scanner_template_id    TEXT,                            -- e.g., 'CVE-2023-1234' or 'wp-plugins/yoast-seo'
    ADD COLUMN target_url             TEXT,                            -- specific URL tested
    ADD COLUMN parameter              TEXT,                            -- specific param (NULL when not applicable)
    ADD COLUMN fingerprint            TEXT,                            -- sha256(scanner:template:url:param)
    ADD COLUMN raw_output_json        JSONB,                           -- full scanner record
    ADD COLUMN epss_score             NUMERIC(4, 3),                   -- 0.000-1.000, real-world exploit probability
    ADD COLUMN risk_score             NUMERIC(5, 2),                   -- 0-100 composite
    ADD COLUMN first_seen_at          TIMESTAMPTZ,                     -- first scan that found this
    ADD COLUMN last_seen_at           TIMESTAMPTZ,                     -- last scan that confirmed it
    ADD COLUMN consecutive_misses     INTEGER NOT NULL DEFAULT 0,      -- runs since last seen (auto-close threshold)
    ADD COLUMN suppressed_by_rule_id  BIGINT REFERENCES mmwss.finding_rules(id) ON DELETE SET NULL,
    ADD COLUMN scan_run_id            BIGINT REFERENCES mmwss.scan_runs(id) ON DELETE SET NULL;

-- Unique constraint per scanner so re-runs upsert instead of duplicating.
-- Vendor findings (source='vendor') have NULL fingerprint and aren't deduped.
CREATE UNIQUE INDEX vapt_findings_fingerprint_uq
    ON mmwss.vapt_findings (fingerprint)
    WHERE fingerprint IS NOT NULL;

CREATE INDEX vapt_findings_source_idx       ON mmwss.vapt_findings (source);
CREATE INDEX vapt_findings_scanner_idx      ON mmwss.vapt_findings (scanner) WHERE scanner IS NOT NULL;
CREATE INDEX vapt_findings_risk_idx         ON mmwss.vapt_findings (risk_score DESC NULLS LAST);
CREATE INDEX vapt_findings_last_seen_idx    ON mmwss.vapt_findings (last_seen_at DESC NULLS LAST);

-- ───── Attack-surface inventory (subfinder + httpx output, diffed per run) ─────
CREATE TABLE mmwss.surface_hosts (
    id              BIGSERIAL PRIMARY KEY,
    zone_id         BIGINT NOT NULL REFERENCES mmwss.zones(id) ON DELETE CASCADE,
    host            TEXT NOT NULL,
    first_seen_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_status     INTEGER,
    last_server     TEXT,
    last_title      TEXT,
    last_run_id     BIGINT REFERENCES mmwss.scan_runs(id) ON DELETE SET NULL,
    active          BOOLEAN NOT NULL DEFAULT TRUE,
    UNIQUE (zone_id, host)
);

CREATE INDEX surface_hosts_zone_idx ON mmwss.surface_hosts (zone_id, active);

COMMIT;
