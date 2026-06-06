-- 006: VAPT remediation tracker.
-- Per the proposal Section 2.2.1, MMWSS will inform Redot when a VAPT round
-- runs; Redot will apply fixes within SLA (critical: 8h, high: 14 days per
-- the plugin-audit clarification). This schema stores the report metadata,
-- the individual findings, and tracks remediation through status changes.
-- Each finding can spawn a ticket so SLA elapsed times are measured by the
-- existing tickets module.

BEGIN;

CREATE TYPE mmwss.vapt_severity AS ENUM ('critical', 'high', 'medium', 'low', 'info');
CREATE TYPE mmwss.vapt_status   AS ENUM
    ('open', 'in_progress', 'remediated', 'verified', 'accepted_risk', 'false_positive');

CREATE TABLE mmwss.vapt_reports (
    id                   BIGSERIAL PRIMARY KEY,
    title                TEXT NOT NULL,
    vendor               TEXT,
    report_date          DATE,
    received_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    notes                TEXT,
    uploaded_by_user_id  BIGINT REFERENCES mmwss.users(id) ON DELETE SET NULL
);

CREATE INDEX vapt_reports_date_idx ON mmwss.vapt_reports (report_date DESC NULLS LAST);

CREATE TABLE mmwss.vapt_findings (
    id                    BIGSERIAL PRIMARY KEY,
    report_id             BIGINT NOT NULL REFERENCES mmwss.vapt_reports(id) ON DELETE CASCADE,
    vendor_finding_id     TEXT,     -- VAPT vendor's issue ID for cross-reference
    title                 TEXT NOT NULL,
    description           TEXT,
    severity              mmwss.vapt_severity NOT NULL,
    cve_reference         TEXT,
    cvss_score            NUMERIC(3, 1),     -- e.g., 7.5
    owasp_category        TEXT,              -- e.g., "A03:2021 - Injection"
    affected_url          TEXT,
    proof_text            TEXT,
    -- Workflow + remediation
    status                mmwss.vapt_status NOT NULL DEFAULT 'open',
    remediation_plan      TEXT,
    remediation_evidence  TEXT,
    -- Cross-references
    zone_id               BIGINT REFERENCES mmwss.zones(id) ON DELETE SET NULL,
    ticket_id             BIGINT REFERENCES mmwss.tickets(id) ON DELETE SET NULL,
    -- Lifecycle
    discovered_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    in_progress_at        TIMESTAMPTZ,
    remediated_at         TIMESTAMPTZ,
    verified_at           TIMESTAMPTZ,
    -- SLA per the proposal: critical 8h, others 14 days for high-risk
    sla_resolution_secs   INTEGER NOT NULL
);

CREATE INDEX vapt_findings_report_idx    ON mmwss.vapt_findings (report_id);
CREATE INDEX vapt_findings_status_idx    ON mmwss.vapt_findings (status);
CREATE INDEX vapt_findings_severity_idx  ON mmwss.vapt_findings (severity);
CREATE INDEX vapt_findings_zone_idx      ON mmwss.vapt_findings (zone_id) WHERE zone_id IS NOT NULL;

COMMIT;
