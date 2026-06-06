-- 005: SLA ticket tracker.
-- Every operational item — incidents, change requests, VAPT findings, ad-hoc
-- support — flows through tickets. The monthly report rolls up SLA compliance
-- (response time + resolution time per priority) from this table.

BEGIN;

CREATE TYPE mmwss.ticket_priority AS ENUM ('p1', 'p2', 'p3', 'p4');
CREATE TYPE mmwss.ticket_status   AS ENUM ('open', 'in_progress', 'resolved', 'closed');
CREATE TYPE mmwss.ticket_source   AS ENUM ('manual', 'auto_incident', 'auto_alert');
CREATE TYPE mmwss.ticket_category AS ENUM
    ('uptime', 'payment', 'security', 'cms', 'performance', 'vapt', 'config_change', 'other');

CREATE TABLE mmwss.tickets (
    id                  BIGSERIAL PRIMARY KEY,
    title               TEXT NOT NULL,
    description         TEXT,
    priority            mmwss.ticket_priority NOT NULL,
    status              mmwss.ticket_status   NOT NULL DEFAULT 'open',
    category            mmwss.ticket_category NOT NULL DEFAULT 'other',
    source              mmwss.ticket_source   NOT NULL DEFAULT 'manual',
    zone_id             BIGINT REFERENCES mmwss.zones(id)     ON DELETE SET NULL,
    incident_id         BIGINT REFERENCES mmwss.incidents(id) ON DELETE SET NULL,
    -- SLA targets are snapshotted at creation (immutable) so the report
    -- reflects what was promised when the ticket opened, even if we tune
    -- the policy table later.
    sla_response_secs   INTEGER NOT NULL,
    sla_resolution_secs INTEGER NOT NULL,
    -- Lifecycle timestamps
    opened_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    response_at         TIMESTAMPTZ,
    resolved_at         TIMESTAMPTZ,
    closed_at           TIMESTAMPTZ,
    -- Audit
    opened_by_user_id   BIGINT REFERENCES mmwss.users(id) ON DELETE SET NULL,
    assigned_to_user_id BIGINT REFERENCES mmwss.users(id) ON DELETE SET NULL,
    rca_text            TEXT,
    resolution_notes    TEXT
);

CREATE INDEX tickets_status_priority_idx ON mmwss.tickets (status, priority);
CREATE INDEX tickets_opened_at_idx       ON mmwss.tickets (opened_at DESC);
CREATE INDEX tickets_zone_idx            ON mmwss.tickets (zone_id) WHERE zone_id IS NOT NULL;
CREATE INDEX tickets_incident_idx        ON mmwss.tickets (incident_id) WHERE incident_id IS NOT NULL;

-- Per-event activity log (status changes, comments, assignments).
-- Keeps the main ticket row stable while preserving the full history.
CREATE TABLE mmwss.ticket_events (
    id           BIGSERIAL PRIMARY KEY,
    ticket_id    BIGINT NOT NULL REFERENCES mmwss.tickets(id) ON DELETE CASCADE,
    ts           TIMESTAMPTZ NOT NULL DEFAULT now(),
    user_id      BIGINT REFERENCES mmwss.users(id) ON DELETE SET NULL,
    event_type   TEXT NOT NULL,   -- created | responded | resolved | reopened | closed | comment | assigned
    details_json JSONB
);

CREATE INDEX ticket_events_ticket_ts_idx ON mmwss.ticket_events (ticket_id, ts DESC);

COMMIT;
