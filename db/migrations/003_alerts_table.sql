-- 003: alerts log table for dedupe + audit of every alert we sent.
-- A "dedupe_key" identifies the logical event (e.g. "incident_opened:42").
-- Before sending an alert, the collector checks if the same key was sent
-- in the last 6 hours. If yes, skip — prevents alert storms.

BEGIN;

CREATE TABLE mmwss.alerts (
    id              BIGSERIAL PRIMARY KEY,
    zone_id         BIGINT REFERENCES mmwss.zones(id) ON DELETE CASCADE,
    incident_id     BIGINT REFERENCES mmwss.incidents(id) ON DELETE SET NULL,
    channel         TEXT NOT NULL,         -- 'slack' | 'email' | 'telegram'
    event_type      TEXT NOT NULL,         -- 'opened' | 'resolved' | 'ssl_warn' | 'test'
    dedupe_key      TEXT NOT NULL,
    payload_json    JSONB,
    sent_at         TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Hot lookup: "has this dedupe_key fired recently on this channel?"
CREATE INDEX alerts_dedupe_recent_idx
    ON mmwss.alerts (channel, dedupe_key, sent_at DESC);

CREATE INDEX alerts_zone_idx ON mmwss.alerts (zone_id, sent_at DESC);

COMMIT;
