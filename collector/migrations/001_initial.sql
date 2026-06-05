-- MMWSS initial schema
-- Lives inside the existing callora-db Postgres instance,
-- isolated to its own "mmwss" schema. The application user
-- will be granted access ONLY to this schema.

BEGIN;

CREATE SCHEMA IF NOT EXISTS mmwss;

-- pgcrypto: symmetric encryption of CF tokens, digests, gen_random_uuid().
-- citext: case-insensitive emails (so Asfak@... = asfak@...).
CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE EXTENSION IF NOT EXISTS citext;

-- =========================
-- Enums
-- =========================
CREATE TYPE mmwss.user_role        AS ENUM ('admin', 'viewer');
CREATE TYPE mmwss.incident_type    AS ENUM ('site_down', 'ssl_expiring', 'ssl_expired', 'threat_spike', 'config_drift', 'cert_renewed');
CREATE TYPE mmwss.incident_severity AS ENUM ('critical', 'warning', 'info');
CREATE TYPE mmwss.report_type      AS ENUM ('daily', 'weekly', 'monthly', 'adhoc');

-- =========================
-- Users + sessions
-- =========================
CREATE TABLE mmwss.users (
    id              BIGSERIAL PRIMARY KEY,
    email           CITEXT UNIQUE NOT NULL,
    name            TEXT NOT NULL,
    password_hash   TEXT NOT NULL,           -- bcrypt
    role            mmwss.user_role NOT NULL DEFAULT 'viewer',
    mfa_secret      TEXT,                    -- TOTP secret, nullable (added later)
    is_active       BOOLEAN NOT NULL DEFAULT TRUE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_login_at   TIMESTAMPTZ
);
CREATE TABLE mmwss.sessions (
    id              BIGSERIAL PRIMARY KEY,
    user_id         BIGINT NOT NULL REFERENCES mmwss.users(id) ON DELETE CASCADE,
    token_hash      TEXT NOT NULL UNIQUE,    -- sha256 of opaque session token
    expires_at      TIMESTAMPTZ NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    ip              INET,
    user_agent      TEXT,
    revoked_at      TIMESTAMPTZ
);
CREATE INDEX sessions_user_id_idx  ON mmwss.sessions(user_id);
CREATE INDEX sessions_expires_idx  ON mmwss.sessions(expires_at) WHERE revoked_at IS NULL;

-- =========================
-- Cloudflare tokens (encrypted at rest)
-- =========================
CREATE TABLE mmwss.cf_tokens (
    id                  BIGSERIAL PRIMARY KEY,
    label               TEXT NOT NULL,           -- human label e.g. "TM MMWSS prod"
    encrypted_token     BYTEA NOT NULL,          -- pgp_sym_encrypt(token, master_key)
    last_4              TEXT NOT NULL,           -- last 4 chars, for UI display
    scopes_json         JSONB,                   -- what perms it has (audited from CF /user/tokens endpoint)
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_used_at        TIMESTAMPTZ,
    added_by_user_id    BIGINT REFERENCES mmwss.users(id) ON DELETE SET NULL
);

-- =========================
-- Cloudflare zones (one row per CF zone we track)
-- =========================
CREATE TABLE mmwss.zones (
    id                  BIGSERIAL PRIMARY KEY,
    cf_zone_id          TEXT NOT NULL UNIQUE,    -- Cloudflare's UUID
    cf_token_id         BIGINT NOT NULL REFERENCES mmwss.cf_tokens(id) ON DELETE RESTRICT,
    name                TEXT NOT NULL,           -- e.g. "wakaf.sg"
    plan                TEXT,                    -- "Enterprise Website" etc.
    status              TEXT,                    -- "active" etc.
    name_servers_json   JSONB,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_synced_at      TIMESTAMPTZ
);
CREATE INDEX zones_name_idx ON mmwss.zones(name);

-- =========================
-- Snapshots of zone config (full settings, SSL, DNS counts) every 6h
-- =========================
CREATE TABLE mmwss.zone_snapshots (
    id                  BIGSERIAL PRIMARY KEY,
    zone_id             BIGINT NOT NULL REFERENCES mmwss.zones(id) ON DELETE CASCADE,
    captured_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    settings_json       JSONB NOT NULL,          -- ssl, security_level, brotli, etc.
    ssl_expiry          TIMESTAMPTZ,
    ssl_packs_active    INT,
    fw_rules_total      INT,
    fw_rules_enabled    INT,
    dns_count           INT,
    dns_by_type_json    JSONB,
    dns_proxied_count   INT
);
CREATE INDEX zone_snapshots_zone_captured_idx ON mmwss.zone_snapshots(zone_id, captured_at DESC);

CREATE TABLE mmwss.dns_records_snapshot (
    id                  BIGSERIAL PRIMARY KEY,
    zone_snapshot_id    BIGINT NOT NULL REFERENCES mmwss.zone_snapshots(id) ON DELETE CASCADE,
    type                TEXT NOT NULL,
    name                TEXT NOT NULL,
    content             TEXT,
    proxied             BOOLEAN,
    ttl                 INT
);
CREATE INDEX dns_records_snap_idx ON mmwss.dns_records_snapshot(zone_snapshot_id);

-- =========================
-- Hourly traffic analytics (from CF GraphQL httpRequests1hGroups)
-- =========================
CREATE TABLE mmwss.analytics_hourly (
    zone_id             BIGINT NOT NULL REFERENCES mmwss.zones(id) ON DELETE CASCADE,
    hour                TIMESTAMPTZ NOT NULL,           -- hour bucket UTC
    requests            BIGINT NOT NULL DEFAULT 0,
    cached_requests     BIGINT NOT NULL DEFAULT 0,
    bytes               BIGINT NOT NULL DEFAULT 0,
    cached_bytes        BIGINT NOT NULL DEFAULT 0,
    threats             BIGINT NOT NULL DEFAULT 0,
    fetched_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (zone_id, hour)
);
CREATE INDEX analytics_hourly_hour_idx ON mmwss.analytics_hourly(hour DESC);

-- =========================
-- Uptime probes — every 60s, per zone
-- =========================
CREATE TABLE mmwss.uptime_checks (
    id                  BIGSERIAL PRIMARY KEY,
    zone_id             BIGINT NOT NULL REFERENCES mmwss.zones(id) ON DELETE CASCADE,
    checked_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    status_code         INT,
    latency_ms          INT,
    ok                  BOOLEAN NOT NULL,
    error_message       TEXT,
    probe_location      TEXT NOT NULL DEFAULT 'callora-sg'
);
CREATE INDEX uptime_checks_zone_time_idx ON mmwss.uptime_checks(zone_id, checked_at DESC);
-- Aggressive trim policy will be enforced by collector (keep 30d of detail).

-- =========================
-- Incidents (auto-grouped events; closed when condition resolves)
-- =========================
CREATE TABLE mmwss.incidents (
    id                  BIGSERIAL PRIMARY KEY,
    zone_id             BIGINT NOT NULL REFERENCES mmwss.zones(id) ON DELETE CASCADE,
    type                mmwss.incident_type NOT NULL,
    severity            mmwss.incident_severity NOT NULL,
    started_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    ended_at            TIMESTAMPTZ,
    summary             TEXT NOT NULL,
    details_json        JSONB,
    resolved            BOOLEAN GENERATED ALWAYS AS (ended_at IS NOT NULL) STORED
);
CREATE INDEX incidents_zone_open_idx ON mmwss.incidents(zone_id, ended_at) WHERE ended_at IS NULL;
CREATE INDEX incidents_started_idx ON mmwss.incidents(started_at DESC);

-- =========================
-- Reports (generated artifacts on disk)
-- =========================
CREATE TABLE mmwss.reports (
    id                  BIGSERIAL PRIMARY KEY,
    type                mmwss.report_type NOT NULL,
    period_start        TIMESTAMPTZ NOT NULL,
    period_end          TIMESTAMPTZ NOT NULL,
    html_path           TEXT,
    pdf_path            TEXT,
    summary_json        JSONB,
    generated_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    generated_by_user_id BIGINT REFERENCES mmwss.users(id) ON DELETE SET NULL,
    downloaded_count    INT NOT NULL DEFAULT 0
);
CREATE INDEX reports_type_period_idx ON mmwss.reports(type, period_start DESC);

-- =========================
-- Audit log (append-only via revoke + trigger)
-- =========================
CREATE TABLE mmwss.audit_log (
    id                  BIGSERIAL PRIMARY KEY,
    ts                  TIMESTAMPTZ NOT NULL DEFAULT now(),
    user_id             BIGINT REFERENCES mmwss.users(id) ON DELETE SET NULL,
    user_email          TEXT,                    -- denormalized so deleted users still readable
    action              TEXT NOT NULL,           -- e.g. 'auth.login', 'cf_token.add'
    target_type         TEXT,
    target_id           TEXT,
    details_json        JSONB,
    ip                  INET
);
CREATE INDEX audit_log_ts_idx ON mmwss.audit_log(ts DESC);
CREATE INDEX audit_log_user_idx ON mmwss.audit_log(user_id);
CREATE INDEX audit_log_action_idx ON mmwss.audit_log(action);

-- Append-only enforcement: prevent UPDATE/DELETE on audit_log
CREATE OR REPLACE FUNCTION mmwss.audit_log_immutable()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'mmwss.audit_log is append-only';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER audit_log_no_update
    BEFORE UPDATE ON mmwss.audit_log
    FOR EACH ROW EXECUTE FUNCTION mmwss.audit_log_immutable();

CREATE TRIGGER audit_log_no_delete
    BEFORE DELETE ON mmwss.audit_log
    FOR EACH ROW EXECUTE FUNCTION mmwss.audit_log_immutable();

-- =========================
-- updated_at trigger helper
-- =========================
CREATE OR REPLACE FUNCTION mmwss.set_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = now();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER users_updated_at BEFORE UPDATE ON mmwss.users
    FOR EACH ROW EXECUTE FUNCTION mmwss.set_updated_at();
CREATE TRIGGER zones_updated_at BEFORE UPDATE ON mmwss.zones
    FOR EACH ROW EXECUTE FUNCTION mmwss.set_updated_at();

COMMIT;
