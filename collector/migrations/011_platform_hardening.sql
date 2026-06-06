-- 011: Platform hardening — 2FA, rate-limited login, audit hash-chain, backup runs.
--
-- These bring the platform itself up to the same security standard we tell
-- MMWSS their WordPress sites should meet. Specifically:
--
-- 1. TOTP-based 2FA per user (mandatory for role='admin').
-- 2. Login attempt log + per-IP/email lockout (5 attempts / 5 minutes).
-- 3. Audit log hash-chain (sha256(prev_hash + canonical_row)) so deletions or
--    edits are detectable. Not tamper-proof (DB superuser can still rewrite
--    history) but creates a chain of evidence that breaks visibly.
-- 4. backup_runs log so the daily DB backup job has a paper trail.

BEGIN;

-- ───── 2FA + login lockout on users ─────
ALTER TABLE mmwss.users
    ADD COLUMN totp_secret           TEXT,
    ADD COLUMN totp_enabled          BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN totp_confirmed_at     TIMESTAMPTZ,
    ADD COLUMN failed_login_count    INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN locked_until          TIMESTAMPTZ;

CREATE INDEX users_locked_idx ON mmwss.users (locked_until) WHERE locked_until IS NOT NULL;

-- ───── Login attempt log (rate-limit window) ─────
CREATE TABLE mmwss.login_attempts (
    id            BIGSERIAL PRIMARY KEY,
    ip            TEXT,
    email         TEXT,
    success       BOOLEAN NOT NULL,
    user_agent    TEXT,
    attempted_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX login_attempts_ip_time_idx    ON mmwss.login_attempts (ip, attempted_at DESC);
CREATE INDEX login_attempts_email_time_idx ON mmwss.login_attempts (email, attempted_at DESC);

-- ───── Audit log hash chain ─────
-- row_hash = sha256(prev_hash || canonical_text(this_row))
-- Backfill all existing rows with a chained hash starting from a fixed seed.
ALTER TABLE mmwss.audit_log
    ADD COLUMN row_hash    TEXT,
    ADD COLUMN prev_hash   TEXT;

CREATE INDEX audit_log_hash_idx ON mmwss.audit_log (id);

-- Initial chain — seed with constant, walk forward through existing rows.
DO $$
DECLARE
    r RECORD;
    prev TEXT := 'mmwss-audit-chain-genesis';
    canonical TEXT;
    h TEXT;
BEGIN
    FOR r IN
        SELECT id, user_id, user_email, action, ip, target_type, target_id,
               details_json, created_at
          FROM mmwss.audit_log
         ORDER BY id
    LOOP
        canonical := COALESCE(r.user_id::text, '')
                  || '|' || COALESCE(r.user_email, '')
                  || '|' || COALESCE(r.action, '')
                  || '|' || COALESCE(r.ip, '')
                  || '|' || COALESCE(r.target_type, '')
                  || '|' || COALESCE(r.target_id, '')
                  || '|' || COALESCE(r.details_json::text, '')
                  || '|' || r.created_at::text;
        h := encode(digest(prev || canonical, 'sha256'), 'hex');
        UPDATE mmwss.audit_log
           SET row_hash = h, prev_hash = prev
         WHERE id = r.id;
        prev := h;
    END LOOP;
END $$;

-- ───── Backup run log ─────
CREATE TABLE mmwss.backup_runs (
    id              BIGSERIAL PRIMARY KEY,
    started_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    finished_at     TIMESTAMPTZ,
    duration_secs   INTEGER,
    status          TEXT NOT NULL DEFAULT 'running',    -- 'running' | 'ok' | 'failed'
    artifact_path   TEXT,
    artifact_size   BIGINT,
    artifact_sha256 TEXT,
    encrypted       BOOLEAN NOT NULL DEFAULT FALSE,
    error_message   TEXT,
    pushed_remote   BOOLEAN NOT NULL DEFAULT FALSE,
    remote_url      TEXT
);

CREATE INDEX backup_runs_started_idx ON mmwss.backup_runs (started_at DESC);

COMMIT;
