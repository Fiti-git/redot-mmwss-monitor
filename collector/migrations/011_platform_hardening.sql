-- 011: Platform hardening — 2FA, rate-limited login, audit hash-chain, backup runs.
--
-- These bring the platform itself up to the same security standard we tell
-- MMWSS their WordPress sites should meet. Specifically:
--
-- 1. TOTP-based 2FA per user (mandatory for role='admin').
-- 2. Login attempt log + per-IP/email lockout (10 attempts / 5 min per IP,
--    5 failures lock the account for 15 min).
-- 3. Audit log hash-chain (sha256(prev_hash + canonical_row)) so deletions or
--    edits are detectable. The pre-existing audit_log_immutable trigger
--    already blocks UPDATE/DELETE at the DB layer — the hash chain is
--    belt-and-suspenders so cross-snapshot tampering also breaks visibly.
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
-- The existing audit_log uses `ts` (not created_at) for timestamps.
-- We add row_hash + prev_hash and back-fill the chain.
-- The existing audit_log_immutable trigger blocks UPDATE, so we temporarily
-- bypass with session_replication_role for the back-fill only.
ALTER TABLE mmwss.audit_log
    ADD COLUMN row_hash    TEXT,
    ADD COLUMN prev_hash   TEXT;

CREATE INDEX audit_log_row_hash_idx ON mmwss.audit_log (row_hash);

SET LOCAL session_replication_role = 'replica';
DO $$
DECLARE
    r RECORD;
    prev TEXT := 'mmwss-audit-chain-genesis';
    canonical TEXT;
    h TEXT;
BEGIN
    FOR r IN
        SELECT id, user_id, user_email, action, ip, target_type, target_id,
               details_json, ts
          FROM mmwss.audit_log
         ORDER BY id
    LOOP
        canonical := COALESCE(r.user_id::text, '')
                  || '|' || COALESCE(r.user_email, '')
                  || '|' || COALESCE(r.action, '')
                  || '|' || COALESCE(r.ip::text, '')
                  || '|' || COALESCE(r.target_type, '')
                  || '|' || COALESCE(r.target_id, '')
                  || '|' || COALESCE(r.details_json::text, '')
                  || '|' || r.ts::text;
        h := encode(digest(prev || canonical, 'sha256'), 'hex');
        UPDATE mmwss.audit_log
           SET row_hash = h, prev_hash = prev
         WHERE id = r.id;
        prev := h;
    END LOOP;
END $$;
SET LOCAL session_replication_role = 'origin';

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
