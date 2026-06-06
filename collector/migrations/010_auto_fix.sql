-- 010: Auto-resolution engine.
--
-- Maps detectable findings to mechanical CF API fixes (Transform Rules for
-- headers, settings for SSL/HTTPS knobs, WAF rules for path blocking).
-- Workflow:
--   scan finds issue → matcher generates proposal (pending_approval)
--                    → admin reviews + approves
--                    → applier calls CF API + records change_log
--                    → finding marked remediated; next scan auto-verifies
--
-- Contract delivery rule: NO autonomous fixes. Every proposal requires
-- explicit admin approval. The "auto" in auto-resolution = automatic
-- proposal generation + automatic application AFTER approval, not zero-touch.
--
-- Canary mode: per-zone enabled flag. Default: disabled everywhere except
-- learnislam.sg (lowest blast-radius zone for first runs).

BEGIN;

CREATE TYPE mmwss.auto_fix_status AS ENUM (
    'pending_approval',
    'approved',
    'applying',
    'applied',
    'failed',
    'rolled_back',
    'rejected',
    'superseded'
);

CREATE TYPE mmwss.auto_fix_action_kind AS ENUM (
    'cf_setting',           -- PATCH /zones/{id}/settings/{setting_id}
    'cf_transform_header',  -- add Transform Rule that sets a response header
    'cf_waf_block_path'     -- add WAF custom rule blocking a URI path
);

CREATE TABLE mmwss.auto_fix_proposals (
    id                  BIGSERIAL PRIMARY KEY,
    finding_id          BIGINT NOT NULL REFERENCES mmwss.vapt_findings(id) ON DELETE CASCADE,
    zone_id             BIGINT NOT NULL REFERENCES mmwss.zones(id) ON DELETE CASCADE,
    -- What we propose to do
    action_kind         mmwss.auto_fix_action_kind NOT NULL,
    action_summary      TEXT NOT NULL,        -- human-readable
    before_state        TEXT,                  -- captured at proposal time
    proposed_state      TEXT NOT NULL,         -- what it'll be after apply
    action_payload      JSONB NOT NULL,        -- exact API call args
    estimated_findings_resolved INTEGER NOT NULL DEFAULT 1,
    -- Lifecycle
    status              mmwss.auto_fix_status NOT NULL DEFAULT 'pending_approval',
    -- Approval
    approved_by_user_id BIGINT REFERENCES mmwss.users(id) ON DELETE SET NULL,
    approved_at         TIMESTAMPTZ,
    rejection_reason    TEXT,
    -- Application
    applied_at          TIMESTAMPTZ,
    applied_by_user_id  BIGINT REFERENCES mmwss.users(id) ON DELETE SET NULL,
    failure_reason      TEXT,
    cf_response_json    JSONB,                 -- audit + rollback context
    -- Linked artifacts
    change_log_id       BIGINT REFERENCES mmwss.change_log(id) ON DELETE SET NULL,
    -- Lifecycle timestamps
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Same proposed-state shouldn't queue twice for the same zone (idempotency).
CREATE UNIQUE INDEX auto_fix_dedup_idx
    ON mmwss.auto_fix_proposals (zone_id, action_kind, action_payload)
    WHERE status IN ('pending_approval', 'approved', 'applying');

CREATE INDEX auto_fix_status_idx  ON mmwss.auto_fix_proposals (status, created_at DESC);
CREATE INDEX auto_fix_finding_idx ON mmwss.auto_fix_proposals (finding_id);
CREATE INDEX auto_fix_zone_idx    ON mmwss.auto_fix_proposals (zone_id, status);

-- ───── Canary / enablement per zone ─────
-- Determines which zones the matcher will generate proposals for.
-- Once you've validated learnislam.sg, flip the others on.
CREATE TABLE mmwss.auto_fix_zone_settings (
    zone_id            BIGINT PRIMARY KEY REFERENCES mmwss.zones(id) ON DELETE CASCADE,
    enabled            BOOLEAN NOT NULL DEFAULT FALSE,
    updated_by_user_id BIGINT REFERENCES mmwss.users(id) ON DELETE SET NULL,
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Default canary: learnislam.sg ON, all others OFF.
-- Use INSERT ... ON CONFLICT so this is idempotent across reapplies.
INSERT INTO mmwss.auto_fix_zone_settings (zone_id, enabled)
SELECT id, (name = 'learnislam.sg')
  FROM mmwss.zones
ON CONFLICT (zone_id) DO NOTHING;

COMMIT;
