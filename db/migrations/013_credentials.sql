-- 013: Generic encrypted-at-rest credentials store.
--
-- Pattern mirrors mmwss.cf_tokens but generalised — one table for AWS keys,
-- WPMU DEV API keys, Slack webhooks, WordPress App Passwords, etc.
--
-- Each row is encrypted with pgcrypto's pgp_sym_encrypt using the platform's
-- MMWSS_MASTER_KEY (sourced from SOPS-decrypted env at startup). Decryption
-- requires both:
--   1. Read access to mmwss.credentials (DB user)
--   2. The master key (env, which comes from SOPS, which needs age key)
--
-- Defense-in-depth: DB backup leak alone is useless; env leak alone is
-- useless. An attacker needs root + age key + DB access to extract anything.
--
-- last_4 is stored plaintext to enable UI display ("AWS key ending ...12AB")
-- without round-tripping decryption every render.

BEGIN;

CREATE TABLE mmwss.credentials (
    id                  BIGSERIAL PRIMARY KEY,
    -- What kind of credential this is (drives how it's used)
    kind                TEXT NOT NULL,
    -- Human label (also used for lookup); unique per (kind, is_active)
    label               TEXT NOT NULL,
    -- The encrypted secret (pgp_sym_encrypt output)
    encrypted_value     BYTEA NOT NULL,
    -- Last 4 chars of the plaintext (for UI / audit display)
    last_4              TEXT,
    -- Optional structured metadata (e.g., zone_id, region, scope, expiry)
    metadata_json       JSONB,
    -- Lifecycle
    is_active           BOOLEAN NOT NULL DEFAULT TRUE,
    rotated_from_id     BIGINT REFERENCES mmwss.credentials(id) ON DELETE SET NULL,
    -- Audit
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_by_user_id  BIGINT REFERENCES mmwss.users(id) ON DELETE SET NULL,
    last_used_at        TIMESTAMPTZ,
    use_count           BIGINT NOT NULL DEFAULT 0,
    -- Honeytoken flag — when true, ANY use should fire an alarm
    is_honeytoken       BOOLEAN NOT NULL DEFAULT FALSE
);

-- Look up active row fast by (kind, label)
CREATE UNIQUE INDEX credentials_active_lookup_idx
    ON mmwss.credentials (kind, label)
    WHERE is_active = TRUE;

-- Audit / history queries
CREATE INDEX credentials_kind_idx ON mmwss.credentials (kind);
CREATE INDEX credentials_last_used_idx ON mmwss.credentials (last_used_at DESC NULLS LAST);

-- Honeytoken poller queries (find all honeytokens that have EVER been used)
CREATE INDEX credentials_honeytoken_alert_idx
    ON mmwss.credentials (is_honeytoken, last_used_at)
    WHERE is_honeytoken = TRUE AND last_used_at IS NOT NULL;

COMMIT;
