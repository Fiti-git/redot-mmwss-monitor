-- 014: FCM push subscriptions for the Redot Sentinel mobile app.
--
-- Each user can have multiple subscriptions (one per phone). When an alert
-- fires, the collector queries every active subscription for users with the
-- appropriate role and sends a push via FCM (Firebase Admin SDK using the
-- service account stored in mmwss.credentials).
--
-- We also log delivery outcomes for audit + to disable broken tokens.

BEGIN;

CREATE TABLE mmwss.push_subscriptions (
    id                  BIGSERIAL PRIMARY KEY,
    user_id             BIGINT NOT NULL REFERENCES mmwss.users(id) ON DELETE CASCADE,
    -- FCM device token (unique per (app install, device))
    fcm_token           TEXT NOT NULL UNIQUE,
    -- Device metadata (for the UI list)
    platform            TEXT NOT NULL DEFAULT 'android',  -- 'android' | 'ios' | 'web'
    device_label        TEXT,                              -- e.g., "Asfak's Pixel 8"
    app_version         TEXT,                              -- e.g., "1.0.0"
    -- Preferences (per-subscription opt-in/out)
    notify_p1           BOOLEAN NOT NULL DEFAULT TRUE,
    notify_scanner_critical BOOLEAN NOT NULL DEFAULT TRUE,
    notify_honeytoken   BOOLEAN NOT NULL DEFAULT TRUE,
    notify_report_ready BOOLEAN NOT NULL DEFAULT TRUE,
    notify_sla_warning  BOOLEAN NOT NULL DEFAULT TRUE,
    -- Lifecycle
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    is_active           BOOLEAN NOT NULL DEFAULT TRUE,
    deactivated_at      TIMESTAMPTZ,
    deactivated_reason  TEXT
);

CREATE INDEX push_subs_user_idx     ON mmwss.push_subscriptions (user_id) WHERE is_active = TRUE;
CREATE INDEX push_subs_active_idx   ON mmwss.push_subscriptions (is_active);

-- Audit log of every push attempt (success or fail)
CREATE TABLE mmwss.push_deliveries (
    id              BIGSERIAL PRIMARY KEY,
    subscription_id BIGINT REFERENCES mmwss.push_subscriptions(id) ON DELETE SET NULL,
    user_id         BIGINT REFERENCES mmwss.users(id) ON DELETE SET NULL,
    kind            TEXT NOT NULL,        -- 'p1_ticket' | 'honeytoken' | 'scanner_critical' | etc.
    title           TEXT NOT NULL,
    body            TEXT NOT NULL,
    data_json       JSONB,                 -- payload for in-app routing
    sent_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    delivered       BOOLEAN NOT NULL DEFAULT FALSE,
    error_message   TEXT,
    fcm_message_id  TEXT                   -- returned by FCM on success
);

CREATE INDEX push_deliveries_sent_idx ON mmwss.push_deliveries (sent_at DESC);
CREATE INDEX push_deliveries_kind_idx ON mmwss.push_deliveries (kind);

-- ───── Mobile session tokens ─────
-- The mobile app authenticates with email+password+2FA then receives a
-- long-lived bearer token (90 day default). Each API call sends this token
-- in the Authorization header. We do NOT use cookies for mobile because
-- (a) refresh flow is cleaner, (b) we can revoke individual devices.
CREATE TABLE mmwss.mobile_sessions (
    id              BIGSERIAL PRIMARY KEY,
    user_id         BIGINT NOT NULL REFERENCES mmwss.users(id) ON DELETE CASCADE,
    -- The token plaintext is NEVER stored — only its sha256.
    token_sha256    TEXT NOT NULL UNIQUE,
    device_label    TEXT,
    user_agent      TEXT,
    ip              TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at      TIMESTAMPTZ NOT NULL,
    last_used_at    TIMESTAMPTZ,
    revoked_at      TIMESTAMPTZ
);

CREATE INDEX mobile_sessions_user_active_idx
    ON mmwss.mobile_sessions (user_id, expires_at)
    WHERE revoked_at IS NULL;

COMMIT;
