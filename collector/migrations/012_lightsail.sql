-- 012: AWS Lightsail integration.
--
-- Hourly metrics pull from MMWSS's Lightsail account (read-only IAM user
-- mmwss-monitoring) populates these tables. The platform then surfaces
-- origin-server health alongside CF-edge data — closing the "we monitor
-- the front door, not inside the building" gap.
--
-- Instance ↔ zone mapping is done by name pattern (e.g., MMWSS-ourmasjid-prov1
-- maps to ourmasjid.sg). Staging instances are catalogued but have NULL zone_id.

BEGIN;

CREATE TABLE mmwss.lightsail_instances (
    id                BIGSERIAL PRIMARY KEY,
    name              TEXT UNIQUE NOT NULL,
    arn               TEXT,
    bundle_id         TEXT,
    blueprint_id      TEXT,
    blueprint_name    TEXT,
    ram_gb            NUMERIC(6, 2),
    vcpu              INTEGER,
    disk_gb           INTEGER,
    transfer_gb_mo    INTEGER,
    public_ip         INET,
    private_ip        INET,
    state             TEXT,
    availability_zone TEXT,
    created_at_aws    TIMESTAMPTZ,
    -- Mapping to our MMWSS zones table (NULL for staging / unmapped)
    zone_id           BIGINT REFERENCES mmwss.zones(id) ON DELETE SET NULL,
    first_synced_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_synced_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX lightsail_instances_zone_idx ON mmwss.lightsail_instances (zone_id) WHERE zone_id IS NOT NULL;
CREATE INDEX lightsail_instances_state_idx ON mmwss.lightsail_instances (state);

CREATE TABLE mmwss.lightsail_metrics_hourly (
    id                  BIGSERIAL PRIMARY KEY,
    instance_id         BIGINT NOT NULL REFERENCES mmwss.lightsail_instances(id) ON DELETE CASCADE,
    hour                TIMESTAMPTZ NOT NULL,
    -- CPU
    cpu_avg             NUMERIC(5, 2),       -- 0-100
    cpu_max             NUMERIC(5, 2),       -- 0-100
    -- Network
    network_in_bytes    BIGINT,
    network_out_bytes   BIGINT,
    -- Health
    status_check_failed INTEGER,             -- count of failures in hour
    -- Burst credits (Lightsail-specific — when these drop, CPU throttles)
    burst_capacity_pct  NUMERIC(5, 2),
    burst_capacity_secs INTEGER,
    fetched_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (instance_id, hour)
);

CREATE INDEX lightsail_metrics_hour_idx     ON mmwss.lightsail_metrics_hourly (hour DESC);
CREATE INDEX lightsail_metrics_instance_idx ON mmwss.lightsail_metrics_hourly (instance_id, hour DESC);

COMMIT;
