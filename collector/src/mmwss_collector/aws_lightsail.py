"""AWS Lightsail integration — catalogue instances + pull hourly metrics.

Credentials: MMWSS_AWS_* env vars (separate prefix from any future Redot-side
AWS credentials we may add). The IAM user is read-only (Lightsail + CloudWatch)
on MMWSS's account.

Two operations:
  sync_instances() — daily-ish refresh of the instance catalogue (name,
                     bundle, IP, RAM, vCPU, zone mapping). Idempotent upsert.
  pull_metrics()   — hourly pull from Lightsail's native get_instance_metric_data
                     for CPU, network, burst credits, status checks.

Instance → zone mapping is name-pattern based:
  MMWSS-ourmasjid-prov1   → ourmasjid.sg
  MMWSS-ourmadrasah-prov1 → ourmadrasah.sg
  MMWSS-wakaf-prov1       → wakaf.sg
  MMWSS-learnislam-prov2  → learnislam.sg
  MMWSS-sharedservices-prov1 → sharedservices.sg
  MMWSS-staging1/2        → unmapped (NULL zone_id)
"""
from __future__ import annotations

import logging
import os
from datetime import datetime, timedelta, timezone

log = logging.getLogger(__name__)


# ───── Instance-name → zone-domain map ─────
# Substring match (case-insensitive) on the Lightsail instance name.
# Order matters only if the substrings could overlap — they don't here.
ZONE_NAME_MAP = {
    "ourmasjid":      "ourmasjid.sg",
    "ourmadrasah":    "ourmadrasah.sg",
    "wakaf":          "wakaf.sg",
    "learnislam":     "learnislam.sg",
    "sharedservices": "sharedservices.sg",
}

# Metrics we pull each hour.
# Tuple: (metric_name, unit, statistic). Lightsail's API takes a single
# statistic per call, so we make one call per metric per instance.
METRICS_TO_PULL = [
    ("CPUUtilization",          "Percent", "Average"),
    ("CPUUtilization",          "Percent", "Maximum"),
    ("NetworkIn",               "Bytes",   "Sum"),
    ("NetworkOut",              "Bytes",   "Sum"),
    ("StatusCheckFailed",       "Count",   "Sum"),
    ("BurstCapacityPercentage", "Percent", "Average"),
    ("BurstCapacityTime",       "Seconds", "Average"),
]


def _have_credentials() -> bool:
    return bool(
        os.environ.get("MMWSS_AWS_ACCESS_KEY_ID")
        and os.environ.get("MMWSS_AWS_SECRET_ACCESS_KEY")
    )


def _client():
    """Lazy boto3 client construction. Raises ImportError clearly if boto3
    isn't installed yet (we install it in the image)."""
    try:
        import boto3
    except ImportError as e:
        raise RuntimeError(
            "boto3 not installed. Add to requirements: boto3==1.35.83"
        ) from e
    return boto3.client(
        "lightsail",
        region_name=os.environ.get("MMWSS_AWS_DEFAULT_REGION", "ap-southeast-1"),
        aws_access_key_id=os.environ["MMWSS_AWS_ACCESS_KEY_ID"],
        aws_secret_access_key=os.environ["MMWSS_AWS_SECRET_ACCESS_KEY"],
    )


def _lookup_zone_id(conn, instance_name: str) -> int | None:
    """Find the zones.id whose domain corresponds to this instance name."""
    lower = instance_name.lower()
    for key, domain in ZONE_NAME_MAP.items():
        if key in lower:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT id FROM mmwss.zones WHERE name = %s LIMIT 1",
                    (domain,),
                )
                row = cur.fetchone()
                if row:
                    return row["id"]
            return None
    return None


# ───── Public job: sync the instance catalogue ─────


def sync_instances(settings, conn) -> int:
    """Upsert every Lightsail instance into mmwss.lightsail_instances.
    Returns count synced (0 if credentials missing).
    """
    if not _have_credentials():
        log.info("MMWSS_AWS_* credentials not set — skipping Lightsail sync")
        return 0

    try:
        ls = _client()
    except Exception:
        log.exception("Failed to construct Lightsail client")
        return 0

    try:
        resp = ls.get_instances()
    except Exception:
        log.exception("Lightsail GetInstances failed")
        return 0

    instances = resp.get("instances", []) or []
    upserted = 0

    for inst in instances:
        try:
            name = inst["name"]
            hw = inst.get("hardware", {}) or {}
            disks = hw.get("disks", []) or []
            disk_gb = sum(int(d.get("sizeInGb") or 0) for d in disks)
            networking = inst.get("networking", {}) or {}
            mtransfer = (networking.get("monthlyTransfer") or {}).get(
                "gbPerMonthAllocated"
            )
            zone_id = _lookup_zone_id(conn, name)

            created_at = inst.get("createdAt")
            # boto3 returns timezone-aware datetimes for these — keep as-is

            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO mmwss.lightsail_instances
                        (name, arn, bundle_id, blueprint_id, blueprint_name,
                         ram_gb, vcpu, disk_gb, transfer_gb_mo,
                         public_ip, private_ip, state, availability_zone,
                         created_at_aws, zone_id, last_synced_at)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s,
                            %s, %s, %s, %s, %s, %s, now())
                    ON CONFLICT (name) DO UPDATE SET
                        arn = EXCLUDED.arn,
                        bundle_id = EXCLUDED.bundle_id,
                        blueprint_id = EXCLUDED.blueprint_id,
                        blueprint_name = EXCLUDED.blueprint_name,
                        ram_gb = EXCLUDED.ram_gb,
                        vcpu = EXCLUDED.vcpu,
                        disk_gb = EXCLUDED.disk_gb,
                        transfer_gb_mo = EXCLUDED.transfer_gb_mo,
                        public_ip = EXCLUDED.public_ip,
                        private_ip = EXCLUDED.private_ip,
                        state = EXCLUDED.state,
                        availability_zone = EXCLUDED.availability_zone,
                        zone_id = COALESCE(EXCLUDED.zone_id, mmwss.lightsail_instances.zone_id),
                        last_synced_at = now()
                    """,
                    (
                        name,
                        inst.get("arn"),
                        inst.get("bundleId"),
                        inst.get("blueprintId"),
                        inst.get("blueprintName"),
                        hw.get("ramSizeInGb"),
                        hw.get("cpuCount"),
                        disk_gb if disk_gb > 0 else None,
                        mtransfer,
                        inst.get("publicIpAddress"),
                        inst.get("privateIpAddress"),
                        (inst.get("state") or {}).get("name"),
                        (inst.get("location") or {}).get("availabilityZone"),
                        created_at,
                        zone_id,
                    ),
                )
            upserted += 1
        except Exception:
            log.exception("Failed to upsert Lightsail instance %s", inst.get("name"))

    conn.commit()
    log.info("Lightsail sync: %d instances catalogued", upserted)
    return upserted


# ───── Public job: pull last hour of metrics for each running instance ─────


def pull_metrics(settings, conn) -> int:
    """For every running Lightsail instance, pull the last full hour of
    Lightsail-native metrics. Upserts one row per (instance, hour)."""
    if not _have_credentials():
        log.info("MMWSS_AWS_* credentials not set — skipping Lightsail metrics")
        return 0

    try:
        ls = _client()
    except Exception:
        log.exception("Failed to construct Lightsail client")
        return 0

    with conn.cursor() as cur:
        cur.execute(
            "SELECT id, name FROM mmwss.lightsail_instances WHERE state = 'running'"
        )
        instances = cur.fetchall()

    if not instances:
        log.info("No running Lightsail instances — sync first")
        return 0

    # Pull the closed last hour (start = top of previous hour, end = top of current)
    now = datetime.now(timezone.utc).replace(minute=0, second=0, microsecond=0)
    end = now
    start = end - timedelta(hours=1)

    upserts = 0
    for inst in instances:
        agg = {}    # metric_name + stat → value
        for metric_name, unit, stat in METRICS_TO_PULL:
            try:
                resp = ls.get_instance_metric_data(
                    instanceName=inst["name"],
                    metricName=metric_name,
                    period=3600,                # one-hour bucket
                    startTime=start,
                    endTime=end,
                    unit=unit,
                    statistics=[stat],
                )
            except Exception as e:
                log.warning(
                    "get_instance_metric_data failed for %s %s/%s: %s",
                    inst["name"], metric_name, stat, e,
                )
                continue
            data = resp.get("metricData", []) or []
            if not data:
                continue
            # We requested period=3600 over a 1-hour window, so should be ≤1 point
            point = data[-1]
            key = f"{metric_name}_{stat.lower()}"
            agg[key] = point.get(stat.lower()) or point.get("average") or point.get("sum") or point.get("maximum")

        if not agg:
            continue

        try:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO mmwss.lightsail_metrics_hourly
                        (instance_id, hour,
                         cpu_avg, cpu_max,
                         network_in_bytes, network_out_bytes,
                         status_check_failed,
                         burst_capacity_pct, burst_capacity_secs)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (instance_id, hour) DO UPDATE SET
                        cpu_avg = EXCLUDED.cpu_avg,
                        cpu_max = EXCLUDED.cpu_max,
                        network_in_bytes = EXCLUDED.network_in_bytes,
                        network_out_bytes = EXCLUDED.network_out_bytes,
                        status_check_failed = EXCLUDED.status_check_failed,
                        burst_capacity_pct = EXCLUDED.burst_capacity_pct,
                        burst_capacity_secs = EXCLUDED.burst_capacity_secs,
                        fetched_at = now()
                    """,
                    (
                        inst["id"],
                        start,
                        agg.get("CPUUtilization_average"),
                        agg.get("CPUUtilization_maximum"),
                        int(agg["NetworkIn_sum"]) if agg.get("NetworkIn_sum") is not None else None,
                        int(agg["NetworkOut_sum"]) if agg.get("NetworkOut_sum") is not None else None,
                        int(agg["StatusCheckFailed_sum"]) if agg.get("StatusCheckFailed_sum") is not None else None,
                        agg.get("BurstCapacityPercentage_average"),
                        int(agg["BurstCapacityTime_average"]) if agg.get("BurstCapacityTime_average") is not None else None,
                    ),
                )
            upserts += 1
        except Exception:
            log.exception("Failed to upsert metrics for %s", inst["name"])

    conn.commit()
    log.info(
        "Lightsail metrics: pulled %d/%d instances for hour %s",
        upserts, len(instances), start.strftime("%Y-%m-%d %H:%M UTC"),
    )
    return upserts


def run_full(settings, conn) -> int:
    """Daily-style: sync catalogue then pull metrics. Returns metric count."""
    sync_instances(settings, conn)
    return pull_metrics(settings, conn)
