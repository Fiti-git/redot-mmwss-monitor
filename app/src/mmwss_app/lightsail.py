"""App-side queries for AWS Lightsail instance catalogue + metrics."""
from __future__ import annotations

from . import db


# Lightsail bundle → friendly tier name + sizing verdict
BUNDLE_VERDICTS = {
    "nano_2_0":    ("Nano (S$5/mo)",        "undersized"),
    "nano_3_0":    ("Nano (S$5/mo)",        "undersized"),
    "micro_2_0":   ("Micro (S$10/mo)",      "undersized"),
    "micro_3_0":   ("Micro (S$10/mo)",      "undersized"),
    "small_2_0":   ("Small (S$20/mo)",      "tight"),
    "small_3_0":   ("Small (S$20/mo)",      "tight"),
    "medium_2_0":  ("Medium (S$40/mo)",     "adequate"),
    "medium_3_0":  ("Medium (S$40/mo)",     "adequate"),
    "large_2_0":   ("Large (S$80/mo)",      "adequate"),
    "large_3_0":   ("Large (S$80/mo)",      "adequate"),
    "xlarge_2_0":  ("XLarge (S$160/mo)",    "comfortable"),
    "xlarge_3_0":  ("XLarge (S$160/mo)",    "comfortable"),
    "2xlarge_2_0": ("2XLarge (S$320/mo)",   "comfortable"),
    "2xlarge_3_0": ("2XLarge (S$320/mo)",   "comfortable"),
}


def list_instances() -> list[dict]:
    """Catalogue with latest metric snapshot per instance."""
    return db.fetch_all(
        """
        SELECT i.id, i.name, i.bundle_id, i.blueprint_name,
               i.ram_gb, i.vcpu, i.disk_gb, i.transfer_gb_mo,
               i.public_ip, i.state, i.availability_zone,
               i.zone_id, z.name AS zone_name,
               i.last_synced_at,
               m.hour AS metrics_hour,
               m.cpu_avg, m.cpu_max,
               m.network_in_bytes, m.network_out_bytes,
               m.status_check_failed,
               m.burst_capacity_pct, m.burst_capacity_secs
          FROM mmwss.lightsail_instances i
          LEFT JOIN mmwss.zones z ON z.id = i.zone_id
          LEFT JOIN LATERAL (
                SELECT *
                  FROM mmwss.lightsail_metrics_hourly mm
                 WHERE mm.instance_id = i.id
                 ORDER BY mm.hour DESC
                 LIMIT 1
          ) m ON true
         ORDER BY (i.zone_id IS NULL), i.name
        """
    )


def latest_for_zone(zone_id: int) -> dict | None:
    return db.fetch_one(
        """
        SELECT i.*, m.cpu_avg, m.cpu_max,
               m.network_in_bytes, m.network_out_bytes,
               m.burst_capacity_pct, m.burst_capacity_secs,
               m.status_check_failed, m.hour AS metrics_hour
          FROM mmwss.lightsail_instances i
          LEFT JOIN LATERAL (
                SELECT *
                  FROM mmwss.lightsail_metrics_hourly mm
                 WHERE mm.instance_id = i.id
                 ORDER BY mm.hour DESC
                 LIMIT 1
          ) m ON true
         WHERE i.zone_id = %s
         LIMIT 1
        """,
        (zone_id,),
    )


def metrics_history(instance_id: int, hours_back: int = 24) -> list[dict]:
    return db.fetch_all(
        """
        SELECT hour, cpu_avg, cpu_max,
               network_in_bytes, network_out_bytes,
               status_check_failed, burst_capacity_pct
          FROM mmwss.lightsail_metrics_hourly
         WHERE instance_id = %s
           AND hour >= now() - (%s::text || ' hours')::interval
         ORDER BY hour
        """,
        (instance_id, str(hours_back)),
    )


def counters() -> dict:
    r = db.fetch_one(
        """
        SELECT
          (SELECT COUNT(*)::int FROM mmwss.lightsail_instances) AS total,
          (SELECT COUNT(*)::int FROM mmwss.lightsail_instances WHERE state = 'running') AS running,
          (SELECT COUNT(*)::int FROM mmwss.lightsail_instances WHERE zone_id IS NOT NULL) AS mapped,
          (SELECT COUNT(*)::int FROM mmwss.lightsail_instances
            WHERE bundle_id IN ('nano_2_0','nano_3_0','micro_2_0','micro_3_0')) AS undersized,
          (SELECT MAX(hour) FROM mmwss.lightsail_metrics_hourly) AS last_metric
        """
    )
    return r or {}


def bundle_label(bundle_id: str | None) -> tuple[str, str]:
    """Return (friendly_name, verdict) — verdict ∈ undersized/tight/adequate/comfortable."""
    if not bundle_id:
        return ("Unknown", "unknown")
    return BUNDLE_VERDICTS.get(bundle_id, (bundle_id, "unknown"))
