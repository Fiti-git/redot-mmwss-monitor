"""mmwss-collector entrypoint.

Subcommands:
  migrate    Apply pending DB migrations and exit.
  sync       One-shot zone sync (applies migrations first if needed).
  scheduler  Long-running scheduler (default).
"""
import logging
import sys
import time

from apscheduler.schedulers.blocking import BlockingScheduler
from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.interval import IntervalTrigger

from . import alerts, aws_lightsail, backup, credentials, db, jobs, reports, scan_jobs
from .config import load
from .zone_sync import sync_all_zones

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s — %(message)s",
)
log = logging.getLogger("mmwss_collector")


def cmd_migrate(settings) -> int:
    with db.connect(settings.database_url) as conn:
        applied = db.apply_pending_migrations(conn)
    log.info("Applied %d migrations: %s", len(applied), applied or "(none)")
    return 0


def cmd_sync(settings) -> int:
    with db.connect(settings.database_url) as conn:
        db.apply_pending_migrations(conn)
        if settings.cloudflare_api_token:
            tid = db.upsert_cf_token(
                conn,
                label=settings.cloudflare_token_label,
                token=settings.cloudflare_api_token,
                master_key=settings.mmwss_master_key,
            )
            log.info("Bootstrap CF token ensured (cf_tokens.id=%d, label=%s)", tid, settings.cloudflare_token_label)
        total = sync_all_zones(settings, conn)
    log.info("Zone sync complete: %d zones upserted", total)
    return 0


def _wrap(fn, settings, name):
    """Run a job within its own DB connection + log exceptions, never raise to APScheduler."""
    def job():
        try:
            with db.connect(settings.database_url) as conn:
                t = time.monotonic()
                result = fn(settings, conn)
                log.info("job %s done in %.1fs result=%s", name, time.monotonic() - t, result)
        except Exception:
            log.exception("job %s failed", name)
    return job


def cmd_scheduler(settings) -> int:
    """Long-running scheduler. Runs jobs on cron-like schedules."""
    log.info("Scheduler starting — running initial migrate + sync")
    rc = cmd_sync(settings)
    if rc != 0:
        log.error("Initial sync failed (rc=%d). Sleeping 5min before exiting.", rc)
        time.sleep(300)
        return rc

    # Initial pulls so the dashboard isn't empty on first deploy
    log.info("Running initial analytics pull and snapshot")
    try:
        with db.connect(settings.database_url) as conn:
            jobs.pull_analytics_hourly(settings, conn)
            jobs.take_snapshot(settings, conn)
            jobs.probe_uptime(settings, conn)
    except Exception:
        log.exception("initial jobs failed (continuing to scheduler)")

    sched = BlockingScheduler(timezone="UTC")
    sched.add_job(_wrap(jobs.probe_uptime, settings, "probe_uptime"),
                  IntervalTrigger(seconds=60), id="uptime", max_instances=1, coalesce=True)
    sched.add_job(_wrap(jobs.pull_analytics_hourly, settings, "pull_analytics_hourly"),
                  CronTrigger(minute=5), id="analytics", max_instances=1, coalesce=True)
    sched.add_job(_wrap(jobs.take_snapshot, settings, "take_snapshot"),
                  CronTrigger(hour="*/6", minute=10), id="snapshot", max_instances=1, coalesce=True)
    sched.add_job(_wrap(jobs.run_wp_checks, settings, "wp_checks"),
                  CronTrigger(hour="*/6", minute=20), id="wp_checks", max_instances=1, coalesce=True)
    sched.add_job(_wrap(sync_all_zones, settings, "sync_zones"),
                  CronTrigger(hour=2, minute=0), id="zone_sync", max_instances=1, coalesce=True)

    # Report cadence — all UTC. SGT is UTC+8.
    #   Daily   07:00 SGT = 23:00 UTC the previous day
    #   Weekly  Monday 08:00 SGT = Sunday 00:00 UTC
    #   Monthly 1st 09:00 SGT = 01:00 UTC on the 1st
    def _gen(kind):
        def job():
            with db.connect(settings.database_url) as conn:
                reports.generate_report(settings, conn, kind)
        return job

    sched.add_job(_wrap(lambda s, c: reports.generate_report(s, c, "daily"), settings, "report_daily"),
                  CronTrigger(hour=23, minute=0), id="report_daily", max_instances=1, coalesce=True)
    sched.add_job(_wrap(lambda s, c: reports.generate_report(s, c, "weekly"), settings, "report_weekly"),
                  CronTrigger(day_of_week="sun", hour=0, minute=0), id="report_weekly", max_instances=1, coalesce=True)
    sched.add_job(_wrap(lambda s, c: reports.generate_report(s, c, "monthly"), settings, "report_monthly"),
                  CronTrigger(day=1, hour=1, minute=0), id="report_monthly", max_instances=1, coalesce=True)

    # ───── In-house VAPT scanners (Phase 1) ─────
    # All UTC; SGT = UTC+8.
    # headers + surface = light, run daily.   nuclei + wpscan + testssl = heavy, run weekly.
    # Stagger schedules so they don't all hammer at once.
    sched.add_job(_wrap(scan_jobs.run_headers, settings, "scan_headers"),
                  CronTrigger(hour=22, minute=15), id="scan_headers", max_instances=1, coalesce=True)
    sched.add_job(_wrap(scan_jobs.run_surface, settings, "scan_surface"),
                  CronTrigger(hour=22, minute=45), id="scan_surface", max_instances=1, coalesce=True)
    sched.add_job(_wrap(scan_jobs.run_nuclei, settings, "scan_nuclei"),
                  CronTrigger(day_of_week="mon", hour=18, minute=0), id="scan_nuclei", max_instances=1, coalesce=True)
    sched.add_job(_wrap(scan_jobs.run_wpscan, settings, "scan_wpscan"),
                  CronTrigger(day_of_week="tue", hour=18, minute=0), id="scan_wpscan", max_instances=1, coalesce=True)
    sched.add_job(_wrap(scan_jobs.run_testssl, settings, "scan_testssl"),
                  CronTrigger(day_of_week="wed", hour=18, minute=0), id="scan_testssl", max_instances=1, coalesce=True)
    sched.add_job(_wrap(scan_jobs.run_zap, settings, "scan_zap"),
                  CronTrigger(day_of_week="thu", hour=18, minute=0), id="scan_zap", max_instances=1, coalesce=True)

    # ───── Daily encrypted DB backup ─────
    # 23:30 UTC = 07:30 SGT — runs just after the daily report so it captures
    # the freshly-generated row too.
    sched.add_job(_wrap(backup.run_backup, settings, "backup_daily"),
                  CronTrigger(hour=23, minute=30), id="backup_daily",
                  max_instances=1, coalesce=True)

    # ───── AWS Lightsail (MMWSS origin servers) ─────
    # Catalogue refresh at 02:30 UTC daily (instance metadata changes rarely).
    # Metric pull every hour at :15 — well clear of analytics (:05) and snapshots (:10).
    sched.add_job(_wrap(aws_lightsail.sync_instances, settings, "lightsail_sync"),
                  CronTrigger(hour=2, minute=30), id="lightsail_sync",
                  max_instances=1, coalesce=True)
    sched.add_job(_wrap(aws_lightsail.pull_metrics, settings, "lightsail_metrics"),
                  CronTrigger(minute=15), id="lightsail_metrics",
                  max_instances=1, coalesce=True)

    log.info("Scheduler running. Jobs: uptime/60s, analytics/hourly, snapshot/6h, zone_sync/daily, "
             "report_daily/weekly/monthly, scan_headers+surface/daily, scan_nuclei+wpscan+testssl+zap/weekly, "
             "backup_daily/23:30 UTC")
    try:
        sched.start()
    except (KeyboardInterrupt, SystemExit):
        log.info("Scheduler stopping")
    return 0


def cmd_test_alert(settings) -> int:
    """Send a test Slack alert to verify the webhook is wired up."""
    with db.connect(settings.database_url) as conn:
        db.apply_pending_migrations(conn)
        ok = alerts.notify_test(settings, conn)
    return 0 if ok else 1


def cmd_report(settings) -> int:
    """Generate a report on demand.
    Usage:  collector report daily|weekly|monthly
    """
    kind = sys.argv[2] if len(sys.argv) > 2 else "daily"
    if kind not in ("daily", "weekly", "monthly"):
        log.error("kind must be daily|weekly|monthly")
        return 2
    with db.connect(settings.database_url) as conn:
        db.apply_pending_migrations(conn)
        report_id = reports.generate_report(settings, conn, kind)
    log.info("Generated %s report id=%d", kind, report_id)
    return 0


def cmd_wp_check(settings) -> int:
    """Run WP synthetic checks against all active zones, on demand."""
    with db.connect(settings.database_url) as conn:
        db.apply_pending_migrations(conn)
        n = jobs.run_wp_checks(settings, conn)
    log.info("WP checks complete: %d zones probed", n)
    return 0


def cmd_credentials(settings) -> int:
    """Credential management.

    Usage:
        collector credentials list                       — show all (no values)
        collector credentials import-from-env            — encrypt env-vars into DB
        collector credentials honeytoken-alerts          — list any tripped honeytokens
        collector credentials set <kind> <label> <val>   — store a new credential
    """
    sub = sys.argv[2] if len(sys.argv) > 2 else "list"
    with db.connect(settings.database_url) as conn:
        db.apply_pending_migrations(conn)
        if sub == "list":
            rows = credentials.list_all(conn)
            print(f"{'KIND':28s} {'LABEL':20s} {'LAST4':8s} {'ACTIVE':6s} {'HONEY':6s} {'USES':6s} LAST USED")
            for r in rows:
                print(f"{r['kind']:28s} {r['label']:20s} {(r['last_4'] or '----'):8s} "
                      f"{'yes' if r['is_active'] else 'no':6s} "
                      f"{'YES' if r['is_honeytoken'] else 'no':6s} "
                      f"{r['use_count']:6d} {r['last_used_at'] or '-'}")
        elif sub == "import-from-env":
            n = credentials.import_from_env(conn, settings)
            print(f"Imported {n} credentials from env into encrypted DB.")
        elif sub == "honeytoken-alerts":
            alerts = credentials.honeytoken_alerts(conn)
            if not alerts:
                print("No honeytoken activity. ✅")
            else:
                print("🚨 HONEYTOKEN USED — BREACH SIGNAL:")
                for a in alerts:
                    print(f"  id={a['id']} kind={a['kind']} label={a['label']} "
                          f"used={a['use_count']}x last_at={a['last_used_at']}")
            return 1 if alerts else 0
        elif sub == "set":
            if len(sys.argv) < 6:
                log.error("Usage: collector credentials set <kind> <label> <value>")
                return 2
            kind, label, value = sys.argv[3], sys.argv[4], sys.argv[5]
            cid = credentials.set(conn, kind, label, value, settings=settings)
            print(f"Stored credential id={cid} ({kind}/{label})")
        else:
            log.error("Unknown subcommand: %r. Try: list | import-from-env | honeytoken-alerts | set", sub)
            return 2
    return 0


def cmd_lightsail(settings) -> int:
    """Catalogue Lightsail instances + pull current-hour metrics on demand."""
    kind = sys.argv[2] if len(sys.argv) > 2 else "all"
    with db.connect(settings.database_url) as conn:
        db.apply_pending_migrations(conn)
        if kind in ("sync", "all"):
            aws_lightsail.sync_instances(settings, conn)
        if kind in ("metrics", "all"):
            aws_lightsail.pull_metrics(settings, conn)
    return 0


def cmd_backup(settings) -> int:
    """Make an encrypted DB backup on demand."""
    with db.connect(settings.database_url) as conn:
        db.apply_pending_migrations(conn)
        result = backup.run_backup(settings, conn)
    if result.get("ok"):
        log.info("backup ok: %s", result)
        return 0
    log.error("backup failed: %s", result)
    return 1


def cmd_scan(settings) -> int:
    """Run one scanner against all active zones, on demand.
    Usage:  collector scan nuclei|wpscan|testssl|headers|surface
    """
    kind = sys.argv[2] if len(sys.argv) > 2 else ""
    runners = {
        "nuclei":  scan_jobs.run_nuclei,
        "wpscan":  scan_jobs.run_wpscan,
        "testssl": scan_jobs.run_testssl,
        "headers": scan_jobs.run_headers,
        "surface": scan_jobs.run_surface,
        "zap":     scan_jobs.run_zap,
    }
    if kind not in runners:
        log.error("scan kind must be one of: %s", ", ".join(runners))
        return 2
    with db.connect(settings.database_url) as conn:
        db.apply_pending_migrations(conn)
        r = runners[kind](settings, conn)
    log.info("scan %s complete: %s", kind, r)
    return 0


COMMANDS = {
    "migrate": cmd_migrate,
    "sync": cmd_sync,
    "scheduler": cmd_scheduler,
    "test_alert": cmd_test_alert,
    "report": cmd_report,
    "wp_check": cmd_wp_check,
    "scan": cmd_scan,
    "backup": cmd_backup,
    "lightsail": cmd_lightsail,
    "credentials": cmd_credentials,
}


def main() -> int:
    cmd = sys.argv[1] if len(sys.argv) > 1 else "scheduler"
    fn = COMMANDS.get(cmd)
    if not fn:
        log.error("Unknown command: %r. Choose from: %s", cmd, ", ".join(COMMANDS))
        return 2
    settings = load()
    try:
        return fn(settings)
    except Exception:
        log.exception("Fatal error in %s", cmd)
        return 1


if __name__ == "__main__":
    sys.exit(main())
