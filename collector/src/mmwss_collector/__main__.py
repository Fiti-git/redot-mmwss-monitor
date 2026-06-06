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

from . import alerts, db, jobs, reports
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

    log.info("Scheduler running. Jobs: uptime/60s, analytics/hourly, snapshot/6h, zone_sync/daily, "
             "report_daily/weekly/monthly")
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


COMMANDS = {
    "migrate": cmd_migrate,
    "sync": cmd_sync,
    "scheduler": cmd_scheduler,
    "test_alert": cmd_test_alert,
    "report": cmd_report,
    "wp_check": cmd_wp_check,
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
