"""mmwss-collector entrypoint.

Subcommands:
  migrate    Apply pending DB migrations and exit.
  sync       One-shot zone sync (applies migrations first if needed).
  scheduler  Long-running scheduler (default).
"""
import logging
import sys
import time

from . import db
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


def cmd_scheduler(settings) -> int:
    """Phase 1 stub: run migrate + sync once, then idle.

    Idling (rather than exiting) is deliberate. With `restart: unless-stopped`,
    exiting would cause a hot restart loop and hammer the CF API. Slice 2 replaces
    this with an APScheduler instance running the real jobs.
    """
    log.info("Scheduler stub — running one-shot migrate + sync")
    rc = cmd_sync(settings)
    if rc != 0:
        log.error("Initial sync failed (rc=%d). Sleeping 5min before letting Docker restart us.", rc)
        time.sleep(300)
        return rc
    log.info("Initial sync OK. Idling (real APScheduler jobs land in slice 2). Heartbeat every 10min.")
    while True:
        time.sleep(600)
        log.info("scheduler heartbeat — still alive")


COMMANDS = {
    "migrate": cmd_migrate,
    "sync": cmd_sync,
    "scheduler": cmd_scheduler,
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
