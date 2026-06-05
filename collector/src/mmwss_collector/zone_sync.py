import logging

from . import db
from .cloudflare import CloudflareClient
from .config import Settings

log = logging.getLogger(__name__)


def sync_all_zones(settings: Settings, conn) -> int:
    """Pull zone list from every active CF token and upsert to mmwss.zones.

    Returns number of zones upserted (across all tokens).
    """
    tokens = db.get_active_cf_tokens(conn, settings.mmwss_master_key)
    if not tokens:
        log.warning("No CF tokens configured — nothing to sync")
        return 0

    total = 0
    for t in tokens:
        client = CloudflareClient(t["token"], user_agent=settings.cf_user_agent)
        zones = client.list_zones()
        log.info("Token %s (last_4=%s) → %d zones", t["label"], t["last_4"], len(zones))
        for z in zones:
            db.upsert_zone(
                conn,
                cf_zone_id=z["id"],
                cf_token_id=t["id"],
                name=z["name"],
                plan=(z.get("plan") or {}).get("name"),
                status=z.get("status"),
                name_servers=z.get("name_servers") or [],
            )
            total += 1
    return total
